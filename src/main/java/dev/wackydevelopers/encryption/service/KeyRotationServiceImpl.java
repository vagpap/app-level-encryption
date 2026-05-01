package dev.wackydevelopers.encryption.service;

import dev.wackydevelopers.encryption.blindindex.BlindIndexServiceImpl;
import dev.wackydevelopers.encryption.blindindex.RotatableBlindIndexService;
import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.crypto.TransitKeyWrapClient;
import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import dev.wackydevelopers.encryption.entity.SecuredEntityRepository;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KeyRotationServiceImpl implements KeyRotationService {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_BITS = 128;
    private static final String STATUS_COMPLETED = "COMPLETED";
    private static final Pattern WRAPPED_DEK_VERSION_PATTERN = Pattern.compile("^vault:v(\\d+):");

    private final Map<String, KeyRotationPlan> plans = new ConcurrentHashMap<>();
    private final Map<String, Map<UUID, String>> bikSnapshots = new ConcurrentHashMap<>();

    private final SecuredEntityRepository repository;
    private final EnvelopeEncryptionService envelopeEncryptionService;
    private final RotatableBlindIndexService blindIndexService;
    private final TransitKeyWrapClient transitKeyWrapClient;
    private final int kekBatchSize;
    private final SecureRandom secureRandom = new SecureRandom();

    public KeyRotationServiceImpl(
            SecuredEntityRepository repository,
            EnvelopeEncryptionService envelopeEncryptionService,
            RotatableBlindIndexService blindIndexService,
            TransitKeyWrapClient transitKeyWrapClient,
            int kekBatchSize) {
        this.repository = repository;
        this.envelopeEncryptionService = envelopeEncryptionService;
        this.blindIndexService = blindIndexService;
        this.transitKeyWrapClient = transitKeyWrapClient;
        this.kekBatchSize = Math.max(1, kekBatchSize);
    }

    @Override
    public KeyRotationPlan rotateKek(String reason) {
        validateReason(reason);

        String rotationId = UUID.randomUUID().toString();
        Instant startedAt = Instant.now();
        KeyRotationPlan inProgress = new KeyRotationPlan(
                rotationId,
                "KEK",
                startedAt,
                null,
                "IN_PROGRESS",
                true,
                0,
                reason,
                "Executing KEK rewrap in batches of " + kekBatchSize
        );
        plans.put(rotationId, inProgress);

        List<SecuredEntity> entities = repository.findAll();
        Map<UUID, KekSnapshot> rewrapSnapshot = new HashMap<>();
        int affected = 0;

        try {
            for (int from = 0; from < entities.size(); from += kekBatchSize) {
                int to = Math.min(from + kekBatchSize, entities.size());
                List<SecuredEntity> batch = entities.subList(from, to);

                for (SecuredEntity entity : batch) {
                    rewrapSnapshot.put(entity.getId(), new KekSnapshot(entity.getSecretDek(), entity.getSecretKekVersion()));

                    String rewrappedDek = transitKeyWrapClient.rewrapDek(entity.getSecretDek());
                    entity.setSecretDek(rewrappedDek);
                    entity.setSecretKekVersion(parseKekVersion(rewrappedDek));
                    repository.save(entity);
                    affected++;
                }
            }

            KeyRotationPlan completed = new KeyRotationPlan(
                    rotationId,
                    "KEK",
                    startedAt,
                    Instant.now(),
                    STATUS_COMPLETED,
                    false,
                    affected,
                    reason,
                    "KEK rewrap completed in batches; per-row DEKs and KEK versions updated"
            );
            plans.put(rotationId, completed);
            return completed;
        } catch (Exception ex) {
            restoreKekSnapshot(rewrapSnapshot);
            KeyRotationPlan failed = new KeyRotationPlan(
                    rotationId,
                    "KEK",
                    startedAt,
                    Instant.now(),
                    "FAILED",
                    true,
                    affected,
                    reason,
                    "KEK rotation failed and wrapped DEKs restored: " + ex.getMessage()
            );
            plans.put(rotationId, failed);
            return failed;
        }
    }

    @Override
    public KeyRotationPlan rotateBik(String reason, boolean requireDryRun) {
        validateReason(reason);

        String rotationId = UUID.randomUUID().toString();
        Instant startedAt = Instant.now();
        KeyRotationPlan inProgress = new KeyRotationPlan(
                rotationId,
                "BIK",
                startedAt,
                null,
                "IN_PROGRESS",
                requireDryRun,
                0,
                reason,
                requireDryRun ? "Dry-run requested" : "Executing BIK cutover"
        );
        plans.put(rotationId, inProgress);

        List<SecuredEntity> entities = repository.findAll();
        Map<UUID, String> previousIndexes = new HashMap<>();

        try {
            for (SecuredEntity entity : entities) {
                previousIndexes.put(entity.getId(), entity.getSecretBidx());
            }
            bikSnapshots.put(rotationId, previousIndexes);

            if (!requireDryRun) {
                byte[] rotatedBik = generateRotatedBik();
                recomputeAndCutoverIndexes(entities, rotatedBik);
                blindIndexService.rotateKey(rotatedBik);
            }

            KeyRotationPlan completed = new KeyRotationPlan(
                    rotationId,
                    "BIK",
                    startedAt,
                    Instant.now(),
                    STATUS_COMPLETED,
                    false,
                    entities.size(),
                    reason,
                    requireDryRun ? "Dry-run validated successfully" : "BIK rotated and blind indexes recomputed"
            );
            plans.put(rotationId, completed);
            return completed;
        } catch (Exception ex) {
            restoreSnapshot(previousIndexes);
            KeyRotationPlan failed = new KeyRotationPlan(
                    rotationId,
                    "BIK",
                    startedAt,
                    Instant.now(),
                    "FAILED",
                    true,
                    entities.size(),
                    reason,
                    "Rotation failed and snapshot restored: " + ex.getMessage()
            );
            plans.put(rotationId, failed);
            return failed;
        }
    }

    @Override
    public KeyRotationPlan getPlan(String rotationId) {
        KeyRotationPlan plan = plans.get(rotationId);
        if (plan == null) {
            throw new ResourceNotFoundException("Rotation plan not found: " + rotationId);
        }
        return plan;
    }

    @Override
    public KeyRotationPlan rollbackBik(String rotationId) {
        KeyRotationPlan plan = getPlan(rotationId);
        if (!"BIK".equals(plan.keyType())) {
            throw new IllegalArgumentException("Rollback is supported only for BIK plans");
        }

        Map<UUID, String> snapshot = bikSnapshots.get(rotationId);
        if (snapshot == null || snapshot.isEmpty()) {
            throw new IllegalArgumentException("No rollback snapshot available for rotation: " + rotationId);
        }

        restoreSnapshot(snapshot);

        KeyRotationPlan rolledBack = new KeyRotationPlan(
                plan.rotationId(),
                plan.keyType(),
                plan.requestedAt(),
                Instant.now(),
                STATUS_COMPLETED,
                false,
                snapshot.size(),
                plan.reason(),
                "Rollback executed using captured snapshot"
        );
        plans.put(rotationId, rolledBack);
        return rolledBack;
    }

    private void recomputeAndCutoverIndexes(List<SecuredEntity> entities, byte[] rotatedBik) {
        for (SecuredEntity entity : entities) {
            EncryptedPayload payload = toEncryptedPayload(entity);
            String plaintext = envelopeEncryptionService.decrypt(payload);
            String rotatedIndex = computeBlindIndexWithRotatedKey(plaintext, rotatedBik);
            entity.setSecretBidx(rotatedIndex);
            repository.save(entity);
        }
    }

    private EncryptedPayload toEncryptedPayload(SecuredEntity entity) {
        String[] parts = entity.getSecretCipher().split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid cipher payload format");
        }
        return new EncryptedPayload(ALGORITHM, parts[0], parts[1], entity.getSecretDek(), TAG_BITS);
    }

    private String computeBlindIndexWithRotatedKey(String plaintext, byte[] rotatedBik) {
        if (blindIndexService instanceof BlindIndexServiceImpl impl) {
            return impl.computeBlindIndexWithKey(plaintext, rotatedBik);
        }
        throw new IllegalStateException("Blind index service does not support rotated key computations");
    }

    private byte[] generateRotatedBik() {
        byte[] bik = new byte[32];
        secureRandom.nextBytes(bik);
        return bik;
    }

    private void restoreSnapshot(Map<UUID, String> snapshot) {
        List<SecuredEntity> all = repository.findAll();
        for (SecuredEntity entity : all) {
            String previous = snapshot.get(entity.getId());
            if (previous != null) {
                entity.setSecretBidx(previous);
                repository.save(entity);
            }
        }
    }

    private void restoreKekSnapshot(Map<UUID, KekSnapshot> snapshot) {
        List<SecuredEntity> all = repository.findAll();
        for (SecuredEntity entity : all) {
            KekSnapshot previous = snapshot.get(entity.getId());
            if (previous != null) {
                entity.setSecretDek(previous.wrappedDek());
                entity.setSecretKekVersion(previous.kekVersion());
                repository.save(entity);
            }
        }
    }

    private int parseKekVersion(String wrappedDek) {
        if (wrappedDek == null || wrappedDek.isBlank()) {
            return 1;
        }

        Matcher matcher = WRAPPED_DEK_VERSION_PATTERN.matcher(wrappedDek);
        if (!matcher.find()) {
            return 1;
        }

        return Integer.parseInt(matcher.group(1));
    }

    private void validateReason(String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Rotation reason must not be blank");
        }
    }

    private record KekSnapshot(String wrappedDek, Integer kekVersion) {
    }
}
