package dev.wackydevelopers.encryption.service;

import dev.wackydevelopers.encryption.blindindex.BlindIndexService;
import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import dev.wackydevelopers.encryption.entity.SecuredEntityRepository;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecuredEntityDomainServiceImpl implements SecuredEntityDomainService {
    
    private static final Pattern WRAPPED_DEK_VERSION_PATTERN = Pattern.compile("^vault:v(\\d+):");

    private final SecuredEntityRepository repository;
    private final EnvelopeEncryptionService envelopeEncryptionService;
    private final BlindIndexService blindIndexService;

    public SecuredEntityDomainServiceImpl(
            SecuredEntityRepository repository,
            EnvelopeEncryptionService envelopeEncryptionService,
            BlindIndexService blindIndexService) {
        this.repository = repository;
        this.envelopeEncryptionService = envelopeEncryptionService;
        this.blindIndexService = blindIndexService;
        this.blindIndexService.initialize();
    }

    @Override
    public SecuredEntity create(String publicInfo, String secretInfo) {
        validateInput(publicInfo, secretInfo);

        EncryptedPayload encrypted = envelopeEncryptionService.encrypt(secretInfo);
        String blindIndex = blindIndexService.computeBlindIndex(secretInfo);

        SecuredEntity entity = new SecuredEntity();
        entity.setPublicInfo(publicInfo.trim());
        entity.setSecretCipher(composeStoredCipher(encrypted.ivBase64(), encrypted.cipherTextBase64()));
        entity.setSecretDek(encrypted.wrappedDek());
        entity.setSecretKekVersion(parseKekVersion(encrypted.wrappedDek()));
        entity.setSecretBidx(blindIndex);

        return repository.save(entity);
    }

    @Override
    public SecuredEntity getById(UUID entityId) {
        Objects.requireNonNull(entityId, "entityId must not be null");
        return repository.findById(entityId)
                .orElseThrow(() -> new ResourceNotFoundException("Secured entity not found: " + entityId));
    }

    @Override
    public SecuredEntity update(UUID entityId, String publicInfo, String secretInfo) {
        validateInput(publicInfo, secretInfo);
        SecuredEntity existing = getById(entityId);

        EncryptedPayload encrypted = envelopeEncryptionService.encrypt(secretInfo);
        String blindIndex = blindIndexService.computeBlindIndex(secretInfo);

        existing.setPublicInfo(publicInfo.trim());
        existing.setSecretCipher(composeStoredCipher(encrypted.ivBase64(), encrypted.cipherTextBase64()));
        existing.setSecretDek(encrypted.wrappedDek());
        existing.setSecretKekVersion(parseKekVersion(encrypted.wrappedDek()));
        existing.setSecretBidx(blindIndex);

        return repository.save(existing);
    }

    @Override
    public void delete(UUID entityId) {
        Objects.requireNonNull(entityId, "entityId must not be null");
        if (!repository.deleteById(entityId)) {
            throw new ResourceNotFoundException("Secured entity not found: " + entityId);
        }
    }

    @Override
    public List<SecuredEntity> list(int page, int pageSize) {
        validatePaging(page, pageSize);
        List<SecuredEntity> all = repository.findAll();

        int from = Math.max(0, (page - 1) * pageSize);
        if (from >= all.size()) {
            return List.of();
        }
        int to = Math.min(all.size(), from + pageSize);
        return all.subList(from, to);
    }

    @Override
    public List<SecuredEntity> searchExactMatch(String secretInfo) {
        if (secretInfo == null || secretInfo.isBlank()) {
            return List.of();
        }

        String index = blindIndexService.computeBlindIndexForExactMatchQuery(secretInfo);
        List<SecuredEntity> candidates = repository.findBySecretBidx(index);

        String normalizedSearch = normalizeForEquality(secretInfo);
        List<SecuredEntity> matches = new ArrayList<>();
        for (SecuredEntity candidate : candidates) {
            String[] parts = parseStoredCipher(candidate.getSecretCipher());
            EncryptedPayload payload = new EncryptedPayload(
                    EnvelopeEncryptionServiceImplConstants.CIPHER_ALGORITHM,
                parts[0],
                parts[1],
                    candidate.getSecretDek(),
                    EnvelopeEncryptionServiceImplConstants.GCM_TAG_BITS
            );

            String decrypted = envelopeEncryptionService.decrypt(payload);
            if (normalizeForEquality(decrypted).equals(normalizedSearch)) {
                matches.add(candidate);
            }
        }

        return matches;
    }

    @Override
    public long count() {
        return repository.findAll().size();
    }

    private void validateInput(String publicInfo, String secretInfo) {
        if (publicInfo == null || publicInfo.isBlank()) {
            throw new IllegalArgumentException("publicInfo must not be blank");
        }
        if (secretInfo == null || secretInfo.isBlank()) {
            throw new IllegalArgumentException("secretInfo must not be blank");
        }
    }

    private void validatePaging(int page, int pageSize) {
        if (page < 1) {
            throw new IllegalArgumentException("page must be >= 1");
        }
        if (pageSize < 1 || pageSize > 100) {
            throw new IllegalArgumentException("pageSize must be between 1 and 100");
        }
    }

    private String normalizeForEquality(String input) {
        String trimmed = input.trim();
        String collapsed = trimmed.replaceAll("\\s+", " ");
        return Normalizer.normalize(collapsed.toLowerCase(), Normalizer.Form.NFC);
    }

    private String composeStoredCipher(String ivBase64, String cipherBase64) {
        return ivBase64 + ":" + cipherBase64;
    }

    private String[] parseStoredCipher(String storedCipher) {
        String[] parts = storedCipher.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Stored cipher payload is invalid");
        }
        return parts;
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

    private static final class EnvelopeEncryptionServiceImplConstants {
        private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
        private static final int GCM_TAG_BITS = 128;

        private EnvelopeEncryptionServiceImplConstants() {
        }
    }
}
