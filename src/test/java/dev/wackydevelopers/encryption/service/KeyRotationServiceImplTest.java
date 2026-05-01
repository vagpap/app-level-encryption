package dev.wackydevelopers.encryption.service;

import dev.wackydevelopers.encryption.blindindex.BlindIndexServiceImpl;
import dev.wackydevelopers.encryption.blindindex.RotatableBlindIndexService;
import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.crypto.TransitKeyWrapClient;
import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.entity.InMemorySecuredEntityRepository;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import dev.wackydevelopers.encryption.entity.SecuredEntityRepository;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KeyRotationServiceImplTest {

    @Test
    void rotateKekShouldRewrapDeksAndAdvanceKekVersion() {
        SecuredEntityRepository repository = seededRepository();
        KeyRotationServiceImpl service = createService(repository);

        List<String> originalDeks = repository.findAll().stream().map(SecuredEntity::getSecretDek).toList();

        KeyRotationService.KeyRotationPlan plan = service.rotateKek("routine");

        assertEquals("COMPLETED", plan.status());
        assertEquals("KEK", plan.keyType());
        assertTrue(plan.affectedEntities() >= 2);

        List<SecuredEntity> entities = repository.findAll();
        for (int i = 0; i < entities.size(); i++) {
            assertNotEquals(originalDeks.get(i), entities.get(i).getSecretDek());
            assertEquals(2, entities.get(i).getSecretKekVersion());
        }
    }

    @Test
    void rotateBikShouldSucceedAfterKekRotation() {
        SecuredEntityRepository repository = seededRepository();
        KeyRotationServiceImpl service = createService(repository);

        KeyRotationService.KeyRotationPlan kekPlan = service.rotateKek("routine");
        KeyRotationService.KeyRotationPlan bikPlan = service.rotateBik("post-kek-validation", false);

        assertEquals("COMPLETED", kekPlan.status());
        assertEquals("COMPLETED", bikPlan.status());
        assertFalse(bikPlan.rollbackRequired());
    }

    @Test
    void rotateBikShouldRecomputeIndexesAndCompletePlan() {
        SecuredEntityRepository repository = seededRepository();
        KeyRotationServiceImpl service = createService(repository);

        List<SecuredEntity> before = repository.findAll();
        String firstBefore = before.get(0).getSecretBidx();

        KeyRotationService.KeyRotationPlan plan = service.rotateBik("compromise", false);

        assertEquals("COMPLETED", plan.status());
        assertEquals("BIK", plan.keyType());

        List<SecuredEntity> after = repository.findAll();
        String firstAfter = after.get(0).getSecretBidx();
        assertNotEquals(firstBefore, firstAfter);
    }

    @Test
    void rollbackBikShouldRestoreSnapshot() {
        SecuredEntityRepository repository = seededRepository();
        KeyRotationServiceImpl service = createService(repository);

        List<SecuredEntity> before = repository.findAll();
        String expectedIndex = before.get(0).getSecretBidx();

        KeyRotationService.KeyRotationPlan rotation = service.rotateBik("policy", false);
        service.rollbackBik(rotation.rotationId());

        List<SecuredEntity> restored = repository.findAll();
        assertEquals(expectedIndex, restored.get(0).getSecretBidx());
    }

    private SecuredEntityRepository seededRepository() {
        InMemorySecuredEntityRepository repository = new InMemorySecuredEntityRepository();
        repository.save(createEntity("alpha", "index-a"));
        repository.save(createEntity("beta", "index-b"));
        return repository;
    }

    private SecuredEntity createEntity(String plaintextSecret, String bidx) {
        SecuredEntity entity = new SecuredEntity();
        entity.setPublicInfo("pub-" + plaintextSecret);
        String iv = Base64.getEncoder().encodeToString("fixed-iv-12b".getBytes(StandardCharsets.UTF_8));
        String cipher = Base64.getEncoder().encodeToString(plaintextSecret.getBytes(StandardCharsets.UTF_8));
        entity.setSecretCipher(iv + ":" + cipher);
        entity.setSecretDek("vault:v1:ZGVr");
        entity.setSecretKekVersion(1);
        entity.setSecretBidx(bidx);
        return entity;
    }

    private KeyRotationServiceImpl createService(SecuredEntityRepository repository) {
        RotatableBlindIndexService blindIndex = new BlindIndexServiceImpl(() -> "seedseedseedseedseedseedseedseed".getBytes(StandardCharsets.UTF_8));
        TransitKeyWrapClient transitKeyWrapClient = new SimulatedTransitRewrapClient();
        return new KeyRotationServiceImpl(repository, new DeterministicEnvelopeService(), blindIndex, transitKeyWrapClient, 2);
    }

    private static final class SimulatedTransitRewrapClient implements TransitKeyWrapClient {
        @Override
        public String wrapDek(byte[] dekPlaintext) {
            return "vault:v1:" + Base64.getEncoder().encodeToString(dekPlaintext);
        }

        @Override
        public byte[] unwrapDek(String wrappedDek) {
            String[] parts = wrappedDek.split(":", 3);
            return Base64.getDecoder().decode(parts[2]);
        }

        @Override
        public String rewrapDek(String wrappedDek) {
            String[] parts = wrappedDek.split(":", 3);
            int currentVersion = Integer.parseInt(parts[1].substring(1));
            return "vault:v" + (currentVersion + 1) + ":" + parts[2];
        }
    }

    private static final class DeterministicEnvelopeService implements EnvelopeEncryptionService {
        @Override
        public EncryptedPayload encrypt(String plaintext) {
            String iv = Base64.getEncoder().encodeToString("fixed-iv-12b".getBytes(StandardCharsets.UTF_8));
            String cipher = Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
            return new EncryptedPayload("AES/GCM/NoPadding", iv, cipher, "vault:v1:dek", 128);
        }

        @Override
        public String decrypt(EncryptedPayload payload) {
            return new String(Base64.getDecoder().decode(payload.cipherTextBase64()), StandardCharsets.UTF_8);
        }
    }
}
