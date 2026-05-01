package dev.wackydevelopers.encryption.service;

import dev.wackydevelopers.encryption.blindindex.BlindIndexService;
import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.entity.InMemorySecuredEntityRepository;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecuredEntityDomainServiceImplTest {

    @Test
    void createShouldPersistEncryptedFieldsWithoutPlaintextLeak() {
        SecuredEntityDomainService service = new SecuredEntityDomainServiceImpl(
                new InMemorySecuredEntityRepository(),
                new DeterministicEnvelopeService(),
                new ExactBlindIndexService());

        SecuredEntity created = service.create("pub", "super-secret");

        assertNotNull(created.getId());
        assertNotEquals("super-secret", created.getSecretCipher());
        assertNotEquals("super-secret", created.getSecretDek());
        assertFalse(created.getSecretCipher().contains("super-secret"));
        assertFalse(created.getSecretDek().contains("super-secret"));
    }

    @Test
    void searchShouldFilterBlindIndexCollisionsByDecryptionVerification() {
        SecuredEntityDomainService service = new SecuredEntityDomainServiceImpl(
                new InMemorySecuredEntityRepository(),
                new DeterministicEnvelopeService(),
                new CollisionBlindIndexService());

        service.create("pub1", "alpha-value");
        service.create("pub2", "beta-value");

        List<SecuredEntity> results = service.searchExactMatch("alpha-value");

        assertEquals(1, results.size());
        assertEquals("pub1", results.get(0).getPublicInfo());
    }

    @Test
    void listShouldApplyPageAndPageSizeBounds() {
        SecuredEntityDomainService service = new SecuredEntityDomainServiceImpl(
                new InMemorySecuredEntityRepository(),
                new DeterministicEnvelopeService(),
                new ExactBlindIndexService());

        service.create("p1", "s1");
        service.create("p2", "s2");
        service.create("p3", "s3");

        List<SecuredEntity> firstPage = service.list(1, 2);
        List<SecuredEntity> secondPage = service.list(2, 2);

        assertEquals(2, firstPage.size());
        assertEquals(1, secondPage.size());
    }

    private static final class DeterministicEnvelopeService implements EnvelopeEncryptionService {
        @Override
        public EncryptedPayload encrypt(String plaintext) {
            String iv = Base64.getEncoder().encodeToString("fixed-iv-12b".getBytes(StandardCharsets.UTF_8));
            String cipher = Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
            String wrapped = "vault:v1:" + Base64.getEncoder().encodeToString(("dek-" + plaintext).getBytes(StandardCharsets.UTF_8));
            return new EncryptedPayload("AES/GCM/NoPadding", iv, cipher, wrapped, 128);
        }

        @Override
        public String decrypt(EncryptedPayload payload) {
            return new String(Base64.getDecoder().decode(payload.cipherTextBase64()), StandardCharsets.UTF_8);
        }
    }

    private static final class ExactBlindIndexService implements BlindIndexService {
        @Override
        public void initialize() {
        }

        @Override
        public String computeBlindIndex(String plaintext) {
            return plaintext.trim().toLowerCase();
        }

        @Override
        public String computeBlindIndexForExactMatchQuery(String query) {
            return computeBlindIndex(query);
        }
    }

    private static final class CollisionBlindIndexService implements BlindIndexService {
        @Override
        public void initialize() {
        }

        @Override
        public String computeBlindIndex(String plaintext) {
            return "collision-index";
        }

        @Override
        public String computeBlindIndexForExactMatchQuery(String query) {
            return "collision-index";
        }
    }
}
