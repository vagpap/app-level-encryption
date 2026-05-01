package dev.wackydevelopers.encryption.crypto;

import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.crypto.spi.DekGenerator;
import dev.wackydevelopers.encryption.crypto.spi.IvGenerator;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeEncryptionServiceImplTest {

    @Test
    void encryptAndDecryptRoundTripShouldSucceed() {
        RecordingTransitClient transitClient = new RecordingTransitClient();
        DekGenerator dekGenerator = size -> new byte[32];
        IvGenerator ivGenerator = size -> createFilledArray((byte) 7, 12);

        EnvelopeEncryptionService service = new EnvelopeEncryptionServiceImpl(transitClient, dekGenerator, ivGenerator);

        String plaintext = "sensitive-value";
        EncryptedPayload payload = service.encrypt(plaintext);

        assertNotEquals(plaintext, payload.cipherTextBase64());
        assertEquals(EnvelopeEncryptionServiceImpl.CIPHER_ALGORITHM, payload.algorithm());
        assertEquals(128, payload.gcmTagBits());

        String decrypted = service.decrypt(payload);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void twoEncryptionsForSamePlaintextShouldProduceDifferentCiphertext() {
        RecordingTransitClient transitClient = new RecordingTransitClient();
        IncrementingDekGenerator dekGenerator = new IncrementingDekGenerator();
        IncrementingIvGenerator ivGenerator = new IncrementingIvGenerator();

        EnvelopeEncryptionService service = new EnvelopeEncryptionServiceImpl(transitClient, dekGenerator, ivGenerator);

        String plaintext = "same-input";
        EncryptedPayload first = service.encrypt(plaintext);
        EncryptedPayload second = service.encrypt(plaintext);

        assertNotEquals(first.ivBase64(), second.ivBase64());
        assertNotEquals(first.cipherTextBase64(), second.cipherTextBase64());
    }

    @Test
    void dekShouldBeZeroizedAfterEncryption() {
        RecordingTransitClient transitClient = new RecordingTransitClient();
        RetainedDekGenerator retainedDekGenerator = new RetainedDekGenerator();
        IvGenerator ivGenerator = size -> createFilledArray((byte) 3, size);

        EnvelopeEncryptionService service = new EnvelopeEncryptionServiceImpl(transitClient, retainedDekGenerator, ivGenerator);

        service.encrypt("zeroize-check");

        assertNotNull(retainedDekGenerator.lastGeneratedDek);
        for (byte b : retainedDekGenerator.lastGeneratedDek) {
            assertEquals(0, b);
        }
    }

    private static byte[] createFilledArray(byte value, int size) {
        byte[] bytes = new byte[size];
        Arrays.fill(bytes, value);
        return bytes;
    }

    private static final class RetainedDekGenerator implements DekGenerator {
        private byte[] lastGeneratedDek;

        @Override
        public byte[] generate(int size) {
            lastGeneratedDek = createFilledArray((byte) 11, size);
            return lastGeneratedDek;
        }
    }

    private static final class IncrementingDekGenerator implements DekGenerator {
        private int seed = 1;

        @Override
        public byte[] generate(int size) {
            byte[] dek = new byte[size];
            Arrays.fill(dek, (byte) seed++);
            return dek;
        }
    }

    private static final class IncrementingIvGenerator implements IvGenerator {
        private int seed = 1;

        @Override
        public byte[] generate(int size) {
            byte[] iv = new byte[size];
            Arrays.fill(iv, (byte) (seed++ * 7));
            return iv;
        }
    }

    private static final class RecordingTransitClient implements TransitKeyWrapClient {
        @Override
        public String wrapDek(byte[] dekPlaintext) {
            byte[] copy = Arrays.copyOf(dekPlaintext, dekPlaintext.length);
            return "vault:v1:" + Base64.getEncoder().encodeToString(copy);
        }

        @Override
        public byte[] unwrapDek(String wrappedDek) {
            String[] parts = wrappedDek.split(":", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid wrapped DEK format");
            }
            return Base64.getDecoder().decode(parts[2].getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public String rewrapDek(String wrappedDek) {
            String[] parts = wrappedDek.split(":", 3);
            if (parts.length != 3 || !parts[1].startsWith("v")) {
                throw new IllegalArgumentException("Invalid wrapped DEK format");
            }
            int currentVersion = Integer.parseInt(parts[1].substring(1));
            return "vault:v" + (currentVersion + 1) + ":" + parts[2];
        }
    }
}
