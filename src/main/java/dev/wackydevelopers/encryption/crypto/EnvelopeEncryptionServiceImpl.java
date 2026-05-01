package dev.wackydevelopers.encryption.crypto;

import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.crypto.spi.DekGenerator;
import dev.wackydevelopers.encryption.crypto.spi.IvGenerator;
import dev.wackydevelopers.encryption.crypto.spi.SecureRandomDekGenerator;
import dev.wackydevelopers.encryption.crypto.spi.SecureRandomIvGenerator;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public class EnvelopeEncryptionServiceImpl implements EnvelopeEncryptionService {
    
    static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    static final int DEK_BYTES = 32;
    static final int IV_BYTES = 12;
    static final int GCM_TAG_BITS = 128;

    private final TransitKeyWrapClient transitKeyWrapClient;
    private final DekGenerator dekGenerator;
    private final IvGenerator ivGenerator;

    public EnvelopeEncryptionServiceImpl(TransitKeyWrapClient transitKeyWrapClient) {
        SecureRandom secureRandom = new SecureRandom();
        this.transitKeyWrapClient = transitKeyWrapClient;
        this.dekGenerator = new SecureRandomDekGenerator(secureRandom);
        this.ivGenerator = new SecureRandomIvGenerator(secureRandom);
    }

    public EnvelopeEncryptionServiceImpl(
            TransitKeyWrapClient transitKeyWrapClient,
            DekGenerator dekGenerator,
            IvGenerator ivGenerator) {
        this.transitKeyWrapClient = transitKeyWrapClient;
        this.dekGenerator = dekGenerator;
        this.ivGenerator = ivGenerator;
    }

    @Override
    public EncryptedPayload encrypt(String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext must not be null");

        byte[] dek = dekGenerator.generate(DEK_BYTES);
        byte[] iv = ivGenerator.generate(IV_BYTES);

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            String wrappedDek = transitKeyWrapClient.wrapDek(dek);

            return new EncryptedPayload(
                    CIPHER_ALGORITHM,
                    Base64.getEncoder().encodeToString(iv),
                    Base64.getEncoder().encodeToString(cipherBytes),
                    wrappedDek,
                    GCM_TAG_BITS);
        } catch (Exception ex) {
            throw new EnvelopeEncryptionException("Encryption failed", ex);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    @Override
    public String decrypt(EncryptedPayload payload) {
        Objects.requireNonNull(payload, "payload must not be null");

        byte[] dek = transitKeyWrapClient.unwrapDek(payload.wrappedDek());

        try {
            byte[] iv = Base64.getDecoder().decode(payload.ivBase64());
            byte[] cipherBytes = Base64.getDecoder().decode(payload.cipherTextBase64());

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(payload.gcmTagBits(), iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            byte[] plainBytes = cipher.doFinal(cipherBytes);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new EnvelopeEncryptionException("Decryption failed", ex);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }
}
