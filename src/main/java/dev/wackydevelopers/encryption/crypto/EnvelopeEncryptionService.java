package dev.wackydevelopers.encryption.crypto;

import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;

public interface EnvelopeEncryptionService {
    
    EncryptedPayload encrypt(String plaintext);

    String decrypt(EncryptedPayload payload);
}
