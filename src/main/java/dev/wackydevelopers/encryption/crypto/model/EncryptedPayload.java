package dev.wackydevelopers.encryption.crypto.model;

public record EncryptedPayload(
        String algorithm,
        String ivBase64,
        String cipherTextBase64,
        String wrappedDek,
        int gcmTagBits) {
}
