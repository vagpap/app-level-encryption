package dev.wackydevelopers.encryption.crypto;

public class EnvelopeEncryptionException extends RuntimeException {
    
    public EnvelopeEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public EnvelopeEncryptionException(String message) {
        super(message);
    }
}
