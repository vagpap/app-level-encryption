package dev.wackydevelopers.encryption.crypto.spi;

import java.security.SecureRandom;

public class SecureRandomDekGenerator implements DekGenerator {
    
    private final SecureRandom secureRandom;

    public SecureRandomDekGenerator(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public byte[] generate(int size) {
        byte[] dek = new byte[size];
        secureRandom.nextBytes(dek);
        return dek;
    }
}
