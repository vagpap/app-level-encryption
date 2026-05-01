package dev.wackydevelopers.encryption.crypto.spi;

import java.security.SecureRandom;

public class SecureRandomIvGenerator implements IvGenerator {
    
    private final SecureRandom secureRandom;

    public SecureRandomIvGenerator(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public byte[] generate(int size) {
        byte[] iv = new byte[size];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
