package dev.wackydevelopers.encryption.crypto.spi;

public interface DekGenerator {
    
    byte[] generate(int size);
}
