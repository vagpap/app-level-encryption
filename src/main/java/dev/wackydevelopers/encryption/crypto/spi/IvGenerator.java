package dev.wackydevelopers.encryption.crypto.spi;

public interface IvGenerator {
    
    byte[] generate(int size);
}
