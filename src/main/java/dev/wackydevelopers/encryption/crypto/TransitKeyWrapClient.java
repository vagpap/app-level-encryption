package dev.wackydevelopers.encryption.crypto;

public interface TransitKeyWrapClient {
    
    String wrapDek(byte[] dekPlaintext);

    byte[] unwrapDek(String wrappedDek);

    String rewrapDek(String wrappedDek);
}
