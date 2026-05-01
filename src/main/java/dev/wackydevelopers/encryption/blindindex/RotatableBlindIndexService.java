package dev.wackydevelopers.encryption.blindindex;

public interface RotatableBlindIndexService extends BlindIndexService {
    
    void rotateKey(byte[] newBik);
}
