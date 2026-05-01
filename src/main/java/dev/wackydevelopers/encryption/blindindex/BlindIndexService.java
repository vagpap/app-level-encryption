package dev.wackydevelopers.encryption.blindindex;

public interface BlindIndexService {
    
    void initialize();

    String computeBlindIndex(String plaintext);

    String computeBlindIndexForExactMatchQuery(String query);
}
