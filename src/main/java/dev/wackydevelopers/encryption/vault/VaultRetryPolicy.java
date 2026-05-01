package dev.wackydevelopers.encryption.vault;

public record VaultRetryPolicy(
        int maxAttempts,
        long initialDelayMillis,
        double backoffMultiplier,
        long maxDelayMillis) {

    public VaultRetryPolicy {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1");
        }
        if (initialDelayMillis < 0 || maxDelayMillis < 0) {
            throw new IllegalArgumentException("Delay values must be >= 0");
        }
        if (backoffMultiplier < 1.0d) {
            throw new IllegalArgumentException("backoffMultiplier must be >= 1.0");
        }
        if (maxDelayMillis > 0 && initialDelayMillis > maxDelayMillis) {
            throw new IllegalArgumentException("initialDelayMillis must be <= maxDelayMillis");
        }
    }
}
