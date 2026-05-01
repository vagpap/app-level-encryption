package dev.wackydevelopers.encryption.vault;

public class VaultStartupConnectivityService {
    
    private final VaultConnectivityProbe connectivityProbe;
    private final VaultRetryPolicy retryPolicy;
    private final Sleeper sleeper;

    public VaultStartupConnectivityService(
            VaultConnectivityProbe connectivityProbe,
            VaultRetryPolicy retryPolicy,
            Sleeper sleeper) {
        this.connectivityProbe = connectivityProbe;
        this.retryPolicy = retryPolicy;
        this.sleeper = sleeper;
    }

    public void ensureConnectivityOrThrow() {
        RuntimeException lastFailure = null;

        for (int attempt = 1; attempt <= retryPolicy.maxAttempts(); attempt++) {
            try {
                connectivityProbe.checkConnectivity();
                return;
            } catch (RuntimeException ex) {
                lastFailure = ex;
                if (attempt == retryPolicy.maxAttempts()) {
                    break;
                }
                long delay = computeDelayMillis(attempt);
                safeSleep(delay, ex);
            }
        }

        throw buildActionableFailure(lastFailure);
    }

    long computeDelayMillis(int attemptNumber) {
        if (attemptNumber <= 0) {
            throw new IllegalArgumentException("attemptNumber must be > 0");
        }
        double exponential = retryPolicy.initialDelayMillis() * Math.pow(retryPolicy.backoffMultiplier(), (double) attemptNumber - 1.0d);
        long candidate = (long) exponential;
        if (retryPolicy.maxDelayMillis() == 0) {
            return candidate;
        }
        return Math.min(candidate, retryPolicy.maxDelayMillis());
    }

    private void safeSleep(long millis, RuntimeException originalFailure) {
        if (millis <= 0) {
            return;
        }
        try {
            sleeper.sleep(millis);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new VaultStartupException("Vault startup retry interrupted", originalFailure);
        }
    }

    private VaultStartupException buildActionableFailure(RuntimeException cause) {
        String message = "Unable to establish Vault connectivity after " + retryPolicy.maxAttempts()
                + " attempts. Verify VAULT_ADDR/VAULT_TOKEN, confirm Vault health status, and inspect network/TLS configuration.";
        return new VaultStartupException(message, cause);
    }
}
