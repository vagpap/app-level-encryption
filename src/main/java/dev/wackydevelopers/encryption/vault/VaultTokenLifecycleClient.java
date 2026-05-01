package dev.wackydevelopers.encryption.vault;

public interface VaultTokenLifecycleClient {
    VaultTokenLeaseStatus renewIfNeeded();
}
