package dev.wackydevelopers.encryption.vault;

public interface VaultTokenLifecycleMetrics {
    
    void recordRenewalSuccess();

    void recordRenewalSkipped();

    void recordRenewalFailure();
}
