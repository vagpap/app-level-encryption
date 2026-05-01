package dev.wackydevelopers.encryption.vault;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class VaultTokenLifecycleManager {
    
    private final VaultTokenLifecycleClient lifecycleClient;
    private final VaultTokenLifecycleMetrics metrics;
    private final AtomicReference<VaultTokenLeaseStatus> lastStatus = new AtomicReference<>();

    public VaultTokenLifecycleManager(
            VaultTokenLifecycleClient lifecycleClient,
            VaultTokenLifecycleMetrics metrics) {
        this.lifecycleClient = lifecycleClient;
        this.metrics = metrics;
    }

    public VaultTokenLeaseStatus renewCycle() {
        try {
            VaultTokenLeaseStatus status = Objects.requireNonNull(
                    lifecycleClient.renewIfNeeded(),
                    "Vault token lease status must not be null");

            lastStatus.set(status);

            if (!status.renewable()) {
                metrics.recordRenewalSkipped();
            } else if (status.renewed()) {
                metrics.recordRenewalSuccess();
            } else {
                metrics.recordRenewalSkipped();
            }

            return status;
        } catch (RuntimeException ex) {
            metrics.recordRenewalFailure();
            throw ex;
        }
    }

    public VaultTokenLeaseStatus getLastStatus() {
        return lastStatus.get();
    }
}
