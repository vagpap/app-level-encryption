package dev.wackydevelopers.encryption.vault;

import java.time.Instant;

public record VaultTokenLeaseStatus(
        String leaseId,
        Instant expiresAt,
        boolean renewable,
        boolean renewed) {
}
