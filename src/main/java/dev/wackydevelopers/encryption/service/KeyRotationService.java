package dev.wackydevelopers.encryption.service;

import java.time.Instant;

public interface KeyRotationService {
    
    KeyRotationPlan rotateKek(String reason);

    KeyRotationPlan rotateBik(String reason, boolean requireDryRun);

    KeyRotationPlan getPlan(String rotationId);

    KeyRotationPlan rollbackBik(String rotationId);

    record KeyRotationPlan(
            String rotationId,
            String keyType,
            Instant requestedAt,
            Instant executedAt,
            String status,
            boolean rollbackRequired,
            int affectedEntities,
            String reason,
            String details) {

        public KeyRotationPlan(
                String rotationId,
                String keyType,
                Instant requestedAt,
                Instant executedAt,
                String status,
                boolean rollbackRequired) {
            this(rotationId, keyType, requestedAt, executedAt, status, rollbackRequired, 0, "", "");
        }
    }
}
