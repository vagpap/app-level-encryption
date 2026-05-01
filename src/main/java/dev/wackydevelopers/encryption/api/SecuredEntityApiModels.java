package dev.wackydevelopers.encryption.api;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

public final class SecuredEntityApiModels {

    private SecuredEntityApiModels() {
    }

    public record CreateSecuredEntityRequest(String publicInfo, String secretInfo) {}

    public record UpdateSecuredEntityRequest(String publicInfo, String secretInfo) {}

    public record SearchSecuredEntityRequest(String secretInfo) {}

    public record RotateKekRequest(String reason) {}

    public record RotateBikRequest(String reason, Boolean requireDryRun) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SecuredEntityDto(
            String id,
            String publicInfo,
            String decryptedSecretInfo,
            String secretCipher,
            String secretDek,
            String secretBidx,
            Instant createdAt,
            Instant updatedAt) {}

    public record SecuredEntityResponse(SecuredEntityDto data) {}

    public record SecuredEntityListResponse(List<SecuredEntityDto> data, Pagination pagination) {}

    public record SecuredEntitySearchResponse(List<SecuredEntityDto> data) {}

    public record Pagination(int page, int pageSize, long totalItems, long totalPages) {}

    public record KeyRotationPlanDto(
            String rotationId,
            String keyType,
            Instant requestedAt,
            Instant executedAt,
            String status,
            boolean rollbackRequired) {}

    public record KeyRotationPlanResponse(KeyRotationPlanDto data) {}
}
