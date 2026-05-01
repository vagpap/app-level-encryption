package dev.wackydevelopers.encryption.api;

import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.crypto.model.EncryptedPayload;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import dev.wackydevelopers.encryption.service.SecuredEntityDomainService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

import static dev.wackydevelopers.encryption.api.SecuredEntityApiModels.*;

@RestController
@RequestMapping("/v1/entities")
public class SecuredEntitiesController {
    
    private final SecuredEntityDomainService domainService;
    private final EnvelopeEncryptionService envelopeEncryptionService;

    public SecuredEntitiesController(
            SecuredEntityDomainService domainService,
            EnvelopeEncryptionService envelopeEncryptionService) {
        this.domainService = domainService;
        this.envelopeEncryptionService = envelopeEncryptionService;
    }

    @GetMapping
    public ResponseEntity<SecuredEntityListResponse> listSecuredEntities(
            @RequestParam(name = "page", defaultValue = "1") int page,
            @RequestParam(name = "pageSize", defaultValue = "20") int pageSize) {
        List<SecuredEntity> pageData = domainService.list(page, pageSize);
        long totalItems = domainService.count();
        long totalPages = (long) Math.ceil((double) totalItems / pageSize);
        List<SecuredEntityDto> mapped = pageData.stream().map(entity -> toDto(entity, false)).toList();
        return ResponseEntity.ok(new SecuredEntityListResponse(mapped, new Pagination(page, pageSize, totalItems, totalPages)));
    }

    @PostMapping
    public ResponseEntity<SecuredEntityResponse> createSecuredEntity(@RequestBody CreateSecuredEntityRequest request) {
        SecuredEntity created = domainService.create(request.publicInfo(), request.secretInfo());
        return ResponseEntity.status(HttpStatus.CREATED).body(new SecuredEntityResponse(toDto(created, false)));
    }

    @GetMapping("/{entityId}")
    public ResponseEntity<SecuredEntityResponse> getSecuredEntityById(
            @PathVariable("entityId") UUID entityId,
            @RequestParam(name = "includeDecrypted", defaultValue = "false") boolean includeDecrypted) {
        SecuredEntity found = domainService.getById(entityId);
        return ResponseEntity.ok(new SecuredEntityResponse(toDto(found, includeDecrypted)));
    }

    @PutMapping("/{entityId}")
    public ResponseEntity<SecuredEntityResponse> updateSecuredEntity(
            @PathVariable("entityId") UUID entityId,
            @RequestBody UpdateSecuredEntityRequest request) {
        SecuredEntity updated = domainService.update(entityId, request.publicInfo(), request.secretInfo());
        return ResponseEntity.ok(new SecuredEntityResponse(toDto(updated, false)));
    }

    @DeleteMapping("/{entityId}")
    public ResponseEntity<Void> deleteSecuredEntity(@PathVariable("entityId") UUID entityId) {
        domainService.delete(entityId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/search")
    public ResponseEntity<SecuredEntitySearchResponse> searchSecuredEntities(
            @RequestBody SearchSecuredEntityRequest request,
            @RequestParam(name = "includeDecrypted", defaultValue = "false") boolean includeDecrypted) {
        List<SecuredEntityDto> results = domainService.searchExactMatch(request.secretInfo()).stream()
                .map(entity -> toDto(entity, includeDecrypted))
                .toList();
        return ResponseEntity.ok(new SecuredEntitySearchResponse(results));
    }

    private SecuredEntityDto toDto(SecuredEntity entity, boolean includeDecrypted) {
        String decryptedSecretInfo = includeDecrypted ? decryptSecret(entity) : null;
        return new SecuredEntityDto(
                entity.getId().toString(),
                entity.getPublicInfo(),
                decryptedSecretInfo,
                entity.getSecretCipher(),
                entity.getSecretDek(),
                entity.getSecretBidx(),
                entity.getCreatedAt(),
                entity.getUpdatedAt());
    }

    private String decryptSecret(SecuredEntity entity) {
        String[] parts = entity.getSecretCipher().split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Stored cipher payload is invalid");
        }

        EncryptedPayload payload = new EncryptedPayload(
                "AES/GCM/NoPadding",
                parts[0],
                parts[1],
                entity.getSecretDek(),
                128);
        return envelopeEncryptionService.decrypt(payload);
    }
}
