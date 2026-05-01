package dev.wackydevelopers.encryption.api;

import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import dev.wackydevelopers.encryption.service.KeyRotationService;
import dev.wackydevelopers.encryption.service.ResourceNotFoundException;
import dev.wackydevelopers.encryption.service.SecuredEntityDomainService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ApiControllersTest {

    private MockMvc mockMvc;
    private SecuredEntityDomainService domainService;
    private KeyRotationService keyRotationService;

    @BeforeEach
    void setUp() {
        domainService = Mockito.mock(SecuredEntityDomainService.class);
        keyRotationService = Mockito.mock(KeyRotationService.class);
        EnvelopeEncryptionService envelopeEncryptionService = Mockito.mock(EnvelopeEncryptionService.class);
        Mockito.when(envelopeEncryptionService.decrypt(any())).thenReturn("sec");

        mockMvc = MockMvcBuilders
            .standaloneSetup(new SecuredEntitiesController(domainService, envelopeEncryptionService), new KeyOperationsController(keyRotationService))
                .setControllerAdvice(new ApiExceptionHandler())
                .build();
    }

    @Test
    void createEndpointShouldReturn201() throws Exception {
        Mockito.when(domainService.create(anyString(), anyString())).thenReturn(sampleEntity());

        mockMvc.perform(post("/v1/entities")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicInfo\":\"pub\",\"secretInfo\":\"sec\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.publicInfo").value("pub"))
            .andExpect(jsonPath("$.data.decryptedSecretInfo").doesNotExist());
    }

    @Test
    void listEndpointShouldReturn200WithPagination() throws Exception {
        Mockito.when(domainService.list(anyInt(), anyInt())).thenReturn(List.of(sampleEntity()));
        Mockito.when(domainService.count()).thenReturn(1L);

        mockMvc.perform(get("/v1/entities?page=1&pageSize=20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pagination.totalItems").value(1));
    }

    @Test
    void notFoundShouldReturn404ErrorContract() throws Exception {
        UUID id = UUID.randomUUID();
        Mockito.when(domainService.getById(id)).thenThrow(new ResourceNotFoundException("not found"));

        mockMvc.perform(get("/v1/entities/" + id))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

            @Test
            void getByIdShouldReturnDecryptedFieldOnlyWhenRequested() throws Exception {
            UUID id = UUID.randomUUID();
            SecuredEntity entity = sampleEntity();
            entity.setId(id);
            Mockito.when(domainService.getById(id)).thenReturn(entity);

            mockMvc.perform(get("/v1/entities/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.decryptedSecretInfo").doesNotExist());

            mockMvc.perform(get("/v1/entities/" + id).param("includeDecrypted", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.decryptedSecretInfo").value("sec"));
            }

    @Test
    void rotateBikShouldReturn202() throws Exception {
        KeyRotationService.KeyRotationPlan plan = new KeyRotationService.KeyRotationPlan(
                "rot-1", "BIK", Instant.now(), null, "REQUESTED", false);
        Mockito.when(keyRotationService.rotateBik(anyString(), anyBoolean())).thenReturn(plan);

        mockMvc.perform(post("/v1/admin/keys/bik/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"policy\",\"requireDryRun\":false}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.rotationId").value("rot-1"));
    }

    private SecuredEntity sampleEntity() {
        SecuredEntity entity = new SecuredEntity();
        entity.setId(UUID.randomUUID());
        entity.setPublicInfo("pub");
        entity.setSecretCipher("iv:cipher");
        entity.setSecretDek("vault:v1:dek");
        entity.setSecretBidx("abc123");
        entity.setCreatedAt(Instant.now());
        entity.setUpdatedAt(Instant.now());
        return entity;
    }
}
