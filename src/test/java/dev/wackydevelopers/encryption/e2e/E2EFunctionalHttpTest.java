package dev.wackydevelopers.encryption.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wackydevelopers.encryption.EncryptionApplication;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import dev.wackydevelopers.encryption.entity.SecuredEntityRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = EncryptionApplication.class, properties = "spring.profiles.active=inmemory")
@AutoConfigureMockMvc
class E2EFunctionalHttpTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecuredEntityRepository repository;

    @AfterEach
    void cleanRepository() {
        for (SecuredEntity entity : repository.findAll()) {
            repository.deleteById(entity.getId());
        }
    }

    @Test
    void fullCrudLifecycleWorksThroughHttpOnly() throws Exception {
        JsonNode created = createEntity("pub-a", "secret-a");
        String id = created.path("data").path("id").asText();

        mockMvc.perform(get("/v1/entities/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.id").value(id))
                .andExpect(jsonPath("$.data.publicInfo").value("pub-a"))
                .andExpect(jsonPath("$.data.decryptedSecretInfo").doesNotExist());

        mockMvc.perform(get("/v1/entities/{id}", id).param("includeDecrypted", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.id").value(id))
                .andExpect(jsonPath("$.data.decryptedSecretInfo").value("secret-a"));

        mockMvc.perform(put("/v1/entities/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicInfo\":\"pub-a-updated\",\"secretInfo\":\"secret-a-updated\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.publicInfo").value("pub-a-updated"))
                .andExpect(jsonPath("$.data.decryptedSecretInfo").doesNotExist());

        mockMvc.perform(delete("/v1/entities/{id}", id))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/v1/entities/{id}", id))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void searchSupportsExactMatchAndRejectsWildcardPatterns() throws Exception {
        createEntity("pub-alpha", "Alpha Value");
        createEntity("pub-beta", "Beta Value");

        mockMvc.perform(post("/v1/entities/search")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretInfo\":\"  alpha   value  \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].publicInfo").value("pub-alpha"))
                .andExpect(jsonPath("$.data[0].decryptedSecretInfo").doesNotExist());

        mockMvc.perform(post("/v1/entities/search")
                        .param("includeDecrypted", "true")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretInfo\":\"  alpha   value  \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].decryptedSecretInfo").value("Alpha Value"));

        mockMvc.perform(post("/v1/entities/search")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretInfo\":\"alpha*\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("UNSUPPORTED_QUERY"));
    }

    @Test
    void listSupportsPaginationWithStableTotals() throws Exception {
        createEntity("pub-1", "sec-1");
        createEntity("pub-2", "sec-2");
        createEntity("pub-3", "sec-3");

        MvcResult pageOne = mockMvc.perform(get("/v1/entities?page=1&pageSize=2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pagination.totalItems").value(3))
                .andExpect(jsonPath("$.pagination.totalPages").value(2))
                .andExpect(jsonPath("$.data.length()").value(2))
                .andReturn();

        MvcResult pageTwo = mockMvc.perform(get("/v1/entities?page=2&pageSize=2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pagination.totalItems").value(3))
                .andExpect(jsonPath("$.data.length()").value(1))
                .andReturn();

        JsonNode pageOneBody = objectMapper.readTree(pageOne.getResponse().getContentAsString());
        JsonNode pageTwoBody = objectMapper.readTree(pageTwo.getResponse().getContentAsString());

        assertEquals(2, pageOneBody.path("data").size());
        assertEquals(1, pageTwoBody.path("data").size());
    }

    @Test
    void getUnknownRotationPlanReturnsNotFoundContract() throws Exception {
        String missingRotationId = UUID.randomUUID().toString();

        mockMvc.perform(get("/v1/admin/keys/rotations/{rotationId}", missingRotationId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    private JsonNode createEntity(String publicInfo, String secretInfo) throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/entities")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicInfo\":\"" + publicInfo + "\",\"secretInfo\":\"" + secretInfo + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertTrue(body.path("data").path("id").isTextual());
        return body;
    }
}
