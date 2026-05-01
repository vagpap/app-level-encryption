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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = EncryptionApplication.class, properties = "spring.profiles.active=inmemory")
@AutoConfigureMockMvc
class E2ESecurityResilienceHttpTest {

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
    void repeatedWritesOfSamePlaintextProduceDifferentCipherArtifacts() throws Exception {
        JsonNode first = createEntity("pub-one", "same-secret-value");
        JsonNode second = createEntity("pub-two", "same-secret-value");

        String firstCipher = first.path("data").path("secretCipher").asText();
        String secondCipher = second.path("data").path("secretCipher").asText();
        String firstDek = first.path("data").path("secretDek").asText();
        String secondDek = second.path("data").path("secretDek").asText();

        assertNotEquals(firstCipher, secondCipher);
        assertNotEquals(firstDek, secondDek);
    }

    @Test
    void plaintextSecretIsReturnedInDedicatedFieldWhileEncryptedArtifactsRemainOpaque() throws Exception {
        String secret = "sensitive-value-123";
        JsonNode created = createEntity("pub-sensitive", secret);
        String entityId = created.path("data").path("id").asText();

        assertTrue(created.path("data").path("decryptedSecretInfo").isMissingNode());
        assertNotEquals(secret, created.path("data").path("secretCipher").asText());
        assertNotEquals(secret, created.path("data").path("secretDek").asText());

        MvcResult getResult = mockMvc.perform(get("/v1/entities/{id}", entityId))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode getBody = objectMapper.readTree(getResult.getResponse().getContentAsString());
        assertTrue(getBody.path("data").path("decryptedSecretInfo").isMissingNode());

        MvcResult getDecryptedResult = mockMvc.perform(get("/v1/entities/{id}", entityId).param("includeDecrypted", "true"))
            .andExpect(status().isOk())
            .andReturn();
        JsonNode getDecryptedBody = objectMapper.readTree(getDecryptedResult.getResponse().getContentAsString());
        assertEquals(secret, getDecryptedBody.path("data").path("decryptedSecretInfo").asText());

        MvcResult searchWithoutDecryptedResult = mockMvc.perform(post("/v1/entities/search")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"secretInfo\":\"" + secret + "\"}"))
            .andExpect(status().isOk())
            .andReturn();
        JsonNode searchWithoutDecryptedBody = objectMapper.readTree(searchWithoutDecryptedResult.getResponse().getContentAsString());
        assertTrue(searchWithoutDecryptedBody.path("data").get(0).path("decryptedSecretInfo").isMissingNode());

        MvcResult searchResult = mockMvc.perform(post("/v1/entities/search")
                .param("includeDecrypted", "true")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"secretInfo\":\"" + secret + "\"}"))
            .andExpect(status().isOk())
            .andReturn();
        JsonNode searchBody = objectMapper.readTree(searchResult.getResponse().getContentAsString());
        assertEquals(secret, getDecryptedBody.path("data").path("decryptedSecretInfo").asText());
        assertEquals(secret, searchBody.path("data").get(0).path("decryptedSecretInfo").asText());
    }

    @Test
    void serviceMaintainsCorrectnessAcrossBikRotation() throws Exception {
        JsonNode created = createEntity("pub-rotate", "rotation-secret");
        String id = created.path("data").path("id").asText();

        mockMvc.perform(post("/v1/entities/search")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretInfo\":\"rotation-secret\"}"))
                .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.length()").value(1))
            .andExpect(jsonPath("$.data[0].decryptedSecretInfo").doesNotExist());

        MvcResult rotationResult = mockMvc.perform(post("/v1/admin/keys/bik/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"e2e-security-test\",\"requireDryRun\":false}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.status").value("COMPLETED"))
                .andReturn();

        JsonNode rotationBody = objectMapper.readTree(rotationResult.getResponse().getContentAsString());
        assertEquals("BIK", rotationBody.path("data").path("keyType").asText());

        mockMvc.perform(post("/v1/entities/search")
                .param("includeDecrypted", "true")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretInfo\":\"rotation-secret\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].id").value(id))
                .andExpect(jsonPath("$.data[0].decryptedSecretInfo").value("rotation-secret"));
    }

    private JsonNode createEntity(String publicInfo, String secretInfo) throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/entities")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicInfo\":\"" + publicInfo + "\",\"secretInfo\":\"" + secretInfo + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }
}
