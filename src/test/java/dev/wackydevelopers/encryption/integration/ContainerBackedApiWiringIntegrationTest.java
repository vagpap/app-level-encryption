package dev.wackydevelopers.encryption.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wackydevelopers.encryption.EncryptionApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.vault.VaultContainer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = EncryptionApplication.class, properties = "encryption.repository.mode=postgres")
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
class ContainerBackedApiWiringIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("wackydevelopers")
            .withUsername("wackydevelopers")
            .withPassword("wackydevelopers");

    @Container
    static final VaultContainer<?> VAULT = new VaultContainer<>("hashicorp/vault:1.17")
            .withVaultToken("root-token")
            .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/app-kek type=aes256-gcm96",
                    "kv put secret/myapp/bik key=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
            );

    @DynamicPropertySource
    static void registerContainerProperties(DynamicPropertyRegistry registry) {
                registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
                registry.add("spring.datasource.username", POSTGRES::getUsername);
                registry.add("spring.datasource.password", POSTGRES::getPassword);
                registry.add("encryption.vault.address", () -> "http://" + VAULT.getHost() + ":" + VAULT.getMappedPort(8200));
                registry.add("encryption.vault.token", () -> "root-token");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void apiWiringShouldCreateAndSearchEntityWhileContainersAreHealthy() throws Exception {
        MvcResult create = mockMvc.perform(post("/v1/entities")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicInfo\":\"container-wired\",\"secretInfo\":\"vault-and-postgres-up\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.id").exists())
                .andExpect(jsonPath("$.data.decryptedSecretInfo").doesNotExist())
                .andReturn();

        JsonNode created = objectMapper.readTree(create.getResponse().getContentAsString());

        MvcResult search = mockMvc.perform(post("/v1/entities/search")
                        .param("includeDecrypted", "true")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretInfo\":\"vault-and-postgres-up\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].decryptedSecretInfo").value("vault-and-postgres-up"))
                .andReturn();

        JsonNode searchBody = objectMapper.readTree(search.getResponse().getContentAsString());
        assertEquals(created.path("data").path("id").asText(), searchBody.path("data").get(0).path("id").asText());
    }
}
