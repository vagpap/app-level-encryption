package dev.wackydevelopers.encryption.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wackydevelopers.encryption.vault.VaultRetryPolicy;
import dev.wackydevelopers.encryption.vault.VaultStartupConnectivityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.vault.VaultContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers(disabledWithoutDocker = true)
class VaultAppRoleIntegrationTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Container
    static final VaultContainer<?> VAULT = new VaultContainer<>("hashicorp/vault:1.17")
            .withVaultToken("root-token")
            .withInitCommand(
                    "auth enable approle",
                    "write auth/approle/role/app-role token_policies=default token_period=60"
            );

    private HttpClient httpClient;
    private String vaultAddress;

    @BeforeEach
    void setUp() {
        this.httpClient = HttpClient.newHttpClient();
        this.vaultAddress = "http://" + VAULT.getHost() + ":" + VAULT.getMappedPort(8200);
    }

    @Test
    void appRoleAuthAndTokenRenewalShouldSucceed() throws Exception {
        String roleId = execVaultReadField("auth/approle/role/app-role/role-id", "role_id");
        String secretId = execVaultWriteAndReadField("auth/approle/role/app-role/secret-id", "secret_id");

        String loginBody = "{\"role_id\":\"" + roleId + "\",\"secret_id\":\"" + secretId + "\"}";
        JsonNode loginResponse = postJson("/v1/auth/approle/login", loginBody, null);

        String clientToken = loginResponse.path("auth").path("client_token").asText();
        assertNotNull(clientToken);
        assertTrue(!clientToken.isBlank());
        assertTrue(loginResponse.path("auth").path("renewable").asBoolean());

        JsonNode renewal = postJson("/v1/auth/token/renew-self", "{}", clientToken);
        assertTrue(renewal.path("auth").path("lease_duration").asLong() > 0);
    }

    @Test
    void startupConnectivityServiceShouldPassAgainstRunningVault() {
        VaultStartupConnectivityService connectivityService = new VaultStartupConnectivityService(
                () -> {
                    try {
                        HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(vaultAddress + "/v1/sys/health"))
                                .GET()
                                .build();
                        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                        int status = response.statusCode();
                        if (status < 200 || status >= 500) {
                            throw new IllegalStateException("Unexpected Vault health status: " + status);
                        }
                    } catch (Exception ex) {
                        throw new RuntimeException("Vault health probe failed", ex);
                    }
                },
                new VaultRetryPolicy(3, 100, 2.0d, 1_000),
                millis -> {
                }
        );

        connectivityService.ensureConnectivityOrThrow();
    }

    private String execVaultReadField(String path, String field) throws Exception {
        org.testcontainers.containers.Container.ExecResult result = VAULT.execInContainer(
                "sh", "-c", "VAULT_TOKEN=root-token vault read -field=" + field + " " + path);
        return result.getStdout().trim();
    }

    private String execVaultWriteAndReadField(String path, String field) throws Exception {
        org.testcontainers.containers.Container.ExecResult result = VAULT.execInContainer(
                "sh", "-c", "VAULT_TOKEN=root-token vault write -f -field=" + field + " " + path);
        return result.getStdout().trim();
    }

    private JsonNode postJson(String path, String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(vaultAddress + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));

        if (token != null && !token.isBlank()) {
            builder.header("X-Vault-Token", token);
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return OBJECT_MAPPER.readTree(response.body());
    }
}
