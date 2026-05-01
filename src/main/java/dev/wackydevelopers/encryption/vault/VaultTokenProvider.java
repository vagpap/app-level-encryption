package dev.wackydevelopers.encryption.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class VaultTokenProvider {
    
    private final String vaultAddress;
    private final String staticToken;
    private final String roleId;
    private final String secretId;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final AtomicReference<String> cachedToken = new AtomicReference<>();

    public VaultTokenProvider(
            String vaultAddress,
            String staticToken,
            String roleId,
            String secretId,
            RestTemplate restTemplate,
            ObjectMapper objectMapper) {
        this.vaultAddress = normalizeAddress(vaultAddress);
        this.staticToken = trimToNull(staticToken);
        this.roleId = trimToNull(roleId);
        this.secretId = trimToNull(secretId);
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public String getToken() {
        if (staticToken != null) {
            return staticToken;
        }

        String token = cachedToken.get();
        if (token != null) {
            return token;
        }

        synchronized (this) {
            String current = cachedToken.get();
            if (current != null) {
                return current;
            }

            String loginToken = loginWithAppRole();
            cachedToken.set(loginToken);
            return loginToken;
        }
    }

    private String loginWithAppRole() {
        if (roleId == null || secretId == null) {
            throw new IllegalStateException("Vault token is not configured. Set VAULT_TOKEN or VAULT_ROLE_ID and VAULT_SECRET_ID.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, String>> request = new HttpEntity<>(
                Map.of("role_id", roleId, "secret_id", secretId),
                headers);

        String response = restTemplate.postForObject(
                vaultAddress + "/v1/auth/approle/login",
                request,
                String.class);

        try {
            JsonNode root = objectMapper.readTree(Objects.requireNonNull(response, "Vault auth response must not be null"));
            String token = root.path("auth").path("client_token").asText();
            if (token == null || token.isBlank()) {
                throw new IllegalStateException("Vault AppRole login did not return a client token");
            }
            return token;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to parse Vault AppRole login response", ex);
        }
    }

    private static String normalizeAddress(String vaultAddress) {
        String trimmed = trimToNull(vaultAddress);
        if (trimmed == null) {
            throw new IllegalArgumentException("Vault address must not be blank");
        }
        if (trimmed.endsWith("/")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}