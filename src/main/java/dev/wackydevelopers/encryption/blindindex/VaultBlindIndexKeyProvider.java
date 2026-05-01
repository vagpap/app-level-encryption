package dev.wackydevelopers.encryption.blindindex;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wackydevelopers.encryption.vault.VaultTokenProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

public class VaultBlindIndexKeyProvider implements BlindIndexKeyProvider {
    
    private final String vaultAddress;
    private final String mountPath;
    private final String secretPath;
    private final VaultTokenProvider tokenProvider;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public VaultBlindIndexKeyProvider(
            String vaultAddress,
            String blindIndexKeyPath,
            VaultTokenProvider tokenProvider,
            RestTemplate restTemplate,
            ObjectMapper objectMapper) {
        this.vaultAddress = normalizeAddress(vaultAddress);
        String normalizedPath = normalizeSecretPath(blindIndexKeyPath);
        int slash = normalizedPath.indexOf('/');
        if (slash < 0) {
            throw new IllegalArgumentException("Blind-index key path must include mount and nested path, e.g. secret/myapp/bik");
        }

        this.mountPath = normalizedPath.substring(0, slash);
        this.secretPath = normalizedPath.substring(slash + 1);
        this.tokenProvider = tokenProvider;
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public byte[] loadBlindIndexKey() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Vault-Token", tokenProvider.getToken());

        String rawValue;
        try {
            ResponseEntity<String> kvV2Response = restTemplate.exchange(
                    vaultAddress + "/v1/" + mountPath + "/data/" + secretPath,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class);
            rawValue = extractRequiredText(kvV2Response.getBody(), "data", "data", "key");
        } catch (HttpClientErrorException.NotFound ex) {
            ResponseEntity<String> kvV1Response = restTemplate.exchange(
                    vaultAddress + "/v1/" + mountPath + "/" + secretPath,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class);
            rawValue = extractRequiredText(kvV1Response.getBody(), "data", "key");
        }

        try {
            return Base64.getDecoder().decode(rawValue);
        } catch (IllegalArgumentException ex) {
            return rawValue.getBytes(StandardCharsets.UTF_8);
        }
    }

    private String extractRequiredText(String responseBody, String... path) {
        try {
            JsonNode root = objectMapper.readTree(Objects.requireNonNull(responseBody, "Vault response must not be null"));
            JsonNode current = root;
            for (String segment : path) {
                current = current.path(segment);
            }

            String value = current.asText();
            if (value == null || value.isBlank()) {
                throw new IllegalStateException("Vault response missing key material at expected path");
            }
            return value;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to parse Vault blind-index key response", ex);
        }
    }

    private static String normalizeAddress(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Vault address must not be blank");
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private static String normalizeSecretPath(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Blind-index key path must not be blank");
        }
        String trimmed = value.trim();
        if (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}