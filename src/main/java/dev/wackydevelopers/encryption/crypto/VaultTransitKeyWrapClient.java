package dev.wackydevelopers.encryption.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wackydevelopers.encryption.vault.VaultTokenProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;
import java.util.Objects;

public class VaultTransitKeyWrapClient implements TransitKeyWrapClient {
    
    private final String vaultAddress;
    private final String transitPath;
    private final String kekName;
    private final VaultTokenProvider tokenProvider;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public VaultTransitKeyWrapClient(
            String vaultAddress,
            String transitPath,
            String kekName,
            VaultTokenProvider tokenProvider,
            RestTemplate restTemplate,
            ObjectMapper objectMapper) {
        this.vaultAddress = normalizeAddress(vaultAddress);
        this.transitPath = normalizePathSegment(transitPath);
        this.kekName = normalizePathSegment(kekName);
        this.tokenProvider = tokenProvider;
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public String wrapDek(byte[] dekPlaintext) {
        Objects.requireNonNull(dekPlaintext, "dekPlaintext must not be null");
        String plaintextB64 = Base64.getEncoder().encodeToString(dekPlaintext);

        String response = restTemplate.postForObject(
                vaultAddress + "/v1/" + transitPath + "/encrypt/" + kekName,
                requestEntity(Map.of("plaintext", plaintextB64)),
                String.class);

        return extractRequiredText(response, "data", "ciphertext");
    }

    @Override
    public byte[] unwrapDek(String wrappedDek) {
        Objects.requireNonNull(wrappedDek, "wrappedDek must not be null");

        String response = restTemplate.postForObject(
                vaultAddress + "/v1/" + transitPath + "/decrypt/" + kekName,
                requestEntity(Map.of("ciphertext", wrappedDek)),
                String.class);

        String plaintextB64 = extractRequiredText(response, "data", "plaintext");
        return Base64.getDecoder().decode(plaintextB64);
    }

    @Override
    public String rewrapDek(String wrappedDek) {
        Objects.requireNonNull(wrappedDek, "wrappedDek must not be null");

        String response = restTemplate.postForObject(
                vaultAddress + "/v1/" + transitPath + "/rewrap/" + kekName,
                requestEntity(Map.of("ciphertext", wrappedDek)),
                String.class);

        return extractRequiredText(response, "data", "ciphertext");
    }

    private HttpEntity<Map<String, String>> requestEntity(Map<String, String> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Vault-Token", tokenProvider.getToken());
        return new HttpEntity<>(body, headers);
    }

    private String extractRequiredText(String responseBody, String firstField, String secondField) {
        try {
            JsonNode root = objectMapper.readTree(Objects.requireNonNull(responseBody, "Vault response must not be null"));
            String value = root.path(firstField).path(secondField).asText();
            if (value == null || value.isBlank()) {
                throw new IllegalStateException("Vault response missing field: " + firstField + "." + secondField);
            }
            return value;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to parse Vault response", ex);
        }
    }

    private static String normalizeAddress(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Vault address must not be blank");
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private static String normalizePathSegment(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Vault path segment must not be blank");
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