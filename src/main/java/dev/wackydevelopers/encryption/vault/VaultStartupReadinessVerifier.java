package dev.wackydevelopers.encryption.vault;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

public class VaultStartupReadinessVerifier {
    
    private final String vaultAddress;
    private final String transitPath;
    private final String kekName;
    private final String blindIndexKeyPath;
    private final VaultTokenProvider tokenProvider;
    private final RestTemplate restTemplate;

    public VaultStartupReadinessVerifier(
            String vaultAddress,
            String transitPath,
            String kekName,
            String blindIndexKeyPath,
            VaultTokenProvider tokenProvider,
            RestTemplate restTemplate) {
        this.vaultAddress = normalizeAddress(vaultAddress);
        this.transitPath = normalizePathSegment(transitPath);
        this.kekName = normalizePathSegment(kekName);
        this.blindIndexKeyPath = normalizeKeyPath(blindIndexKeyPath);
        this.tokenProvider = tokenProvider;
        this.restTemplate = restTemplate;
    }

    public void verifyOrThrow() {
        verifyTransitKeyExists();
        verifyBlindIndexKeyPathExists();
    }

    private void verifyTransitKeyExists() {
        try {
            restTemplate.exchange(
                    vaultAddress + "/v1/" + transitPath + "/keys/" + kekName,
                    HttpMethod.GET,
                    requestEntity(),
                    String.class);
        } catch (HttpClientErrorException.NotFound ex) {
            throw new VaultStartupException(
                    "Vault transit key not found at '" + transitPath + "/keys/" + kekName
                            + "'. Run vault init/bootstrap before starting the API.",
                    ex);
        } catch (RuntimeException ex) {
            throw new VaultStartupException("Unable to verify Vault transit key availability", ex);
        }
    }

    private void verifyBlindIndexKeyPathExists() {
        int slash = blindIndexKeyPath.indexOf('/');
        String mountPath = blindIndexKeyPath.substring(0, slash);
        String secretPath = blindIndexKeyPath.substring(slash + 1);

        try {
            restTemplate.exchange(
                    vaultAddress + "/v1/" + mountPath + "/data/" + secretPath,
                    HttpMethod.GET,
                    requestEntity(),
                    String.class);
            return;
        } catch (HttpClientErrorException.NotFound ex) {
            try {
                restTemplate.exchange(
                        vaultAddress + "/v1/" + mountPath + "/" + secretPath,
                        HttpMethod.GET,
                        requestEntity(),
                        String.class);
                return;
            } catch (HttpClientErrorException.NotFound nested) {
                throw new VaultStartupException(
                        "Vault blind-index key not found at '" + blindIndexKeyPath
                                + "'. Ensure the BIK secret is provisioned before startup.",
                        nested);
            }
        } catch (RuntimeException ex) {
            throw new VaultStartupException("Unable to verify Vault blind-index key availability", ex);
        }
    }

    private HttpEntity<Void> requestEntity() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Vault-Token", tokenProvider.getToken());
        return new HttpEntity<>(headers);
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

    private static String normalizeKeyPath(String value) {
        String normalized = normalizePathSegment(value);
        if (!normalized.contains("/")) {
            throw new IllegalArgumentException("Blind-index key path must include mount and key path (example: secret/myapp/bik)");
        }
        return normalized;
    }
}