package dev.wackydevelopers.encryption.api;

import dev.wackydevelopers.encryption.blindindex.BlindIndexKeyProvider;
import dev.wackydevelopers.encryption.blindindex.BlindIndexService;
import dev.wackydevelopers.encryption.blindindex.BlindIndexServiceImpl;
import dev.wackydevelopers.encryption.blindindex.RotatableBlindIndexService;
import dev.wackydevelopers.encryption.blindindex.VaultBlindIndexKeyProvider;
import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionService;
import dev.wackydevelopers.encryption.crypto.EnvelopeEncryptionServiceImpl;
import dev.wackydevelopers.encryption.crypto.TransitKeyWrapClient;
import dev.wackydevelopers.encryption.crypto.VaultTransitKeyWrapClient;
import dev.wackydevelopers.encryption.entity.InMemorySecuredEntityRepository;
import dev.wackydevelopers.encryption.entity.JdbcSecuredEntityRepository;
import dev.wackydevelopers.encryption.entity.SecuredEntityRepository;
import dev.wackydevelopers.encryption.service.KeyRotationServiceImpl;
import dev.wackydevelopers.encryption.service.KeyRotationService;
import dev.wackydevelopers.encryption.service.SecuredEntityDomainService;
import dev.wackydevelopers.encryption.service.SecuredEntityDomainServiceImpl;
import dev.wackydevelopers.encryption.vault.VaultStartupReadinessVerifier;
import dev.wackydevelopers.encryption.vault.VaultTokenProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;

@Configuration
public class EncryptionApiConfiguration {

    @Bean
    @ConditionalOnProperty(name = "encryption.repository.mode", havingValue = "in-memory")
    public SecuredEntityRepository inMemorySecuredEntityRepository() {
        return new InMemorySecuredEntityRepository();
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.repository.mode", havingValue = "postgres", matchIfMissing = true)
    public SecuredEntityRepository jdbcSecuredEntityRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcSecuredEntityRepository(jdbcTemplate);
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "real", matchIfMissing = true)
    public VaultTokenProvider vaultTokenProvider(
            @Value("${encryption.vault.address:${VAULT_ADDR:http://localhost:8200}}") String vaultAddress,
            @Value("${encryption.vault.token:${VAULT_TOKEN:}}") String staticToken,
            @Value("${encryption.vault.role-id:${VAULT_ROLE_ID:}}") String roleId,
            @Value("${encryption.vault.secret-id:${VAULT_SECRET_ID:}}") String secretId,
            RestTemplate restTemplate,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        return new VaultTokenProvider(vaultAddress, staticToken, roleId, secretId, restTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "real", matchIfMissing = true)
    public TransitKeyWrapClient vaultTransitKeyWrapClient(
            @Value("${encryption.vault.address:${VAULT_ADDR:http://localhost:8200}}") String vaultAddress,
            @Value("${encryption.vault.transit-path:transit}") String transitPath,
            @Value("${encryption.vault.kek-name:app-kek}") String kekName,
            VaultTokenProvider vaultTokenProvider,
            RestTemplate restTemplate,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        return new VaultTransitKeyWrapClient(vaultAddress, transitPath, kekName, vaultTokenProvider, restTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "real", matchIfMissing = true)
    public VaultStartupReadinessVerifier vaultStartupReadinessVerifier(
            @Value("${encryption.vault.address:${VAULT_ADDR:http://localhost:8200}}") String vaultAddress,
            @Value("${encryption.vault.transit-path:transit}") String transitPath,
            @Value("${encryption.vault.kek-name:app-kek}") String kekName,
            @Value("${encryption.blind-index.key-path:secret/myapp/bik}") String blindIndexKeyPath,
            VaultTokenProvider vaultTokenProvider,
            RestTemplate restTemplate) {
        return new VaultStartupReadinessVerifier(
                vaultAddress,
                transitPath,
                kekName,
                blindIndexKeyPath,
                vaultTokenProvider,
                restTemplate);
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "real", matchIfMissing = true)
    public ApplicationRunner vaultStartupReadinessRunner(
            VaultStartupReadinessVerifier verifier,
            @Value("${encryption.vault.startup-check.enabled:true}") boolean startupCheckEnabled) {
        return args -> {
            if (startupCheckEnabled) {
                verifier.verifyOrThrow();
            }
        };
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "stub")
    public TransitKeyWrapClient stubTransitKeyWrapClient() {
        return new TransitKeyWrapClient() {
            @Override
            public String wrapDek(byte[] dekPlaintext) {
                return "vault:v1:" + java.util.Base64.getEncoder().encodeToString(java.util.Arrays.copyOf(dekPlaintext, dekPlaintext.length));
            }

            @Override
            public byte[] unwrapDek(String wrappedDek) {
                String[] parts = wrappedDek.split(":", 3);
                if (parts.length != 3) {
                    throw new IllegalArgumentException("Invalid wrapped DEK format");
                }
                return java.util.Base64.getDecoder().decode(parts[2].getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public String rewrapDek(String wrappedDek) {
                String[] parts = wrappedDek.split(":", 3);
                if (parts.length != 3 || !parts[1].startsWith("v")) {
                    throw new IllegalArgumentException("Invalid wrapped DEK format");
                }
                int currentVersion = Integer.parseInt(parts[1].substring(1));
                return "vault:v" + (currentVersion + 1) + ":" + parts[2];
            }
        };
    }

    @Bean
    public EnvelopeEncryptionService envelopeEncryptionService(TransitKeyWrapClient transitKeyWrapClient) {
        return new EnvelopeEncryptionServiceImpl(transitKeyWrapClient);
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "real", matchIfMissing = true)
    public BlindIndexKeyProvider vaultBlindIndexKeyProvider(
            @Value("${encryption.vault.address:${VAULT_ADDR:http://localhost:8200}}") String vaultAddress,
            @Value("${encryption.blind-index.key-path:secret/myapp/bik}") String blindIndexKeyPath,
            VaultTokenProvider vaultTokenProvider,
            RestTemplate restTemplate,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        return new VaultBlindIndexKeyProvider(vaultAddress, blindIndexKeyPath, vaultTokenProvider, restTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnProperty(name = "encryption.vault.mode", havingValue = "stub")
    public BlindIndexKeyProvider stubBlindIndexKeyProvider() {
        return () -> "local-dev-bik-seed-32-bytes-length".getBytes(StandardCharsets.UTF_8);
    }

    @Bean
    public RotatableBlindIndexService blindIndexService(BlindIndexKeyProvider keyProvider) {
        return new BlindIndexServiceImpl(keyProvider);
    }

    @Bean
    public SecuredEntityDomainService securedEntityDomainService(
            SecuredEntityRepository repository,
            EnvelopeEncryptionService encryptionService,
            BlindIndexService blindIndexService) {
        return new SecuredEntityDomainServiceImpl(repository, encryptionService, blindIndexService);
    }

    @Bean
    public KeyRotationService keyRotationService(
            SecuredEntityRepository repository,
            EnvelopeEncryptionService encryptionService,
            RotatableBlindIndexService blindIndexService,
            TransitKeyWrapClient transitKeyWrapClient,
            @Value("${encryption.rotation.kek.batch-size:100}") int kekBatchSize) {
        return new KeyRotationServiceImpl(repository, encryptionService, blindIndexService, transitKeyWrapClient, kekBatchSize);
    }
}
