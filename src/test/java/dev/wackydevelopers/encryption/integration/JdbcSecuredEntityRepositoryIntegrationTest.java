package dev.wackydevelopers.encryption.integration;

import dev.wackydevelopers.encryption.entity.JdbcSecuredEntityRepository;
import dev.wackydevelopers.encryption.entity.SecuredEntity;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers(disabledWithoutDocker = true)
class JdbcSecuredEntityRepositoryIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("wackydevelopers")
            .withUsername("wackydevelopers")
            .withPassword("wackydevelopers");

    @Test
    void shouldCreateUpdateListAndDeleteEntitiesThroughJdbcRepository() throws Exception {
        JdbcSecuredEntityRepository repository = repositoryWithSchema();

        SecuredEntity first = new SecuredEntity();
        first.setPublicInfo("public-one");
        first.setSecretCipher("iv1:cipher1");
        first.setSecretDek("vault:v1:dek1");
        first.setSecretBidx("bidx-1");

        SecuredEntity second = new SecuredEntity();
        second.setPublicInfo("public-two");
        second.setSecretCipher("iv2:cipher2");
        second.setSecretDek("vault:v1:dek2");
        second.setSecretBidx("bidx-2");

        SecuredEntity savedFirst = repository.save(first);
        SecuredEntity savedSecond = repository.save(second);

        assertNotNull(savedFirst.getId());
        assertNotNull(savedSecond.getId());

        Optional<SecuredEntity> loadedFirst = repository.findById(savedFirst.getId());
        assertTrue(loadedFirst.isPresent());
        assertEquals("public-one", loadedFirst.get().getPublicInfo());

        Instant originalCreatedAt = loadedFirst.get().getCreatedAt();
        Instant originalUpdatedAt = loadedFirst.get().getUpdatedAt();

        loadedFirst.get().setPublicInfo("public-one-updated");
        loadedFirst.get().setSecretCipher("iv1:cipher1-updated");
        loadedFirst.get().setSecretDek("vault:v1:dek1-updated");
        loadedFirst.get().setSecretBidx("bidx-1-updated");

        SecuredEntity updated = repository.save(loadedFirst.get());
        assertEquals(savedFirst.getId(), updated.getId());
        assertEquals(originalCreatedAt, updated.getCreatedAt());
        assertTrue(!updated.getUpdatedAt().isBefore(originalUpdatedAt));

        List<SecuredEntity> all = repository.findAll();
        assertEquals(2, all.size());

        List<SecuredEntity> byBlindIndex = repository.findBySecretBidx("bidx-1-updated");
        assertEquals(1, byBlindIndex.size());
        assertEquals(savedFirst.getId(), byBlindIndex.get(0).getId());

        boolean deleted = repository.deleteById(savedSecond.getId());
        assertTrue(deleted);
        assertFalse(repository.findById(savedSecond.getId()).isPresent());

        UUID unknownId = UUID.randomUUID();
        assertFalse(repository.deleteById(unknownId));
    }

    private JdbcSecuredEntityRepository repositoryWithSchema() throws Exception {
        DataSource dataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(),
                POSTGRES.getPassword());

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("create extension if not exists pgcrypto");
            statement.execute("""
                    create table if not exists secured_entities (
                        id uuid primary key default gen_random_uuid(),
                        public_info text not null,
                        secret_cipher text not null,
                        secret_dek text not null,
                        secret_kek_version integer not null default 1,
                        secret_bidx varchar(64) not null,
                        created_at timestamptz not null default now(),
                        updated_at timestamptz not null default now()
                    )
                    """);
            statement.execute("create index if not exists idx_secured_entities_secret_bidx on secured_entities(secret_bidx)");
            statement.execute("delete from secured_entities");
        }

        return new JdbcSecuredEntityRepository(new JdbcTemplate(dataSource));
    }
}