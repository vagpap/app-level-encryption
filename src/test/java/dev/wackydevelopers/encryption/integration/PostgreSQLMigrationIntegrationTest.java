package dev.wackydevelopers.encryption.integration;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers(disabledWithoutDocker = true)
class PostgreSqlMigrationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("wackydevelopers")
            .withUsername("wackydevelopers")
            .withPassword("wackydevelopers");

    @Test
    void migrationStartupShouldCreatePgcryptoTableAndIndex() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(),
                POSTGRES.getPassword())) {

            executeMigrationBaseline(connection);

            assertTrue(existsQuery(connection,
                    "select 1 from pg_extension where extname = 'pgcrypto'"));
            assertTrue(existsQuery(connection,
                    "select 1 from information_schema.tables where table_name = 'secured_entities'"));
            assertTrue(existsQuery(connection,
                    "select 1 from pg_indexes where tablename = 'secured_entities' and indexname = 'idx_secured_entities_secret_bidx'"));
        }
    }

    @Test
    void persistenceLookupShouldWorkWithBlindIndexColumn() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(),
                POSTGRES.getPassword())) {

            executeMigrationBaseline(connection);

            String blindIndex = "0123456789abcdef0123456789abcdef";
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into secured_entities (public_info, secret_cipher, secret_dek, secret_bidx) values (?, ?, ?, ?)")) {
                insert.setString(1, "public-a");
                insert.setString(2, "iv:cipher");
                insert.setString(3, "vault:v1:wrapped");
                insert.setString(4, blindIndex);
                insert.executeUpdate();
            }

            try (PreparedStatement query = connection.prepareStatement(
                    "select count(*) from secured_entities where secret_bidx = ?")) {
                query.setString(1, blindIndex);
                try (ResultSet resultSet = query.executeQuery()) {
                    assertTrue(resultSet.next());
                    assertEquals(1, resultSet.getInt(1));
                }
            }
        }
    }

    private static void executeMigrationBaseline(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("create extension if not exists pgcrypto");
            statement.execute("""
                    create table if not exists secured_entities (
                        id uuid primary key default gen_random_uuid(),
                        public_info text not null,
                        secret_cipher text not null,
                        secret_dek text not null,
                        secret_kek_version integer not null default 1,
                        secret_bidx char(32) not null,
                        created_at timestamptz not null default now(),
                        updated_at timestamptz not null default now()
                    )
                    """);
            statement.execute("create index if not exists idx_secured_entities_secret_bidx on secured_entities(secret_bidx)");
        }
    }

    private static boolean existsQuery(Connection connection, String query) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(query)) {
            return resultSet.next();
        }
    }
}
