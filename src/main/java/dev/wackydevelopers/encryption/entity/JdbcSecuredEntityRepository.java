package dev.wackydevelopers.encryption.entity;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JdbcSecuredEntityRepository implements SecuredEntityRepository {
    
    private static final String SELECT_COLUMNS = "select id, public_info, secret_cipher, secret_dek, secret_kek_version, secret_bidx, created_at, updated_at from secured_entities";
    private static final Pattern WRAPPED_DEK_VERSION_PATTERN = Pattern.compile("^vault:v(\\d+):");

    private final JdbcTemplate jdbcTemplate;

    public JdbcSecuredEntityRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public SecuredEntity save(SecuredEntity entity) {
        UUID entityId = entity.getId() != null ? entity.getId() : UUID.randomUUID();
        Instant createdAt = resolveCreatedAt(entity, entityId);
        Instant updatedAt = Instant.now();
        int kekVersion = resolveSecretKekVersion(entity, entityId);

        jdbcTemplate.update(
                """
                        insert into secured_entities (id, public_info, secret_cipher, secret_dek, secret_kek_version, secret_bidx, created_at, updated_at)
                        values (?, ?, ?, ?, ?, ?, ?, ?)
                        on conflict (id) do update
                        set public_info = excluded.public_info,
                            secret_cipher = excluded.secret_cipher,
                            secret_dek = excluded.secret_dek,
                            secret_kek_version = excluded.secret_kek_version,
                            secret_bidx = excluded.secret_bidx,
                            updated_at = excluded.updated_at
                        """,
                entityId,
                entity.getPublicInfo(),
                entity.getSecretCipher(),
                entity.getSecretDek(),
                kekVersion,
                entity.getSecretBidx(),
                Timestamp.from(createdAt),
                Timestamp.from(updatedAt)
        );

        SecuredEntity saved = copy(entity);
        saved.setId(entityId);
        saved.setSecretKekVersion(kekVersion);
        saved.setCreatedAt(createdAt);
        saved.setUpdatedAt(updatedAt);
        return saved;
    }

    @Override
    public Optional<SecuredEntity> findById(UUID id) {
        List<SecuredEntity> matches = jdbcTemplate.query(
                SELECT_COLUMNS + " where id = ?",
                (rs, rowNum) -> mapRow(rs),
                id
        );
        return matches.stream().findFirst();
    }

    @Override
    public List<SecuredEntity> findAll() {
        return jdbcTemplate.query(
                SELECT_COLUMNS + " order by created_at desc",
                (rs, rowNum) -> mapRow(rs)
        );
    }

    @Override
    public List<SecuredEntity> findBySecretBidx(String secretBidx) {
        return jdbcTemplate.query(
                SELECT_COLUMNS + " where secret_bidx = ? order by created_at desc",
                (rs, rowNum) -> mapRow(rs),
                secretBidx
        );
    }

    @Override
    public boolean deleteById(UUID id) {
        return jdbcTemplate.update("delete from secured_entities where id = ?", id) > 0;
    }

    private Instant resolveCreatedAt(SecuredEntity entity, UUID entityId) {
        if (entity.getCreatedAt() != null) {
            return entity.getCreatedAt();
        }

        if (entity.getId() == null) {
            return Instant.now();
        }

        try {
            Timestamp existingCreatedAt = jdbcTemplate.queryForObject(
                    "select created_at from secured_entities where id = ?",
                    Timestamp.class,
                    entityId
            );
            return existingCreatedAt != null ? existingCreatedAt.toInstant() : Instant.now();
        } catch (EmptyResultDataAccessException ex) {
            return Instant.now();
        }
    }

    private int resolveSecretKekVersion(SecuredEntity entity, UUID entityId) {
        if (entity.getSecretKekVersion() != null) {
            return entity.getSecretKekVersion();
        }

        if (entity.getId() != null) {
            try {
                Integer existingVersion = jdbcTemplate.queryForObject(
                        "select secret_kek_version from secured_entities where id = ?",
                        Integer.class,
                        entityId
                );
                if (existingVersion != null) {
                    return existingVersion;
                }
            } catch (EmptyResultDataAccessException ignored) {
                // fall through to parse from wrapped DEK
            }
        }

        return parseKekVersion(entity.getSecretDek());
    }

    private int parseKekVersion(String wrappedDek) {
        if (wrappedDek == null || wrappedDek.isBlank()) {
            return 1;
        }

        Matcher matcher = WRAPPED_DEK_VERSION_PATTERN.matcher(wrappedDek);
        if (!matcher.find()) {
            return 1;
        }

        return Integer.parseInt(matcher.group(1));
    }

    private SecuredEntity mapRow(java.sql.ResultSet rs) throws java.sql.SQLException {
        SecuredEntity entity = new SecuredEntity();
        entity.setId(rs.getObject("id", UUID.class));
        entity.setPublicInfo(rs.getString("public_info"));
        entity.setSecretCipher(rs.getString("secret_cipher"));
        entity.setSecretDek(rs.getString("secret_dek"));
        entity.setSecretKekVersion(rs.getInt("secret_kek_version"));
        entity.setSecretBidx(rs.getString("secret_bidx"));
        entity.setCreatedAt(rs.getTimestamp("created_at").toInstant());
        entity.setUpdatedAt(rs.getTimestamp("updated_at").toInstant());
        return entity;
    }

    private SecuredEntity copy(SecuredEntity source) {
        SecuredEntity copy = new SecuredEntity();
        copy.setId(source.getId());
        copy.setPublicInfo(source.getPublicInfo());
        copy.setSecretCipher(source.getSecretCipher());
        copy.setSecretDek(source.getSecretDek());
        copy.setSecretKekVersion(source.getSecretKekVersion());
        copy.setSecretBidx(source.getSecretBidx());
        copy.setCreatedAt(source.getCreatedAt());
        copy.setUpdatedAt(source.getUpdatedAt());
        return copy;
    }
}