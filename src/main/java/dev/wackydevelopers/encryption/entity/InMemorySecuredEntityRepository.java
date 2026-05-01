package dev.wackydevelopers.encryption.entity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class InMemorySecuredEntityRepository implements SecuredEntityRepository {
    
    private final ConcurrentHashMap<UUID, SecuredEntity> storage = new ConcurrentHashMap<>();

    @Override
    public SecuredEntity save(SecuredEntity entity) {
        if (entity.getId() == null) {
            entity.setId(UUID.randomUUID());
            entity.setCreatedAt(Instant.now());
        }
        entity.setUpdatedAt(Instant.now());
        storage.put(entity.getId(), copy(entity));
        return copy(entity);
    }

    @Override
    public Optional<SecuredEntity> findById(UUID id) {
        SecuredEntity found = storage.get(id);
        return Optional.ofNullable(found).map(this::copy);
    }

    @Override
    public List<SecuredEntity> findAll() {
        return storage.values().stream()
                .sorted(Comparator.comparing(SecuredEntity::getCreatedAt).reversed())
                .map(this::copy)
                .toList();
    }

    @Override
    public List<SecuredEntity> findBySecretBidx(String secretBidx) {
        List<SecuredEntity> matches = new ArrayList<>();
        for (SecuredEntity value : storage.values()) {
            if (secretBidx.equals(value.getSecretBidx())) {
                matches.add(copy(value));
            }
        }
        return matches;
    }

    @Override
    public boolean deleteById(UUID id) {
        return storage.remove(id) != null;
    }

    private SecuredEntity copy(SecuredEntity src) {
        SecuredEntity c = new SecuredEntity();
        c.setId(src.getId());
        c.setPublicInfo(src.getPublicInfo());
        c.setSecretCipher(src.getSecretCipher());
        c.setSecretDek(src.getSecretDek());
        c.setSecretKekVersion(src.getSecretKekVersion());
        c.setSecretBidx(src.getSecretBidx());
        c.setCreatedAt(src.getCreatedAt());
        c.setUpdatedAt(src.getUpdatedAt());
        return c;
    }
}
