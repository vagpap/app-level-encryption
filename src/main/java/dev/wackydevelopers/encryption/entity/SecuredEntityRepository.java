package dev.wackydevelopers.encryption.entity;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SecuredEntityRepository {
    
    SecuredEntity save(SecuredEntity entity);

    Optional<SecuredEntity> findById(UUID id);

    List<SecuredEntity> findAll();

    List<SecuredEntity> findBySecretBidx(String secretBidx);

    boolean deleteById(UUID id);
}
