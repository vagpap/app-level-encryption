package dev.wackydevelopers.encryption.service;

import dev.wackydevelopers.encryption.entity.SecuredEntity;

import java.util.List;
import java.util.UUID;

public interface SecuredEntityDomainService {
    
    SecuredEntity create(String publicInfo, String secretInfo);

    SecuredEntity getById(UUID entityId);

    SecuredEntity update(UUID entityId, String publicInfo, String secretInfo);

    void delete(UUID entityId);

    List<SecuredEntity> list(int page, int pageSize);

    List<SecuredEntity> searchExactMatch(String secretInfo);

    long count();
}
