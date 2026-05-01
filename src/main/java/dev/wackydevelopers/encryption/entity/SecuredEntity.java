package dev.wackydevelopers.encryption.entity;

import java.time.Instant;
import java.util.UUID;

public class SecuredEntity {
    
    private UUID id;
    private String publicInfo;
    private String secretCipher;
    private String secretDek;
    private Integer secretKekVersion;
    private String secretBidx;
    private Instant createdAt;
    private Instant updatedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getPublicInfo() {
        return publicInfo;
    }

    public void setPublicInfo(String publicInfo) {
        this.publicInfo = publicInfo;
    }

    public String getSecretCipher() {
        return secretCipher;
    }

    public void setSecretCipher(String secretCipher) {
        this.secretCipher = secretCipher;
    }

    public String getSecretDek() {
        return secretDek;
    }

    public void setSecretDek(String secretDek) {
        this.secretDek = secretDek;
    }

    public Integer getSecretKekVersion() {
        return secretKekVersion;
    }

    public void setSecretKekVersion(Integer secretKekVersion) {
        this.secretKekVersion = secretKekVersion;
    }

    public String getSecretBidx() {
        return secretBidx;
    }

    public void setSecretBidx(String secretBidx) {
        this.secretBidx = secretBidx;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
