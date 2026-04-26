package com.erikromson.datawallet.domain;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface AuthChallengeRepository extends JpaRepository<AuthChallengeEntity, AuthChallengeEntity.PK> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM AuthChallengeEntity c WHERE c.verifierId = :verifierId AND c.nonce = :nonce")
    Optional<AuthChallengeEntity> findForUpdate(UUID verifierId, byte[] nonce);
}
