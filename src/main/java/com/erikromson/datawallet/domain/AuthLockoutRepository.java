package com.erikromson.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface AuthLockoutRepository extends JpaRepository<AuthLockoutEntity, UUID> {

    @Query(value = "SELECT * FROM auth_lockouts WHERE verifier_id = :verifierId FOR UPDATE",
            nativeQuery = true)
    Optional<AuthLockoutEntity> findByVerifierIdForUpdate(@Param("verifierId") UUID verifierId);
}
