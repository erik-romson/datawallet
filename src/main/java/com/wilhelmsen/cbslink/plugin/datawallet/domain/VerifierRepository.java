package com.wilhelmsen.cbslink.plugin.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface VerifierRepository extends JpaRepository<VerifierEntity, UUID> {

    Optional<VerifierEntity> findByHandle(String handle);
}
