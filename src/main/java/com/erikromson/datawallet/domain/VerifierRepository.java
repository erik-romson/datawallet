package com.erikromson.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VerifierRepository extends JpaRepository<VerifierEntity, UUID> {

    Optional<VerifierEntity> findByHandle(String handle);

    @Query(value = """
            SELECT v.* FROM verifiers v
            WHERE v.discoverable AND v.status = 'active'
            ORDER BY v.created_at DESC, v.verifier_id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<VerifierEntity> findDiscoverable(@Param("limit") int limit);

    @Query(value = """
            SELECT v.* FROM verifiers v
            WHERE v.discoverable AND v.status = 'active'
            AND v.created_at >= :since
            ORDER BY v.created_at DESC, v.verifier_id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<VerifierEntity> findDiscoverableSince(
            @Param("since") Instant since,
            @Param("limit") int limit);

    @Query(value = """
            SELECT v.* FROM verifiers v
            WHERE v.discoverable AND v.status = 'active'
            AND (v.created_at < :cursorTs
                 OR (v.created_at = :cursorTs AND v.verifier_id < :cursorId))
            ORDER BY v.created_at DESC, v.verifier_id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<VerifierEntity> findDiscoverableWithCursor(
            @Param("cursorTs") Instant cursorTs,
            @Param("cursorId") UUID cursorId,
            @Param("limit") int limit);
}
