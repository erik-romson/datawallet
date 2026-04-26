package com.erikromson.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EntryRepository extends JpaRepository<EntryEntity, EntryEntity.EntryId> {

    @Query(value = """
            SELECT e.* FROM entries e
            JOIN entry_recipients er ON e.entry_id = er.entry_id AND e.version = er.version
            WHERE er.verifier_id = :verifierId
            AND e.is_current = true
            ORDER BY e.created_at DESC, e.entry_id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<EntryEntity> findCurrentForVerifier(
            @Param("verifierId") UUID verifierId,
            @Param("limit") int limit);

    @Query(value = """
            SELECT e.* FROM entries e
            JOIN entry_recipients er ON e.entry_id = er.entry_id AND e.version = er.version
            WHERE er.verifier_id = :verifierId
            AND e.is_current = true
            AND e.created_at >= :since
            ORDER BY e.created_at DESC, e.entry_id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<EntryEntity> findCurrentForVerifierSince(
            @Param("verifierId") UUID verifierId,
            @Param("since") Instant since,
            @Param("limit") int limit);

    @Query(value = """
            SELECT e.* FROM entries e
            JOIN entry_recipients er ON e.entry_id = er.entry_id AND e.version = er.version
            WHERE er.verifier_id = :verifierId
            AND e.is_current = true
            AND (e.created_at < :cursorTs
                 OR (e.created_at = :cursorTs AND e.entry_id < :cursorId))
            ORDER BY e.created_at DESC, e.entry_id DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<EntryEntity> findCurrentForVerifierWithCursor(
            @Param("verifierId") UUID verifierId,
            @Param("cursorTs") Instant cursorTs,
            @Param("cursorId") UUID cursorId,
            @Param("limit") int limit);

    @Query(value = """
            SELECT e.* FROM entries e
            JOIN entry_recipients er ON e.entry_id = er.entry_id AND e.version = er.version
            WHERE e.entry_id = :entryId
            AND er.verifier_id = :verifierId
            AND e.is_current = true
            """, nativeQuery = true)
    Optional<EntryEntity> findCurrentByEntryIdForVerifier(
            @Param("entryId") UUID entryId,
            @Param("verifierId") UUID verifierId);

    @Query("SELECT e FROM EntryEntity e WHERE e.entryId = :entryId AND e.isCurrent = true")
    Optional<EntryEntity> findCurrentByEntryId(@Param("entryId") UUID entryId);

    /**
     * Optimistically flips {@code is_current} to false only when the row still has the expected version.
     * Returns 1 if the flip succeeded, 0 if a concurrent writer already changed it.
     */
    @Modifying
    @Query("UPDATE EntryEntity e SET e.isCurrent = false, e.supersededAt = :now " +
           "WHERE e.entryId = :entryId AND e.version = :version AND e.isCurrent = true")
    int flipCurrentToSuperseded(@Param("entryId") UUID entryId,
                                @Param("version") int version,
                                @Param("now") Instant now);

    @Query("SELECT MAX(e.version) FROM EntryEntity e WHERE e.entryId = :entryId")
    Optional<Integer> findMaxVersionByEntryId(@Param("entryId") UUID entryId);

    boolean existsByEntryIdAndIssuerId(UUID entryId, UUID issuerId);

    boolean existsByEntryId(UUID entryId);

    @Modifying
    @Query("DELETE FROM EntryEntity e WHERE e.entryId = :entryId")
    void deleteByEntryId(@Param("entryId") UUID entryId);

    @Modifying
    @Query(value = "DELETE FROM entries WHERE NOT is_current AND superseded_at < :threshold", nativeQuery = true)
    int deleteSupersededBefore(@Param("threshold") Instant threshold);
}
