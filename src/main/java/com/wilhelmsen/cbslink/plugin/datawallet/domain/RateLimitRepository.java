package com.wilhelmsen.cbslink.plugin.datawallet.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface RateLimitRepository extends JpaRepository<RateLimitEntity, String> {

    @Modifying
    @Query(value = "INSERT INTO rate_limits(key, tokens, refilled_at) VALUES (:key, :capacity, :now) ON CONFLICT DO NOTHING",
            nativeQuery = true)
    void insertIfAbsent(@Param("key") String key,
                        @Param("capacity") double capacity,
                        @Param("now") Instant now);

    @Query(value = "SELECT * FROM rate_limits WHERE key = :key FOR UPDATE", nativeQuery = true)
    Optional<RateLimitEntity> findByKeyForUpdate(@Param("key") String key);
}
