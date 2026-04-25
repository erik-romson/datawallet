package com.wilhelmsen.cbslink.plugin.datawallet.ratelimit;

import com.wilhelmsen.cbslink.plugin.datawallet.domain.RateLimitEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.RateLimitRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Token-bucket rate limiter backed by the {@code rate_limits} PostgreSQL table.
 *
 * <p>Each {@link #consume} call runs in its own {@code REQUIRES_NEW} transaction so the
 * bucket state commits independently of any surrounding caller transaction. The
 * {@code SELECT … FOR UPDATE} on the row serializes concurrent writers from multiple
 * threads or JVM instances.
 */
@Service
public class RateLimitService {

    public sealed interface Decision permits Decision.Allowed, Decision.Denied {
        record Allowed() implements Decision {}
        record Denied(long retryAfterSec) implements Decision {}
    }

    private final RateLimitRepository rateLimitRepository;
    private final Clock clock;

    public RateLimitService(RateLimitRepository rateLimitRepository, Clock clock) {
        this.rateLimitRepository = rateLimitRepository;
        this.clock = clock;
    }

    /**
     * Consumes one token from the bucket identified by {@code key}.
     *
     * @param key          composite key (e.g. {@code "ip:verifier_id"})
     * @param capacity     maximum burst size (initial tokens on first request)
     * @param refillPerSec sustained rate expressed as tokens added per second
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Decision consume(String key, double capacity, double refillPerSec) {
        Instant now = Instant.now(clock);
        rateLimitRepository.insertIfAbsent(key, capacity, now);
        RateLimitEntity entity = rateLimitRepository.findByKeyForUpdate(key).orElseThrow();

        double elapsed = Duration.between(entity.getRefilledAt(), now).toMillis() / 1000.0;
        double refilled = Math.min(capacity, entity.getTokens() + Math.max(0.0, elapsed) * refillPerSec);

        entity.setRefilledAt(now);

        if (refilled >= 1.0) {
            entity.setTokens(refilled - 1.0);
            rateLimitRepository.save(entity);
            return new Decision.Allowed();
        }

        entity.setTokens(refilled);
        rateLimitRepository.save(entity);
        long retryAfterSec = Math.max(1L, (long) Math.ceil((1.0 - refilled) / refillPerSec));
        return new Decision.Denied(retryAfterSec);
    }
}
