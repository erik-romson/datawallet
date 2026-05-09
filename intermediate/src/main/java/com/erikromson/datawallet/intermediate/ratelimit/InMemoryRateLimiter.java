package com.erikromson.datawallet.intermediate.ratelimit;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory token-bucket rate limiter, keyed by an arbitrary string.
 *
 * <p>Buckets are created on first use and never evicted (the key space is
 * bounded by the number of distinct client IPs that reach the service).
 */
@Component
public class InMemoryRateLimiter {

    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    /**
     * Attempts to consume one token from the bucket for {@code key}.
     *
     * @return {@code true} if the request is allowed, {@code false} if rate-limited
     */
    public boolean tryConsume(String key, double capacity, double refillPerSec) {
        return buckets.computeIfAbsent(key, k -> new TokenBucket(capacity, refillPerSec))
                      .tryConsume();
    }
}
