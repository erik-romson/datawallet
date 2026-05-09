package com.erikromson.datawallet.intermediate.ratelimit;

/**
 * Thread-safe in-memory token bucket.
 *
 * <p>Starts full (capacity tokens). Each call to {@link #tryConsume} refills
 * based on elapsed wall-clock time, then consumes one token if available.
 */
final class TokenBucket {

    private final double capacity;
    private final double refillPerSec;
    private double tokens;
    private long lastNanos;

    TokenBucket(double capacity, double refillPerSec) {
        this.capacity = capacity;
        this.refillPerSec = refillPerSec;
        this.tokens = capacity;
        this.lastNanos = System.nanoTime();
    }

    synchronized boolean tryConsume() {
        long now = System.nanoTime();
        double elapsed = (now - lastNanos) / 1_000_000_000.0;
        tokens = Math.min(capacity, tokens + elapsed * refillPerSec);
        lastNanos = now;
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }
}
