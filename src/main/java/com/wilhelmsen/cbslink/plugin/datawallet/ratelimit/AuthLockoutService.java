package com.wilhelmsen.cbslink.plugin.datawallet.ratelimit;

import com.wilhelmsen.cbslink.plugin.datawallet.domain.AuthLockoutEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.AuthLockoutRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Progressive lockout: after {@value #MAX_FAILURES} consecutive {@code auth_invalid_signature}
 * events for the same {@code verifier_id}, the account is locked for {@value #LOCKOUT_MINUTES}
 * minutes. A successful verify resets the counter.
 *
 * <p>Write operations use {@code REQUIRES_NEW} so they commit even if the calling
 * {@code verify} transaction later rolls back.
 */
@Service
public class AuthLockoutService {

    static final int MAX_FAILURES = 10;
    static final long LOCKOUT_MINUTES = 15;

    private final AuthLockoutRepository authLockoutRepository;
    private final Clock clock;

    public AuthLockoutService(AuthLockoutRepository authLockoutRepository, Clock clock) {
        this.authLockoutRepository = authLockoutRepository;
        this.clock = clock;
    }

    /** Throws {@link AuthLocked} if the verifier is currently locked. */
    @Transactional(readOnly = true)
    public void checkNotLocked(UUID verifierId) {
        authLockoutRepository.findById(verifierId).ifPresent(lockout -> {
            Instant now = Instant.now(clock);
            if (lockout.getLockedUntil() != null && now.isBefore(lockout.getLockedUntil())) {
                long retryAfterSec = Math.max(1L, Duration.between(now, lockout.getLockedUntil()).getSeconds());
                throw new AuthLocked(retryAfterSec);
            }
        });
    }

    /** Increments the failure counter; locks for {@value #LOCKOUT_MINUTES} min at {@value #MAX_FAILURES}. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(UUID verifierId) {
        AuthLockoutEntity lockout = authLockoutRepository.findByVerifierIdForUpdate(verifierId)
                .orElseGet(() -> new AuthLockoutEntity(verifierId));

        int failures = lockout.getConsecutiveFailures() + 1;
        lockout.setConsecutiveFailures(failures);
        lockout.setUpdatedAt(Instant.now(clock));

        if (failures >= MAX_FAILURES) {
            lockout.setLockedUntil(Instant.now(clock).plus(LOCKOUT_MINUTES, ChronoUnit.MINUTES));
        }

        authLockoutRepository.save(lockout);
    }

    /** Resets the failure counter and clears any lock on successful verify. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccess(UUID verifierId) {
        authLockoutRepository.findByVerifierIdForUpdate(verifierId).ifPresent(lockout -> {
            if (lockout.getConsecutiveFailures() > 0 || lockout.getLockedUntil() != null) {
                lockout.setConsecutiveFailures(0);
                lockout.setLockedUntil(null);
                lockout.setUpdatedAt(Instant.now(clock));
                authLockoutRepository.save(lockout);
            }
        });
    }

    public static class AuthLocked extends RuntimeException {
        private final long retryAfterSec;

        public AuthLocked(long retryAfterSec) {
            super("Account temporarily locked due to repeated failed attempts");
            this.retryAfterSec = retryAfterSec;
        }

        public long getRetryAfterSec() { return retryAfterSec; }
    }
}
