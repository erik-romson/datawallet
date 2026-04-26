package com.wilhelmsen.cbslink.plugin.datawallet.api.auth;

import com.wilhelmsen.cbslink.plugin.datawallet.audit.AuditService;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Sha256;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.AuthChallengeEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.AuthChallengeRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.SessionEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.SessionRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.VerifierEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.VerifierRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.ratelimit.AuthLockoutService;
import com.wilhelmsen.cbslink.plugin.datawallet.security.SessionPrincipal;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    public static final byte[] AUTH_PREFIX = "datawallet-auth-v1\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int NONCE_LEN = 32;
    private static final int TOKEN_LEN = 32;
    private static final long CHALLENGE_TTL_SECONDS = 60;
    private static final long SESSION_TTL_SECONDS = 3600;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private final VerifierRepository verifierRepository;
    private final AuthChallengeRepository challengeRepository;
    private final SessionRepository sessionRepository;
    private final AuditService auditService;
    private final AuthLockoutService authLockoutService;

    public AuthController(VerifierRepository verifierRepository,
                          AuthChallengeRepository challengeRepository,
                          SessionRepository sessionRepository,
                          AuditService auditService,
                          AuthLockoutService authLockoutService) {
        this.verifierRepository = verifierRepository;
        this.challengeRepository = challengeRepository;
        this.sessionRepository = sessionRepository;
        this.auditService = auditService;
        this.authLockoutService = authLockoutService;
    }

    @PostMapping(value = "/challenge",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> challenge(@Valid @RequestBody AuthChallengeDto dto) {
        verifierRepository.findById(dto.verifierId())
                .orElseThrow(() -> new VerifierNotFound(dto.verifierId()));

        byte[] nonce = Random.bytes(NONCE_LEN);
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(CHALLENGE_TTL_SECONDS);

        var entity = new AuthChallengeEntity(dto.verifierId(), nonce, now, expiresAt);
        challengeRepository.save(entity);

        return ResponseEntity.ok(Map.of(
                "nonce", B64URL.encodeToString(nonce),
                "expires_at", expiresAt.toEpochMilli()
        ));
    }

    @PostMapping(value = "/verify",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ResponseEntity<Map<String, Object>> verify(@Valid @RequestBody AuthVerifyDto dto) {
        // check lockout before doing any DB work — throws AuthLocked (423) if active
        authLockoutService.checkNotLocked(dto.verifierId());

        VerifierEntity verifier = verifierRepository.findById(dto.verifierId())
                .orElseThrow(() -> new VerifierNotFound(dto.verifierId()));

        byte[] nonceBytes = B64URL_DEC.decode(dto.nonce());

        AuthChallengeEntity challenge = challengeRepository.findForUpdate(dto.verifierId(), nonceBytes)
                .orElseThrow(() -> new AuthNonceInvalid("nonce not found"));

        if (challenge.getConsumedAt() != null) {
            throw new AuthNonceConsumed();
        }

        Instant now = Instant.now();
        if (!now.isBefore(challenge.getExpiresAt())) {
            throw new AuthNonceExpired();
        }

        byte[] signatureBytes = B64URL_DEC.decode(dto.signature());
        byte[] signedBytes = buildSignedBytes(nonceBytes);

        boolean valid = Ed25519.verifyDetached(verifier.getAuthPublicKey(), signedBytes, signatureBytes);
        if (!valid) {
            authLockoutService.recordFailure(dto.verifierId());
            throw new AuthInvalidSignature();
        }

        challenge.setConsumedAt(now);

        byte[] token = Random.bytes(TOKEN_LEN);
        byte[] tokenId = Sha256.hash(token);
        Instant sessionExpires = now.plusSeconds(SESSION_TTL_SECONDS);

        var session = new SessionEntity(tokenId, dto.verifierId(), now, sessionExpires);
        sessionRepository.save(session);

        authLockoutService.recordSuccess(dto.verifierId());

        auditService.recordEvent(
                AuditService.EventType.VERIFIER_LOGIN,
                dto.verifierId(), null, Collections.emptyMap()
        );

        return ResponseEntity.ok(Map.of(
                "session_token", B64URL.encodeToString(token),
                "expires_at", sessionExpires.toEpochMilli()
        ));
    }

    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<Void> logout(@AuthenticationPrincipal SessionPrincipal principal) {
        sessionRepository.deleteAllByVerifierIdAndRevokedAtIsNull(principal.getVerifierId());

        auditService.recordEvent(
                AuditService.EventType.VERIFIER_LOGOUT,
                principal.getVerifierId(), null, Collections.emptyMap()
        );

        return ResponseEntity.noContent()
                .header("Clear-Site-Data", "\"cache\", \"storage\"")
                .build();
    }

    public static byte[] buildSignedBytes(byte[] nonce) {
        byte[] result = new byte[AUTH_PREFIX.length + nonce.length];
        System.arraycopy(AUTH_PREFIX, 0, result, 0, AUTH_PREFIX.length);
        System.arraycopy(nonce, 0, result, AUTH_PREFIX.length, nonce.length);
        return result;
    }

    public static class VerifierNotFound extends RuntimeException {
        public VerifierNotFound(java.util.UUID id) {
            super("Verifier not found: " + id);
        }
    }

    public static class AuthNonceConsumed extends RuntimeException {
        public AuthNonceConsumed() { super("Nonce already consumed"); }
    }

    public static class AuthNonceExpired extends RuntimeException {
        public AuthNonceExpired() { super("Nonce expired"); }
    }

    public static class AuthInvalidSignature extends RuntimeException {
        public AuthInvalidSignature() { super("Invalid signature"); }
    }

    public static class AuthNonceInvalid extends RuntimeException {
        public AuthNonceInvalid(String msg) { super(msg); }
    }
}
