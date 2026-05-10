package com.erikromson.datawallet.security;

import com.erikromson.datawallet.crypto.Ed25519;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-stack contract test. Mirrors `intermediate`'s `JwsSigner.mint(...)`
 * recipe inline (header keys + payload keys + canonical-JSON ordering +
 * base64url-no-padding + EdDSA detached signature) and verifies the result
 * via the production `BearerJwtVerifier`. If `JwsSigner` changes its wire
 * shape and breaks `BearerJwtVerifier`, the divergence shows up here.
 *
 * Intermediate cannot depend on server (deployable independence per
 * CLAUDE.md), so this test re-encodes the recipe rather than calling
 * `JwsSigner` directly. The intermediate-side `JwsSignerInteropTest`
 * asserts `JwsSigner` produces this exact recipe; the two together pin
 * the contract from both sides.
 */
class JwsInteropIT {

    private static final String AUDIENCE = "urn:datawallet:server";
    private static final String INSTALL_UUID = "01941f29-7c00-7050-9050-505050505050";
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-01-15T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(5);

    private static byte[] intermediatePublicKey;
    private static byte[] intermediatePrivateKey;

    @BeforeAll
    static void seedIntermediateKey() {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i + 1);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        intermediatePublicKey = kp.publicKey();
        intermediatePrivateKey = kp.privateKey();
    }

    @Test
    void jwsSignerWireFormatIsAcceptedByBearerJwtVerifier() {
        UUID installUuid = UUID.fromString(INSTALL_UUID);
        String jkt = "some-thumbprint";
        String jwt = mintLikeJwsSigner(installUuid, jkt);

        BearerJwtVerifier verifier = new BearerJwtVerifier(FIXED_CLOCK);
        BearerClaims claims = verifier.verify(jwt, AUDIENCE, intermediatePublicKey);

        assertThat(claims.installUuid()).isEqualTo(installUuid);
        assertThat(claims.jktB64()).isEqualTo(jkt);
        assertThat(claims.expMs()).isEqualTo((NOW.getEpochSecond() + TOKEN_LIFETIME.toSeconds()) * 1000);
    }

    @Test
    void verifierRejectsTokenSignedByDifferentKey() {
        byte[] otherSeed = new byte[32];
        for (int i = 0; i < otherSeed.length; i++) otherSeed[i] = (byte) (i + 100);
        Ed25519.KeyPair other = Ed25519.seedKeypair(otherSeed);

        UUID installUuid = UUID.fromString(INSTALL_UUID);
        String jwt = mintLikeJwsSigner(installUuid, "thumb", other.privateKey());

        BearerJwtVerifier verifier = new BearerJwtVerifier(FIXED_CLOCK);
        assertThat(catchesBearerRejection(() -> verifier.verify(jwt, AUDIENCE, intermediatePublicKey)))
                .as("verifier should reject tokens not signed by the trusted intermediate key")
                .isTrue();
    }

    private String mintLikeJwsSigner(UUID installUuid, String jkt) {
        return mintLikeJwsSigner(installUuid, jkt, intermediatePrivateKey);
    }

    private String mintLikeJwsSigner(UUID installUuid, String jkt, byte[] privateKey) {
        long nowSec = FIXED_CLOCK.millis() / 1000;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "JWT");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:datawallet:issuer:" + installUuid);
        payload.put("aud", AUDIENCE);
        payload.put("exp", nowSec + TOKEN_LIFETIME.toSeconds());
        payload.put("iat", nowSec);
        payload.put("cnf", Map.of("jkt", jkt));

        try {
            String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
            String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            byte[] signature = Ed25519.signDetached(privateKey, signingInput);
            return headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean catchesBearerRejection(Runnable r) {
        try {
            r.run();
            return false;
        } catch (BearerRejection e) {
            return true;
        }
    }
}
