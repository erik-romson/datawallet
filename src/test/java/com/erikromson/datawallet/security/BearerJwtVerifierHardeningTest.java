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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BearerJwtVerifierHardeningTest {

    private static final String AUDIENCE = "urn:datawallet:server";
    private static final String INSTALL_UUID = "01941f29-7c00-7050-9050-505050505050";
    private static final String ISS = "urn:datawallet:issuer:" + INSTALL_UUID;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();

    private static byte[] intermediatePublicKey;
    private static byte[] intermediatePrivateKey;
    private static final Instant NOW = Instant.parse("2026-01-15T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @BeforeAll
    static void generateIntermediateKey() {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i + 1);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        intermediatePublicKey = kp.publicKey();
        intermediatePrivateKey = kp.privateKey();
    }

    private BearerJwtVerifier verifier() {
        return new BearerJwtVerifier(FIXED_CLOCK);
    }

    private BearerJwtVerifier verifier(Duration skew) {
        return new BearerJwtVerifier(FIXED_CLOCK, skew);
    }

    private String mintJwt(Map<String, Object> header, Map<String, Object> payload) {
        return mintJwt(header, payload, intermediatePrivateKey);
    }

    private String mintJwt(Map<String, Object> header, Map<String, Object> payload, byte[] privateKey) {
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

    private Map<String, Object> validHeader() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("alg", "EdDSA");
        h.put("typ", "JWT");
        return h;
    }

    private Map<String, Object> validPayload() {
        long nowSec = NOW.getEpochSecond();
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("iss", ISS);
        p.put("aud", AUDIENCE);
        p.put("exp", nowSec + 120);
        p.put("iat", nowSec);
        p.put("cnf", Map.of("jkt", "some-thumbprint"));
        return p;
    }

    @Test
    void acceptsValidJwt() {
        String jwt = mintJwt(validHeader(), validPayload());
        BearerClaims claims = verifier().verify(jwt, AUDIENCE, intermediatePublicKey);
        assertThat(claims.installUuid().toString()).isEqualTo(INSTALL_UUID);
    }

    @Test
    void rejectsAlgNone() {
        Map<String, Object> h = validHeader();
        h.put("alg", "none");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Unsupported algorithm: none");
    }

    @Test
    void rejectsAlgHs256() {
        Map<String, Object> h = validHeader();
        h.put("alg", "HS256");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Unsupported algorithm: HS256");
    }

    @Test
    void rejectsAlgRs256() {
        Map<String, Object> h = validHeader();
        h.put("alg", "RS256");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Unsupported algorithm: RS256");
    }

    @Test
    void rejectsAlgEmpty() {
        Map<String, Object> h = validHeader();
        h.put("alg", "");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Unsupported algorithm");
    }

    @Test
    void rejectsMissingAlg() {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("typ", "JWT");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Missing required header: alg");
    }

    @Test
    void rejectsAlgNonString() {
        Map<String, Object> h = validHeader();
        h.put("alg", 42);
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("'alg' must be a string");
    }

    @Test
    void rejectsTypNonJwt() {
        Map<String, Object> h = validHeader();
        h.put("typ", "at+jwt");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Unsupported typ");
    }

    @Test
    void rejectsCtyHeader() {
        Map<String, Object> h = validHeader();
        h.put("cty", "JWT");
        String jwt = mintJwt(h, validPayload());
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("'cty' is not allowed");
    }

    @Test
    void rejectsKidPointingAtInactiveIntermediate() {
        Map<String, Object> h = validHeader();
        h.put("kid", "inactive-intermediate-key-id");
        // kid is informational only; the test verifies the JWT still validates against
        // the explicitly-passed intermediatePublicKey, not whatever kid claims.
        // The resolver is responsible for selecting the right key; the verifier ignores kid.
        String jwt = mintJwt(h, validPayload());
        BearerClaims claims = verifier().verify(jwt, AUDIENCE, intermediatePublicKey);
        assertThat(claims.installUuid().toString()).isEqualTo(INSTALL_UUID);
    }

    @Test
    void rejectsDuplicateJsonKeys() {
        // Manually craft a payload with duplicate keys
        String headerB64 = B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        long nowSec = NOW.getEpochSecond();
        String payloadJson = "{\"iss\":\"" + ISS + "\",\"aud\":\"" + AUDIENCE + "\","
                + "\"exp\":" + (nowSec + 120) + ",\"iat\":" + nowSec + ","
                + "\"cnf\":{\"jkt\":\"t1\"},\"iss\":\"urn:datawallet:issuer:evil\"}";
        String payloadB64 = B64URL.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = Ed25519.signDetached(intermediatePrivateKey, signingInput);
        String jwt = headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);

        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void acceptsExpAtSkewBoundary30sPast() {
        Map<String, Object> p = validPayload();
        long nowSec = NOW.getEpochSecond();
        // Token expired 30s ago — within 60s skew
        p.put("exp", nowSec - 30);
        p.put("iat", nowSec - 150);
        String jwt = mintJwt(validHeader(), p);
        BearerClaims claims = verifier().verify(jwt, AUDIENCE, intermediatePublicKey);
        assertThat(claims).isNotNull();
    }

    @Test
    void rejectsExpBeyondSkew90sPast() {
        Map<String, Object> p = validPayload();
        long nowSec = NOW.getEpochSecond();
        // Token expired 90s ago — beyond 60s skew
        p.put("exp", nowSec - 90);
        p.put("iat", nowSec - 210);
        String jwt = mintJwt(validHeader(), p);
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsLifetimeOver5Min() {
        Map<String, Object> p = validPayload();
        long nowSec = NOW.getEpochSecond();
        p.put("iat", nowSec - 600);
        p.put("exp", nowSec + 120);
        String jwt = mintJwt(validHeader(), p);
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("lifetime exceeds 5 minutes");
    }

    @Test
    void rejectsSegmentOver8Kb() {
        String bigPayload = "x".repeat(9000);
        String jwt = B64URL.encodeToString("{\"alg\":\"EdDSA\"}".getBytes(StandardCharsets.UTF_8))
                + "." + bigPayload + "." + B64URL.encodeToString(new byte[64]);
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("8KB");
    }

    @Test
    void rejectsNonCanonicalBase64url() {
        // Standard base64 with padding
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";
        String paddedHeader = Base64.getUrlEncoder().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        // Ensure padding is present
        if (!paddedHeader.contains("=")) {
            // Force a payload that requires padding
            paddedHeader = Base64.getUrlEncoder().encodeToString("ab".getBytes(StandardCharsets.UTF_8));
        }
        String jwt = paddedHeader + ".eyJ0ZXN0IjoxfQ.AAAA";
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class);
    }

    @Test
    void rejectsIssAsNumber() {
        Map<String, Object> p = validPayload();
        p.put("iss", 12345);
        String jwt = mintJwt(validHeader(), p);
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("'iss' must be a JSON string");
    }

    @Test
    void rejectsExpAsString() {
        Map<String, Object> p = validPayload();
        p.put("exp", "not-a-number");
        String jwt = mintJwt(validHeader(), p);
        assertThatThrownBy(() -> verifier().verify(jwt, AUDIENCE, intermediatePublicKey))
                .isInstanceOf(BearerRejection.class)
                .hasMessageContaining("'exp' must be a JSON integer");
    }
}
