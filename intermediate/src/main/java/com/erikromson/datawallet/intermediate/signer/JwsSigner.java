package com.erikromson.datawallet.intermediate.signer;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class JwsSigner {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(5);

    private final Signer signer;
    private final Clock clock;
    private final String audience;

    public JwsSigner(Signer signer, Clock clock, String audience) {
        this.signer = signer;
        this.clock = clock;
        this.audience = audience;
    }

    public String mint(UUID installUuid, String jkt) {
        long nowSec = clock.millis() / 1000;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "JWT");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:datawallet:issuer:" + installUuid);
        payload.put("aud", audience);
        payload.put("exp", nowSec + TOKEN_LIFETIME.toSeconds());
        payload.put("iat", nowSec);
        payload.put("cnf", Map.of("jkt", jkt));

        try {
            String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
            String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            byte[] signature = signer.sign(signingInput);
            return headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(signature);
        } catch (Exception e) {
            throw new JwsMintException("Failed to mint JWS", e);
        }
    }

    public static String computeJwkThumbprint(byte[] ed25519PublicKey) {
        String xB64 = B64URL.encodeToString(ed25519PublicKey);
        String jwkJson = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + xB64 + "\"}";
        byte[] hash = sha256(jwkJson.getBytes(StandardCharsets.UTF_8));
        return B64URL.encodeToString(hash);
    }

    private static byte[] sha256(byte[] input) {
        byte[] output = new byte[32];
        com.goterl.lazysodium.SodiumJava sodium =
                (com.goterl.lazysodium.SodiumJava) new com.goterl.lazysodium.LazySodiumJava(
                        new com.goterl.lazysodium.SodiumJava()).getSodium();
        int result = sodium.crypto_hash_sha256(output, input, input.length);
        if (result != 0) {
            throw new IllegalStateException("crypto_hash_sha256 failed");
        }
        return output;
    }

    public static final class JwsMintException extends RuntimeException {
        public JwsMintException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
