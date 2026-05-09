package com.erikromson.datawallet.security;

import com.erikromson.datawallet.crypto.Ed25519;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BearerFixtureGenerator {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void generateBearerFixture() throws Exception {
        byte[] intSeed = new byte[32];
        for (int i = 0; i < 32; i++) intSeed[i] = (byte) (i + 1);
        Ed25519.KeyPair intKp = Ed25519.seedKeypair(intSeed);

        byte[] installSeed = new byte[32];
        for (int i = 0; i < 32; i++) installSeed[i] = (byte) (i + 50);
        Ed25519.KeyPair installKp = Ed25519.seedKeypair(installSeed);

        String installJkt = BearerIssuerPrincipalResolver.computeJwkThumbprint(installKp.publicKey());

        long nowSec = Instant.now().getEpochSecond();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "JWT");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:datawallet:issuer:01941f29-7c00-7050-9050-505050505050");
        payload.put("aud", "urn:datawallet:server");
        payload.put("exp", nowSec + 120);
        payload.put("iat", nowSec);
        payload.put("cnf", Map.of("jkt", installJkt));

        String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
        String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
        byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = Ed25519.signDetached(intKp.privateKey(), signingInput);
        String jwt = headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);

        Path fixturesDir = resolveFixturesDir().resolve("bearer");
        Files.createDirectories(fixturesDir);
        Files.writeString(fixturesDir.resolve("test-bearer.jwt"), jwt);
        Files.write(fixturesDir.resolve("intermediate-pubkey.bin"), intKp.publicKey());

        assertThat(jwt.split("\\.")).hasSize(3);
        assertThat(intKp.publicKey()).hasSize(32);
    }

    private static Path resolveFixturesDir() {
        Path dir = Path.of(System.getProperty("user.dir"));
        while (dir != null) {
            Path candidate = dir.resolve("spec/fixtures");
            if (Files.isDirectory(candidate)) return candidate;
            dir = dir.getParent();
        }
        throw new IllegalStateException("spec/fixtures not found");
    }
}
