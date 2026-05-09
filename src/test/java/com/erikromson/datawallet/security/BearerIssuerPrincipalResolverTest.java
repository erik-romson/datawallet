package com.erikromson.datawallet.security;

import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.RootSignature;
import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BearerIssuerPrincipalResolverTest {

    private static final String AUDIENCE = "urn:datawallet:server";
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper JSON = new ObjectMapper();

    private byte[] intermediatePublicKey;
    private byte[] intermediatePrivateKey;
    private byte[] installPublicKey;
    private UUID installUuid;
    private String installJkt;

    private DirectoryRecordRepository repository;
    private DirectoryRecordCodec codec;
    private BearerIssuerPrincipalResolver resolver;

    @BeforeEach
    void setUp() {
        byte[] intSeed = new byte[32];
        for (int i = 0; i < 32; i++) intSeed[i] = (byte) (i + 1);
        Ed25519.KeyPair intKp = Ed25519.seedKeypair(intSeed);
        intermediatePublicKey = intKp.publicKey();
        intermediatePrivateKey = intKp.privateKey();

        byte[] installSeed = new byte[32];
        for (int i = 0; i < 32; i++) installSeed[i] = (byte) (i + 50);
        Ed25519.KeyPair installKp = Ed25519.seedKeypair(installSeed);
        installPublicKey = installKp.publicKey();
        installUuid = UUID.fromString("01941f29-7c00-7050-9050-505050505050");
        installJkt = BearerIssuerPrincipalResolver.computeJwkThumbprint(installPublicKey);

        repository = mock(DirectoryRecordRepository.class);
        codec = new DirectoryRecordCodec();

        BearerJwtVerifier verifier = new BearerJwtVerifier(Clock.systemUTC());
        resolver = new BearerIssuerPrincipalResolver(repository, codec, verifier, AUDIENCE);

        setupDirectoryRecords();
    }

    private void setupDirectoryRecords() {
        long nowMs = System.currentTimeMillis();

        DirectoryRecord intRecord = new DirectoryRecord(
                1, "intermediate", new byte[16], new byte[16],
                intermediatePublicKey, "sign", "active",
                nowMs - 86400_000, nowMs + 86400_000, nowMs - 86400_000,
                List.of(new RootSignature(new byte[16], new byte[64])),
                null, null
        );
        byte[] intRecordBytes = codec.encode(intRecord);
        DirectoryRecordEntity intEntity = new DirectoryRecordEntity(
                "intermediate", UUID.randomUUID(), new byte[16],
                "active", Instant.ofEpochMilli(nowMs - 86400_000),
                Instant.ofEpochMilli(nowMs + 86400_000),
                Instant.ofEpochMilli(nowMs - 86400_000),
                new byte[16], null, intRecordBytes
        );

        DirectoryRecord installRecord = new DirectoryRecord(
                1, "issuer", new byte[16], new byte[16],
                installPublicKey, "sign", "active",
                nowMs - 86400_000, nowMs + 86400_000, nowMs - 86400_000,
                Collections.emptyList(), new byte[16], new byte[64]
        );
        byte[] installRecordBytes = codec.encode(installRecord);
        DirectoryRecordEntity installEntity = new DirectoryRecordEntity(
                "issuer", installUuid, new byte[16],
                "active", Instant.ofEpochMilli(nowMs - 86400_000),
                Instant.ofEpochMilli(nowMs + 86400_000),
                Instant.ofEpochMilli(nowMs - 86400_000),
                null, new byte[16], installRecordBytes
        );

        when(repository.findAll()).thenReturn(List.of(intEntity, installEntity));
        when(repository.findActiveBySubjectId(installUuid)).thenReturn(List.of(installEntity));
    }

    private String mintValidJwt() {
        long nowSec = System.currentTimeMillis() / 1000;
        return mintJwt(nowSec, nowSec + 120, AUDIENCE, installUuid, installJkt);
    }

    private String mintJwt(long iat, long exp, String aud, UUID uuid, String jkt) {
        try {
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", "EdDSA");
            header.put("typ", "JWT");

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", "urn:datawallet:issuer:" + uuid);
            payload.put("aud", aud);
            payload.put("exp", exp);
            payload.put("iat", iat);
            payload.put("cnf", Map.of("jkt", jkt));

            String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
            String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            byte[] sig = Ed25519.signDetached(intermediatePrivateKey, signingInput);
            return headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private HttpServletRequest requestWithBearer(String jwt) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);
        return request;
    }

    @Test
    void happyPathReturnsExpectedUuid() {
        Optional<UUID> result = resolver.resolve(requestWithBearer(mintValidJwt()));
        assertThat(result).contains(installUuid);
    }

    @Test
    void expiredJwtRejectsReturnsEmpty() {
        long pastSec = System.currentTimeMillis() / 1000 - 3600;
        String jwt = mintJwt(pastSec - 120, pastSec, AUDIENCE, installUuid, installJkt);
        Optional<UUID> result = resolver.resolve(requestWithBearer(jwt));
        assertThat(result).isEmpty();
    }

    @Test
    void wrongAudienceRejectsReturnsEmpty() {
        long nowSec = System.currentTimeMillis() / 1000;
        String jwt = mintJwt(nowSec, nowSec + 120, "urn:datawallet:wrong", installUuid, installJkt);
        Optional<UUID> result = resolver.resolve(requestWithBearer(jwt));
        assertThat(result).isEmpty();
    }

    @Test
    void wrongIssuerPrefixRejectsReturnsEmpty() {
        try {
            long nowSec = System.currentTimeMillis() / 1000;
            Map<String, Object> header = Map.of("alg", "EdDSA", "typ", "JWT");
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", "urn:wrong:issuer:" + installUuid);
            payload.put("aud", AUDIENCE);
            payload.put("exp", nowSec + 120);
            payload.put("iat", nowSec);
            payload.put("cnf", Map.of("jkt", installJkt));

            String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
            String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            byte[] sig = Ed25519.signDetached(intermediatePrivateKey, signingInput);
            String jwt = headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);

            Optional<UUID> result = resolver.resolve(requestWithBearer(jwt));
            assertThat(result).isEmpty();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void cnfJktMismatchRejectsReturnsEmpty() {
        long nowSec = System.currentTimeMillis() / 1000;
        String jwt = mintJwt(nowSec, nowSec + 120, AUDIENCE, installUuid, "wrong-thumbprint");
        Optional<UUID> result = resolver.resolve(requestWithBearer(jwt));
        assertThat(result).isEmpty();
    }

    @Test
    void intermediateRecordRevokedRejectsReturnsEmpty() {
        long nowMs = System.currentTimeMillis();
        DirectoryRecord revokedInt = new DirectoryRecord(
                1, "intermediate", new byte[16], new byte[16],
                intermediatePublicKey, "sign", "revoked",
                nowMs - 86400_000, nowMs + 86400_000, nowMs - 86400_000,
                List.of(new RootSignature(new byte[16], new byte[64])),
                null, null
        );
        byte[] revokedBytes = codec.encode(revokedInt);
        DirectoryRecordEntity revokedEntity = new DirectoryRecordEntity(
                "intermediate", UUID.randomUUID(), new byte[16],
                "revoked", Instant.ofEpochMilli(nowMs - 86400_000),
                Instant.ofEpochMilli(nowMs + 86400_000),
                Instant.ofEpochMilli(nowMs - 86400_000),
                new byte[16], null, revokedBytes
        );
        when(repository.findAll()).thenReturn(List.of(revokedEntity));

        Optional<UUID> result = resolver.resolve(requestWithBearer(mintValidJwt()));
        assertThat(result).isEmpty();
    }

    @Test
    void jwtSignedByDifferentIntermediateRejectsReturnsEmpty() {
        byte[] otherSeed = new byte[32];
        for (int i = 0; i < 32; i++) otherSeed[i] = (byte) (i + 100);
        Ed25519.KeyPair otherKp = Ed25519.seedKeypair(otherSeed);

        try {
            long nowSec = System.currentTimeMillis() / 1000;
            Map<String, Object> header = Map.of("alg", "EdDSA", "typ", "JWT");
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", "urn:datawallet:issuer:" + installUuid);
            payload.put("aud", AUDIENCE);
            payload.put("exp", nowSec + 120);
            payload.put("iat", nowSec);
            payload.put("cnf", Map.of("jkt", installJkt));

            String headerB64 = B64URL.encodeToString(JSON.writeValueAsBytes(header));
            String payloadB64 = B64URL.encodeToString(JSON.writeValueAsBytes(payload));
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
            byte[] sig = Ed25519.signDetached(otherKp.privateKey(), signingInput);
            String jwt = headerB64 + "." + payloadB64 + "." + B64URL.encodeToString(sig);

            Optional<UUID> result = resolver.resolve(requestWithBearer(jwt));
            assertThat(result).isEmpty();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void missingAuthorizationHeaderReturnsEmpty() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(null);
        Optional<UUID> result = resolver.resolve(request);
        assertThat(result).isEmpty();
    }

    @Test
    void nonBearerAuthorizationHeaderReturnsEmpty() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");
        Optional<UUID> result = resolver.resolve(request);
        assertThat(result).isEmpty();
    }
}
