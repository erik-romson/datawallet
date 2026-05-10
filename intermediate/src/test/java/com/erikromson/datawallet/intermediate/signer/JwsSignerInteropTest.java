package com.erikromson.datawallet.intermediate.signer;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts {@link JwsSigner} produces the wire shape the server-side
 * {@code BearerJwtVerifier} requires. Verification is done with raw
 * libsodium here because the intermediate cannot depend on the server
 * (deployable independence per CLAUDE.md). The matching contract test
 * runs on the server side: {@code JwsInteropIT} mirrors this minting
 * recipe inline and feeds the result into the production verifier.
 */
class JwsSignerInteropTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");
    private static final Instant NOW = Instant.parse("2026-01-15T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final LazySodiumJava LAZY = new LazySodiumJava(new SodiumJava());

    @Test
    void mintedJwsIsVerifiableByServerSideBearerJwtVerifier() throws Exception {
        SoftSigner signer = new SoftSigner(SEED);
        JwsSigner jwsSigner = new JwsSigner(signer, FIXED_CLOCK, "urn:datawallet:server");

        UUID installUuid = UUID.fromString("01941f29-7c00-7050-9050-505050505050");
        String jkt = "some-thumbprint";

        String jwt = jwsSigner.mint(installUuid, jkt);
        String[] parts = jwt.split("\\.", -1);
        assertThat(parts).hasSize(3);

        byte[] headerBytes = B64URL.decode(parts[0]);
        byte[] payloadBytes = B64URL.decode(parts[1]);
        byte[] signature = B64URL.decode(parts[2]);

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);

        JsonNode header = mapper.readTree(headerBytes);
        assertThat(header.get("alg").asText()).isEqualTo("EdDSA");
        assertThat(header.get("typ").asText()).isEqualTo("JWT");

        JsonNode payload = mapper.readTree(payloadBytes);
        assertThat(payload.get("iss").asText()).isEqualTo("urn:datawallet:issuer:" + installUuid);
        assertThat(payload.get("aud").asText()).isEqualTo("urn:datawallet:server");
        assertThat(payload.get("cnf").get("jkt").asText()).isEqualTo(jkt);

        long exp = payload.get("exp").asLong();
        long iat = payload.get("iat").asLong();
        assertThat(exp - iat).isLessThanOrEqualTo(300);

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        boolean valid = verifyEd25519(signer.publicKey(), signingInput, signature);
        assertThat(valid).isTrue();
    }

    private static boolean verifyEd25519(byte[] publicKey, byte[] message, byte[] signature) {
        return ((SodiumJava) LAZY.getSodium()).crypto_sign_verify_detached(
                signature, message, message.length, publicKey) == 0;
    }
}
