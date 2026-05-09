package com.erikromson.datawallet.intermediate.token;

import com.erikromson.datawallet.intermediate.attestation.Attestation;
import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import com.erikromson.datawallet.intermediate.signer.JwsSigner;
import com.erikromson.datawallet.intermediate.signer.SoftSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.sun.jna.Pointer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TokenControllerTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");
    private static final byte[] INSTALL_SEED = HexFormat.of().parseHex(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final LazySodiumJava LAZY = new LazySodiumJava(new SodiumJava());

    private SoftSigner intermediateSigner;
    private IntermediateCborMapper cbor;
    private SimpleMeterRegistry meterRegistry;
    private byte[] installPublicKey;
    private byte[] installPrivateKey;
    private UUID installUuid;

    @BeforeEach
    void setUp() {
        intermediateSigner = new SoftSigner(SEED);
        cbor = new IntermediateCborMapper();
        meterRegistry = new SimpleMeterRegistry();

        byte[] pk = new byte[32];
        byte[] sk = new byte[64];
        ((SodiumJava) LAZY.getSodium()).crypto_sign_seed_keypair(pk, sk, INSTALL_SEED);
        installPublicKey = pk;
        installPrivateKey = sk;
        installUuid = UUID.randomUUID();
    }

    @Test
    void mintsBearerOnHappyPath() {
        TokenController controller = buildController(new StubOkAttestation(), new EmptyDenyList());

        byte[] record = buildSignedRecord("active");
        byte[] popSig = signPop(installPrivateKey);

        ResponseEntity<?> response = controller.mintToken(new TokenController.TokenRequest(
                B64URL.encodeToString(record),
                B64URL.encodeToString(popSig),
                "token"
        ));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsKey("bearer");
        String bearer = (String) body.get("bearer");
        assertThat(bearer.split("\\.")).hasSize(3);
    }

    @Test
    void rejectsPopSignatureMismatch() {
        TokenController controller = buildController(new StubOkAttestation(), new EmptyDenyList());

        byte[] record = buildSignedRecord("active");
        byte[] wrongSig = new byte[64];

        ResponseEntity<?> response = controller.mintToken(new TokenController.TokenRequest(
                B64URL.encodeToString(record),
                B64URL.encodeToString(wrongSig),
                "token"
        ));

        assertThat(response.getStatusCode().value()).isEqualTo(403);
    }

    @Test
    void rejectsRevokedInstall() {
        byte[] keyId = DirectoryRecordSigner.computeKeyId(installPublicKey);
        RevocationDenyList denyList = new PopulatedDenyList(installUuid, keyId);

        TokenController controller = buildController(new StubOkAttestation(), denyList);

        byte[] record = buildSignedRecord("active");
        byte[] popSig = signPop(installPrivateKey);

        ResponseEntity<?> response = controller.mintToken(new TokenController.TokenRequest(
                B64URL.encodeToString(record),
                B64URL.encodeToString(popSig),
                "token"
        ));

        assertThat(response.getStatusCode().value()).isEqualTo(403);
    }

    @Test
    void rejectsWhenAttestationFails() {
        TokenController controller = buildController(new RejectingAttestation(), new EmptyDenyList());

        byte[] record = buildSignedRecord("active");
        byte[] popSig = signPop(installPrivateKey);

        ResponseEntity<?> response = controller.mintToken(new TokenController.TokenRequest(
                B64URL.encodeToString(record),
                B64URL.encodeToString(popSig),
                "token"
        ));

        assertThat(response.getStatusCode().value()).isEqualTo(403);
    }

    private TokenController buildController(Attestation attestation, RevocationDenyList denyList) {
        JwsSigner jwsSigner = new JwsSigner(intermediateSigner, FIXED_CLOCK, "urn:datawallet:server");
        return new TokenController(jwsSigner, intermediateSigner, attestation, denyList, cbor, meterRegistry);
    }

    private byte[] buildSignedRecord(String status) {
        DirectoryRecordSigner recordSigner = new DirectoryRecordSigner(intermediateSigner, cbor, FIXED_CLOCK);
        byte[] keyId = DirectoryRecordSigner.computeKeyId(installPublicKey);
        return recordSigner.signIssuerRecord(installUuid, installPublicKey, keyId, status);
    }

    private byte[] signPop(byte[] privateKey) {
        byte[] message = "datawallet-token-pop".getBytes();
        byte[] sig = new byte[64];
        ((SodiumJava) LAZY.getSodium()).crypto_sign_detached(sig, Pointer.NULL, message, message.length, privateKey);
        return sig;
    }

    private static class StubOkAttestation implements Attestation {
        @Override
        public Result verify(String token, UUID installUuid) { return Result.ok(); }
    }

    private static class RejectingAttestation implements Attestation {
        @Override
        public Result verify(String token, UUID installUuid) { return Result.reject("test_rejected"); }
    }

    private static class EmptyDenyList extends RevocationDenyList {
        EmptyDenyList() { super(null, new SimpleMeterRegistry(), 600); }

        @Override protected void startupRebuild() {}
        @Override public boolean isRevoked(UUID installUuid, byte[] keyId) { return false; }
        @Override public int size() { return 0; }
        @Override public long ageSeconds() { return 0; }
    }

    private static class PopulatedDenyList extends RevocationDenyList {
        private final UUID revokedUuid;
        private final byte[] revokedKeyId;

        PopulatedDenyList(UUID revokedUuid, byte[] revokedKeyId) {
            super(null, new SimpleMeterRegistry(), 600);
            this.revokedUuid = revokedUuid;
            this.revokedKeyId = revokedKeyId;
        }

        @Override protected void startupRebuild() {}

        @Override
        public boolean isRevoked(UUID installUuid, byte[] keyId) {
            return installUuid.equals(revokedUuid) && java.util.Arrays.equals(keyId, revokedKeyId);
        }

        @Override public int size() { return 1; }
        @Override public long ageSeconds() { return 0; }
    }
}
