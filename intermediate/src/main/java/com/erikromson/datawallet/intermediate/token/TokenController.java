package com.erikromson.datawallet.intermediate.token;

import com.erikromson.datawallet.intermediate.attestation.Attestation;
import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.observability.MetricsConfig;
import com.erikromson.datawallet.intermediate.signer.JwsSigner;
import com.erikromson.datawallet.intermediate.signer.Signer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.sun.jna.Pointer;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@RestController
public class TokenController {

    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final LazySodiumJava LAZY = new LazySodiumJava(new SodiumJava());

    private final JwsSigner jwsSigner;
    private final Signer signer;
    private final Attestation attestation;
    private final RevocationDenyList denyList;
    private final IntermediateCborMapper cbor;
    private final MeterRegistry meterRegistry;

    public TokenController(JwsSigner jwsSigner,
                           Signer signer,
                           Attestation attestation,
                           RevocationDenyList denyList,
                           IntermediateCborMapper cbor,
                           MeterRegistry meterRegistry) {
        this.jwsSigner = jwsSigner;
        this.signer = signer;
        this.attestation = attestation;
        this.denyList = denyList;
        this.cbor = cbor;
        this.meterRegistry = meterRegistry;
    }

    @PostMapping("/token")
    public ResponseEntity<?> mintToken(@RequestBody TokenRequest request) {
        byte[] signedRecordBytes = B64URL.decode(request.signedDirectoryRecord());
        byte[] popSignature = B64URL.decode(request.popSignature());

        Attestation.Result attResult = attestation.verify(request.attestationToken(), null);
        if (!attResult.accepted()) {
            meterRegistry.counter(MetricsConfig.ATTESTATION_RESULTS, "result", "rejected").increment();
            meterRegistry.counter(MetricsConfig.TOKEN_RESULTS, "result", "attestation_rejected").increment();
            return ResponseEntity.status(403).body(Map.of(
                    "error", "attestation_failed",
                    "rejection_code", attResult.rejectionCode()
            ));
        }
        meterRegistry.counter(MetricsConfig.ATTESTATION_RESULTS, "result", "ok").increment();

        @SuppressWarnings("unchecked")
        Map<String, Object> recordMap = cbor.readValue(signedRecordBytes, Map.class);

        byte[] parentKeyId = (byte[]) recordMap.get("parent_key_id");
        if (parentKeyId == null || !Arrays.equals(parentKeyId, signer.keyId())) {
            meterRegistry.counter(MetricsConfig.TOKEN_RESULTS, "result", "record_invalid").increment();
            return ResponseEntity.status(403).body(Map.of("error", "record_not_signed_by_this_intermediate"));
        }

        String status = (String) recordMap.get("status");
        if (!"active".equals(status)) {
            meterRegistry.counter(MetricsConfig.TOKEN_RESULTS, "result", "record_invalid").increment();
            return ResponseEntity.status(403).body(Map.of("error", "record_not_active"));
        }

        byte[] publicKey = (byte[]) recordMap.get("public_key");
        byte[] subjectIdBytes = (byte[]) recordMap.get("subject_id");
        byte[] keyId = (byte[]) recordMap.get("key_id");
        UUID installUuid = bytesToUuid(subjectIdBytes);

        try {
            if (denyList.isRevoked(installUuid, keyId)) {
                meterRegistry.counter(MetricsConfig.TOKEN_RESULTS, "result", "revoked").increment();
                return ResponseEntity.status(403).body(Map.of("error", "revoked"));
            }
        } catch (RevocationDenyList.DenyListStaleException e) {
            return ResponseEntity.status(503).body(Map.of("error", "denylist_stale"));
        }

        byte[] popMessage = "datawallet-token-pop".getBytes();
        if (!verifyEd25519(publicKey, popMessage, popSignature)) {
            meterRegistry.counter(MetricsConfig.TOKEN_RESULTS, "result", "pop_invalid").increment();
            return ResponseEntity.status(403).body(Map.of("error", "pop_invalid"));
        }

        String jkt = JwsSigner.computeJwkThumbprint(publicKey);
        String bearer = jwsSigner.mint(installUuid, jkt);

        meterRegistry.counter(MetricsConfig.TOKEN_RESULTS, "result", "minted").increment();
        return ResponseEntity.ok(Map.of("bearer", bearer));
    }

    private static boolean verifyEd25519(byte[] publicKey, byte[] message, byte[] signature) {
        int result = ((SodiumJava) LAZY.getSodium()).crypto_sign_verify_detached(
                signature, message, message.length, publicKey
        );
        return result == 0;
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }

    public record TokenRequest(
            @JsonProperty("signed_directory_record") String signedDirectoryRecord,
            @JsonProperty("pop_signature") String popSignature,
            @JsonProperty("attestation_token") String attestationToken
    ) {}
}
