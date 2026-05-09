package com.erikromson.datawallet.intermediate.signer;

import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;

import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class DirectoryRecordSigner {

    private static final Duration DEFAULT_VALIDITY = Duration.ofDays(365);

    private final Signer signer;
    private final IntermediateCborMapper cbor;
    private final Clock clock;

    public DirectoryRecordSigner(Signer signer, IntermediateCborMapper cbor, Clock clock) {
        this.signer = signer;
        this.cbor = cbor;
        this.clock = clock;
    }

    public byte[] signIssuerRecord(UUID installUuid, byte[] publicKey, byte[] keyId, String status) {
        long nowMs = clock.millis();
        long validFrom = nowMs;
        long validUntil = nowMs + DEFAULT_VALIDITY.toMillis();

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", 1);
        map.put("record_type", "issuer");
        map.put("subject_id", uuidToBytes(installUuid));
        map.put("key_id", keyId);
        map.put("public_key", publicKey);
        map.put("key_use", "sign");
        map.put("status", status);
        map.put("valid_from", validFrom);
        map.put("valid_until", validUntil);
        map.put("issued_at", nowMs);
        map.put("parent_key_id", signer.keyId());

        byte[] signedBytes = cbor.writeBytes(map);
        byte[] signature = signer.sign(signedBytes);
        map.put("parent_signature", signature);

        return cbor.writeBytes(map);
    }

    public byte[] signRevokedRecord(UUID installUuid, byte[] publicKey, byte[] keyId,
                                     long validFrom, long validUntil) {
        long nowMs = clock.millis();

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", 1);
        map.put("record_type", "issuer");
        map.put("subject_id", uuidToBytes(installUuid));
        map.put("key_id", keyId);
        map.put("public_key", publicKey);
        map.put("key_use", "sign");
        map.put("status", "revoked");
        map.put("valid_from", validFrom);
        map.put("valid_until", validUntil);
        map.put("issued_at", nowMs);
        map.put("parent_key_id", signer.keyId());

        byte[] signedBytes = cbor.writeBytes(map);
        byte[] signature = signer.sign(signedBytes);
        map.put("parent_signature", signature);

        return cbor.writeBytes(map);
    }

    public static byte[] computeKeyId(byte[] publicKey) {
        byte[] hash = sha256(publicKey);
        return Arrays.copyOf(hash, 16);
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

    private static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return buf.array();
    }
}
