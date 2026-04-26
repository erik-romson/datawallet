package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class EnvelopeCodec {

    private final CanonicalCborMapper cbor = new CanonicalCborMapper();

    public byte[] encode(SharedEnvelope envelope) {
        Map<String, Object> map = toMap(envelope);
        if (envelope.signature() != null) {
            map.put("signature", envelope.signature());
        }
        return cbor.writeBytes(map);
    }

    @SuppressWarnings("unchecked")
    public SharedEnvelope decode(byte[] bytes) {
        Map<String, Object> map;
        try {
            map = cbor.readValue(bytes, Map.class);
        } catch (Exception e) {
            throw new EnvelopeRejection.MalformedCbor("Failed to parse envelope CBOR", e);
        }
        return fromMap(map);
    }

    public byte[] signedBytesOf(SharedEnvelope envelope) {
        Map<String, Object> map = toMap(envelope);
        return cbor.writeBytes(map);
    }

    private Map<String, Object> toMap(SharedEnvelope env) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", env.version());
        map.put("entry_id", uuidToBytes(env.entryId()));
        map.put("issuer_id", uuidToBytes(env.issuerId()));
        map.put("issuer_label", env.issuerLabel());
        map.put("issuer_signing_key_id", env.issuerSigningKeyId());
        map.put("created_at", env.createdAt());
        map.put("description", env.description());
        map.put("ciphertext_alg", env.ciphertextAlg());
        map.put("ciphertext_nonce", env.ciphertextNonce());
        map.put("ciphertext", env.ciphertext());
        map.put("ciphertext_hash", env.ciphertextHash());

        List<Map<String, Object>> wrappings = new ArrayList<>();
        for (RecipientWrapping rw : env.recipientWrappings()) {
            Map<String, Object> rwMap = new LinkedHashMap<>();
            rwMap.put("verifier_id", uuidToBytes(rw.verifierId()));
            rwMap.put("verifier_key_id", rw.verifierKeyId());
            rwMap.put("wrapped_data_key", rw.wrappedDataKey());
            wrappings.add(rwMap);
        }
        map.put("recipient_wrappings", wrappings);
        return map;
    }

    @SuppressWarnings("unchecked")
    private SharedEnvelope fromMap(Map<String, Object> map) {
        int version = ((Number) map.get("version")).intValue();
        UUID entryId = bytesToUuid((byte[]) map.get("entry_id"));
        UUID issuerId = bytesToUuid((byte[]) map.get("issuer_id"));
        String issuerLabel = (String) map.get("issuer_label");
        byte[] issuerSigningKeyId = (byte[]) map.get("issuer_signing_key_id");
        long createdAt = ((Number) map.get("created_at")).longValue();
        String description = (String) map.get("description");
        String ciphertextAlg = (String) map.get("ciphertext_alg");
        byte[] ciphertextNonce = (byte[]) map.get("ciphertext_nonce");
        byte[] ciphertext = (byte[]) map.get("ciphertext");
        byte[] ciphertextHash = (byte[]) map.get("ciphertext_hash");
        byte[] signature = (byte[]) map.get("signature");

        List<Map<String, Object>> rawWrappings = (List<Map<String, Object>>) map.get("recipient_wrappings");
        List<RecipientWrapping> wrappings = new ArrayList<>();
        for (Map<String, Object> rw : rawWrappings) {
            wrappings.add(new RecipientWrapping(
                    bytesToUuid((byte[]) rw.get("verifier_id")),
                    (byte[]) rw.get("verifier_key_id"),
                    (byte[]) rw.get("wrapped_data_key")
            ));
        }

        return new SharedEnvelope(
                version, entryId, issuerId, issuerLabel, issuerSigningKeyId,
                createdAt, description, ciphertextAlg, ciphertextNonce,
                ciphertext, ciphertextHash, wrappings, signature
        );
    }

    static byte[] uuidToBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return bytes;
    }

    static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }
}
