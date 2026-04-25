package com.wilhelmsen.cbslink.plugin.datawallet.directory;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class DirectoryRecordCodec {

    private final CanonicalCborMapper cbor = new CanonicalCborMapper();

    public byte[] encode(DirectoryRecord record) {
        Map<String, Object> map = toMap(record);
        List<Map<String, Object>> sigs = new ArrayList<>();
        for (RootSignature rs : record.rootSignatures()) {
            Map<String, Object> sigMap = new LinkedHashMap<>();
            sigMap.put("root_key_id", rs.rootKeyId());
            sigMap.put("signature", rs.signature());
            sigs.add(sigMap);
        }
        map.put("root_signatures", sigs);
        return cbor.writeBytes(map);
    }

    @SuppressWarnings("unchecked")
    public DirectoryRecord decode(byte[] bytes) {
        Map<String, Object> map;
        try {
            map = cbor.readValue(bytes, Map.class);
        } catch (Exception e) {
            throw new DirectoryRejection.MalformedCbor("Failed to parse directory record CBOR", e);
        }
        return fromMap(map);
    }

    public byte[] signedBytesOf(DirectoryRecord record) {
        Map<String, Object> map = toMap(record);
        return cbor.writeBytes(map);
    }

    public byte[] signedBytesOf(byte[] recordBytes) {
        Map<String, Object> map;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = cbor.readValue(recordBytes, Map.class);
            map = parsed;
        } catch (Exception e) {
            throw new DirectoryRejection.MalformedCbor("Failed to parse directory record CBOR", e);
        }
        map.remove("root_signatures");
        return cbor.writeBytes(map);
    }

    private Map<String, Object> toMap(DirectoryRecord rec) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", rec.version());
        map.put("record_type", rec.recordType());
        map.put("subject_id", rec.subjectId());
        map.put("key_id", rec.keyId());
        map.put("public_key", rec.publicKey());
        map.put("key_use", rec.keyUse());
        map.put("status", rec.status());
        map.put("valid_from", rec.validFrom());
        map.put("valid_until", rec.validUntil());
        map.put("issued_at", rec.issuedAt());
        return map;
    }

    @SuppressWarnings("unchecked")
    private DirectoryRecord fromMap(Map<String, Object> map) {
        int version = ((Number) map.get("version")).intValue();
        String recordType = (String) map.get("record_type");
        byte[] subjectId = (byte[]) map.get("subject_id");
        byte[] keyId = (byte[]) map.get("key_id");
        byte[] publicKey = (byte[]) map.get("public_key");
        String keyUse = (String) map.get("key_use");
        String status = (String) map.get("status");
        long validFrom = ((Number) map.get("valid_from")).longValue();
        long validUntil = ((Number) map.get("valid_until")).longValue();
        long issuedAt = ((Number) map.get("issued_at")).longValue();

        List<RootSignature> rootSignatures = new ArrayList<>();
        Object rawSigs = map.get("root_signatures");
        if (rawSigs instanceof List<?> sigList) {
            for (Object entry : sigList) {
                Map<String, Object> sigMap = (Map<String, Object>) entry;
                rootSignatures.add(new RootSignature(
                        (byte[]) sigMap.get("root_key_id"),
                        (byte[]) sigMap.get("signature")
                ));
            }
        }

        return new DirectoryRecord(
                version, recordType, subjectId, keyId, publicKey,
                keyUse, status, validFrom, validUntil, issuedAt, rootSignatures
        );
    }

    @SuppressWarnings("unchecked")
    public PinnedRoot decodePinnedRoot(byte[] bytes) {
        Map<String, Object> map;
        try {
            map = cbor.readValue(bytes, Map.class);
        } catch (Exception e) {
            throw new DirectoryRejection.MalformedCbor("Failed to parse pinned root CBOR", e);
        }

        int version = ((Number) map.get("version")).intValue();
        String scheme = (String) map.get("scheme");
        int threshold = ((Number) map.get("threshold")).intValue();

        List<PinnedRoot.RootEntry> roots = new ArrayList<>();
        for (Object entry : (List<?>) map.get("roots")) {
            Map<String, Object> rootMap = (Map<String, Object>) entry;
            roots.add(new PinnedRoot.RootEntry(
                    (byte[]) rootMap.get("root_key_id"),
                    (byte[]) rootMap.get("public_key"),
                    ((Number) rootMap.get("valid_from")).longValue(),
                    ((Number) rootMap.get("valid_until")).longValue()
            ));
        }

        return new PinnedRoot(version, scheme, threshold, roots);
    }
}
