package com.wilhelmsen.cbslink.plugin.datawallet.directory;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CBOR codec for {@link RootUpdate} records per {@code crypto-formats.md §7}.
 *
 * <p>Signed bytes: {@code canonical_cbor(RootUpdate without "old_root_signatures")}.
 */
public final class RootUpdateCodec {

    private final CanonicalCborMapper cbor = new CanonicalCborMapper();
    private final DirectoryRecordCodec directoryCodec = new DirectoryRecordCodec();

    @SuppressWarnings("unchecked")
    public RootUpdate decode(byte[] bytes) {
        Map<String, Object> map;
        try {
            map = cbor.readValue(bytes, Map.class);
        } catch (Exception e) {
            throw new DirectoryRejection.MalformedCbor("Failed to parse RootUpdate CBOR", e);
        }

        int version = ((Number) map.get("version")).intValue();

        List<byte[]> oldRootKeyIds = new ArrayList<>();
        for (Object entry : (List<?>) map.get("old_root_key_ids")) {
            oldRootKeyIds.add((byte[]) entry);
        }

        Map<String, Object> pinnedRootMap = (Map<String, Object>) map.get("new_pinned_root");
        PinnedRoot newPinnedRoot = decodePinnedRoot(pinnedRootMap);

        long issuedAt = ((Number) map.get("issued_at")).longValue();

        List<RootSignature> oldRootSignatures = new ArrayList<>();
        for (Object entry : (List<?>) map.get("old_root_signatures")) {
            Map<String, Object> sigMap = (Map<String, Object>) entry;
            oldRootSignatures.add(new RootSignature(
                    (byte[]) sigMap.get("root_key_id"),
                    (byte[]) sigMap.get("signature")
            ));
        }

        return new RootUpdate(version, oldRootKeyIds, newPinnedRoot, issuedAt, oldRootSignatures);
    }

    public byte[] signedBytesOf(byte[] rootUpdateBytes) {
        Map<String, Object> map;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = cbor.readValue(rootUpdateBytes, Map.class);
            map = parsed;
        } catch (Exception e) {
            throw new DirectoryRejection.MalformedCbor("Failed to parse RootUpdate CBOR", e);
        }
        map.remove("old_root_signatures");
        return cbor.writeBytes(map);
    }

    public byte[] encodePinnedRoot(PinnedRoot root) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", root.version());
        map.put("scheme", root.scheme());
        map.put("threshold", root.threshold());
        List<Map<String, Object>> rootsList = new ArrayList<>();
        for (PinnedRoot.RootEntry entry : root.roots()) {
            Map<String, Object> entryMap = new LinkedHashMap<>();
            entryMap.put("root_key_id", entry.rootKeyId());
            entryMap.put("public_key", entry.publicKey());
            entryMap.put("valid_from", entry.validFrom());
            entryMap.put("valid_until", entry.validUntil());
            rootsList.add(entryMap);
        }
        map.put("roots", rootsList);
        return cbor.writeBytes(map);
    }

    @SuppressWarnings("unchecked")
    private PinnedRoot decodePinnedRoot(Map<String, Object> map) {
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
