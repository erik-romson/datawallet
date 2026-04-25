package com.wilhelmsen.cbslink.plugin.datawallet.directory;

import java.util.List;

/**
 * Decoded form of a {@code RootUpdate} CBOR record per {@code crypto-formats.md §7}.
 */
public record RootUpdate(
        int version,
        List<byte[]> oldRootKeyIds,
        PinnedRoot newPinnedRoot,
        long issuedAt,
        List<RootSignature> oldRootSignatures
) {}
