package com.erikromson.datawallet.directory;

import java.util.List;

public record PinnedRoot(
        int version,
        String scheme,
        int threshold,
        List<RootEntry> roots
) {

    public record RootEntry(byte[] rootKeyId, byte[] publicKey, long validFrom, long validUntil) {}
}
