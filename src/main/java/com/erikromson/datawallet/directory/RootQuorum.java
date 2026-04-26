package com.erikromson.datawallet.directory;

import com.erikromson.datawallet.crypto.Ed25519;

import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

public final class RootQuorum {

    private RootQuorum() {}

    public static void verify(byte[] signedBytes, List<RootSignature> sigs, long issuedAtMs, PinnedRoot pinned) {
        Set<String> validKeyIds = new HashSet<>();

        for (RootSignature sig : sigs) {
            PinnedRoot.RootEntry root = findRoot(sig.rootKeyId(), pinned);
            if (root == null) {
                throw new DirectoryRejection.RootKeyNotFound(
                        "Root key not found: " + HexFormat.of().formatHex(sig.rootKeyId()));
            }

            if (issuedAtMs < root.validFrom() || issuedAtMs >= root.validUntil()) {
                throw new DirectoryRejection.RootKeyExpired(
                        "Root key outside valid window at issued_at=" + issuedAtMs);
            }

            if (!Ed25519.verifyDetached(root.publicKey(), signedBytes, sig.signature())) {
                throw new DirectoryRejection.SignatureInvalid(
                        "Signature invalid for root key: " + HexFormat.of().formatHex(sig.rootKeyId()));
            }

            validKeyIds.add(HexFormat.of().formatHex(sig.rootKeyId()));
        }

        if (validKeyIds.size() < pinned.threshold()) {
            throw new DirectoryRejection.QuorumBelowThreshold(validKeyIds.size(), pinned.threshold());
        }
    }

    private static PinnedRoot.RootEntry findRoot(byte[] rootKeyId, PinnedRoot pinned) {
        for (PinnedRoot.RootEntry entry : pinned.roots()) {
            if (Arrays.equals(entry.rootKeyId(), rootKeyId)) {
                return entry;
            }
        }
        return null;
    }
}
