package com.erikromson.datawallet.directory;

import com.erikromson.datawallet.crypto.Ed25519;

import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Set;

public final class DirectoryRecordVerifier {

    private static final Duration MAX_AGE = Duration.ofDays(7);
    private static final int MAX_DEPTH = 2;
    private static final Set<String> VALID_RECORD_TYPES = Set.of("verifier", "issuer", "intermediate");
    private static final Set<String> VALID_KEY_USES = Set.of("enc", "auth", "sign");
    private static final Set<String> VALID_STATUSES = Set.of("active", "superseded", "revoked");

    /** Resolves a parent intermediate record by its key_id. Returns the raw signed CBOR bytes. */
    @FunctionalInterface
    public interface ParentLookup {
        byte[] findParentBytes(byte[] parentKeyId);
    }

    private static final ParentLookup NO_PARENT_LOOKUP = parentKeyId -> {
        throw new DirectoryRejection.ParentNotFound(
                "Parent lookup not available for key_id=" + HexFormat.of().formatHex(parentKeyId));
    };

    private final DirectoryRecordCodec codec;
    private final Clock clock;

    public DirectoryRecordVerifier(DirectoryRecordCodec codec, Clock clock) {
        this.codec = codec;
        this.clock = clock;
    }

    public DirectoryRecordVerifier(DirectoryRecordCodec codec) {
        this(codec, Clock.systemUTC());
    }

    /** Verifies a root-signed record. Fails fast if a parent chain is required. */
    public DirectoryRecord verify(byte[] recordBytes, PinnedRoot pinned) {
        return verify(recordBytes, pinned, NO_PARENT_LOOKUP);
    }

    /** Verifies a record, walking the parent chain using [lookup] when needed. */
    public DirectoryRecord verify(byte[] recordBytes, PinnedRoot pinned, ParentLookup lookup) {
        return verifyAtDepth(recordBytes, pinned, lookup, 1);
    }

    private DirectoryRecord verifyAtDepth(byte[] recordBytes, PinnedRoot pinned,
                                           ParentLookup lookup, int depth) {
        DirectoryRecord record = codec.decode(recordBytes);

        if (record.version() != 1) {
            throw new DirectoryRejection.UnsupportedVersion(record.version());
        }
        if (!VALID_RECORD_TYPES.contains(record.recordType())) {
            throw new DirectoryRejection.InvalidRecordType(record.recordType());
        }
        if (!VALID_KEY_USES.contains(record.keyUse())) {
            throw new DirectoryRejection.InvalidKeyUse(record.keyUse());
        }
        if (!VALID_STATUSES.contains(record.status())) {
            throw new DirectoryRejection.InvalidStatus(record.status());
        }

        long nowMs = clock.millis();
        long ageMs = nowMs - record.issuedAt();
        if (ageMs > MAX_AGE.toMillis()) {
            throw new DirectoryRejection.FreshnessExpired(
                    "Record issued_at=" + record.issuedAt() + " is older than 7 days (age=" + ageMs + "ms)");
        }

        byte[] signedBytes = codec.signedBytesOf(recordBytes);

        if (record.parentKeyId() == null) {
            RootQuorum.verify(signedBytes, record.rootSignatures(), record.issuedAt(), pinned);
        } else {
            verifyParentChain(record, signedBytes, pinned, lookup, depth);
        }

        return record;
    }

    private void verifyParentChain(DirectoryRecord record, byte[] signedBytes,
                                    PinnedRoot pinned, ParentLookup lookup, int depth) {
        if (depth >= MAX_DEPTH) {
            throw new DirectoryRejection.ChainTooDeep(
                    "Chain depth exceeds maximum of " + MAX_DEPTH);
        }

        byte[] parentBytes = lookup.findParentBytes(record.parentKeyId());
        DirectoryRecord parent = codec.decode(parentBytes);

        if (!"intermediate".equals(parent.recordType())) {
            throw new DirectoryRejection.ParentNotIntermediate(
                    "Parent record_type=" + parent.recordType() + " is not 'intermediate'");
        }
        if (!"active".equals(parent.status())) {
            throw new DirectoryRejection.ParentInactive(
                    "Parent status=" + parent.status() + " is not 'active'");
        }
        long nowMs = clock.millis();
        if (nowMs < parent.validFrom() || nowMs >= parent.validUntil()) {
            throw new DirectoryRejection.ParentInactive(
                    "Current time " + nowMs + " is outside parent valid window ["
                            + parent.validFrom() + ", " + parent.validUntil() + ")");
        }

        if (!Ed25519.verifyDetached(parent.publicKey(), signedBytes, record.parentSignature())) {
            throw new DirectoryRejection.ParentSignatureInvalid(
                    "Parent signature invalid for key_id="
                            + HexFormat.of().formatHex(record.parentKeyId()));
        }

        verifyAtDepth(parentBytes, pinned, lookup, depth + 1);
    }
}
