package com.erikromson.datawallet.directory;

import java.time.Clock;
import java.time.Duration;
import java.util.Set;

public final class DirectoryRecordVerifier {

    private static final Duration MAX_AGE = Duration.ofDays(7);
    private static final Set<String> VALID_RECORD_TYPES = Set.of("verifier", "issuer");
    private static final Set<String> VALID_KEY_USES = Set.of("enc", "auth", "sign");
    private static final Set<String> VALID_STATUSES = Set.of("active", "superseded", "revoked");

    private final DirectoryRecordCodec codec;
    private final Clock clock;

    public DirectoryRecordVerifier(DirectoryRecordCodec codec, Clock clock) {
        this.codec = codec;
        this.clock = clock;
    }

    public DirectoryRecordVerifier(DirectoryRecordCodec codec) {
        this(codec, Clock.systemUTC());
    }

    public DirectoryRecord verify(byte[] recordBytes, PinnedRoot pinned) {
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
        RootQuorum.verify(signedBytes, record.rootSignatures(), record.issuedAt(), pinned);

        return record;
    }
}
