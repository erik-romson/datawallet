package com.erikromson.datawallet.api.shared;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public record Cursor(Instant createdAt, UUID entryId) {

    private static final int BYTE_LEN = 24;
    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();

    public static String encode(Instant createdAt, UUID entryId) {
        ByteBuffer buf = ByteBuffer.allocate(BYTE_LEN);
        buf.putLong(createdAt.toEpochMilli());
        buf.putLong(entryId.getMostSignificantBits());
        buf.putLong(entryId.getLeastSignificantBits());
        return ENC.encodeToString(buf.array());
    }

    public static Cursor decode(String encoded) {
        byte[] bytes;
        try {
            bytes = DEC.decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new BadCursor();
        }
        if (bytes.length != BYTE_LEN) {
            throw new BadCursor();
        }
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        long epochMs = buf.getLong();
        long msb = buf.getLong();
        long lsb = buf.getLong();
        return new Cursor(Instant.ofEpochMilli(epochMs), new UUID(msb, lsb));
    }

    public static class BadCursor extends RuntimeException {
        public BadCursor() {
            super("Invalid cursor");
        }
    }
}
