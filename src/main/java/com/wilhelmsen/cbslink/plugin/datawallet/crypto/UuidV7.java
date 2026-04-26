package com.wilhelmsen.cbslink.plugin.datawallet.crypto;

import java.util.UUID;

public final class UuidV7 {

    static final int RAND_BYTES_LEN = 10;

    private UuidV7() {}

    /// Generates a UUIDv7 from explicit timestamp and random bytes.
    /// `randBytes` must be exactly 10 bytes (rand_a 2 + rand_b 8 per crypto-formats.md §10).
    public static UUID generate(long tsMs, byte[] randBytes) {
        if (randBytes.length != RAND_BYTES_LEN) {
            throw new IllegalArgumentException("randBytes must be " + RAND_BYTES_LEN + " bytes, got " + randBytes.length);
        }

        long msb = 0;
        msb |= (tsMs & 0xFFFF_FFFF_FFFFL) << 16;
        msb |= 0x7000L;
        msb |= (randBytes[0] & 0x0FL) << 8;
        msb |= (randBytes[1] & 0xFFL);

        long lsb = 0;
        lsb |= 0x80L << 56;
        lsb |= (long) (randBytes[2] & 0x3F) << 56;
        lsb |= (long) (randBytes[3] & 0xFF) << 48;
        lsb |= (long) (randBytes[4] & 0xFF) << 40;
        lsb |= (long) (randBytes[5] & 0xFF) << 32;
        lsb |= (long) (randBytes[6] & 0xFF) << 24;
        lsb |= (long) (randBytes[7] & 0xFF) << 16;
        lsb |= (long) (randBytes[8] & 0xFF) << 8;
        lsb |= (long) (randBytes[9] & 0xFF);

        return new UUID(msb, lsb);
    }

    /// Generates a UUIDv7 using the current time and libsodium randomness.
    public static UUID now() {
        long tsMs = System.currentTimeMillis();
        byte[] randBytes = Random.bytes(RAND_BYTES_LEN);
        return generate(tsMs, randBytes);
    }
}
