package com.erikromson.datawallet.crypto;

public final class Fingerprint {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Fingerprint() {}

    /// Renders a public key fingerprint per crypto-formats.md §8.
    public static String render(byte[] publicKey) {
        byte[] hash = Sha256.hash(publicKey);
        byte[] truncated = new byte[10];
        System.arraycopy(hash, 0, truncated, 0, 10);
        String base32 = base32Encode(truncated);
        return base32.substring(0, 4) + "-"
                + base32.substring(4, 8) + "-"
                + base32.substring(8, 12) + "-"
                + base32.substring(12, 16);
    }

    static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(BASE32_ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0) {
            sb.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }
}
