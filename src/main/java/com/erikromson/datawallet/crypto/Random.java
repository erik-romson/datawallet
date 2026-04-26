package com.erikromson.datawallet.crypto;

public final class Random {

    private Random() {}

    public static byte[] bytes(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("n must be non-negative");
        }
        byte[] buf = new byte[n];
        CryptoProvider.sodium().randombytes_buf(buf, n);
        return buf;
    }
}
