package com.wilhelmsen.cbslink.plugin.datawallet.crypto;

public final class Sha256 {

    static final int HASH_LEN = 32;

    private Sha256() {}

    public static byte[] hash(byte[] input) {
        byte[] output = new byte[HASH_LEN];
        int result = CryptoProvider.sodium().crypto_hash_sha256(output, input, input.length);
        if (result != 0) {
            throw new CryptoException("crypto_hash_sha256 failed");
        }
        return output;
    }
}
