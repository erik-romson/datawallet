package com.erikromson.datawallet.crypto;

public final class X25519 {

    static final int PUBLIC_KEY_LEN = 32;
    static final int SECRET_KEY_LEN = 32;

    private X25519() {}

    public record KeyPair(byte[] publicKey, byte[] secretKey) {}

    public static KeyPair seedKeypair(byte[] seed) {
        byte[] publicKey = new byte[PUBLIC_KEY_LEN];
        byte[] secretKey = new byte[SECRET_KEY_LEN];
        int result = CryptoProvider.sodium().crypto_box_seed_keypair(publicKey, secretKey, seed);
        if (result != 0) {
            throw new CryptoException("crypto_box_seed_keypair failed");
        }
        return new KeyPair(publicKey, secretKey);
    }
}
