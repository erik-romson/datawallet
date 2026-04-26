package com.erikromson.datawallet.crypto;

import com.sun.jna.Pointer;

public final class Ed25519 {

    static final int PUBLIC_KEY_LEN = 32;
    static final int PRIVATE_KEY_LEN = 64;
    static final int SIGNATURE_LEN = 64;

    private Ed25519() {}

    public record KeyPair(byte[] publicKey, byte[] privateKey) {}

    public static KeyPair seedKeypair(byte[] seed) {
        byte[] publicKey = new byte[PUBLIC_KEY_LEN];
        byte[] privateKey = new byte[PRIVATE_KEY_LEN];
        int result = CryptoProvider.sodium().crypto_sign_seed_keypair(publicKey, privateKey, seed);
        if (result != 0) {
            throw new CryptoException("crypto_sign_seed_keypair failed");
        }
        return new KeyPair(publicKey, privateKey);
    }

    public static byte[] signDetached(byte[] privateKey, byte[] message) {
        byte[] signature = new byte[SIGNATURE_LEN];
        int result = CryptoProvider.sodium().crypto_sign_detached(
                signature, Pointer.NULL, message, message.length, privateKey
        );
        if (result != 0) {
            throw new CryptoException("crypto_sign_detached failed");
        }
        return signature;
    }

    public static boolean verifyDetached(byte[] publicKey, byte[] message, byte[] signature) {
        int result = CryptoProvider.sodium().crypto_sign_verify_detached(
                signature, message, message.length, publicKey
        );
        return result == 0;
    }
}
