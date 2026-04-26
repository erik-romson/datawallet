package com.erikromson.datawallet.crypto;

public final class SealedBox {

    static final int SEAL_OVERHEAD = 48;

    private SealedBox() {}

    public static byte[] seal(byte[] plaintext, byte[] recipientPublicKey) {
        byte[] ciphertext = new byte[plaintext.length + SEAL_OVERHEAD];
        int result = CryptoProvider.sodium().crypto_box_seal(
                ciphertext, plaintext, plaintext.length, recipientPublicKey
        );
        if (result != 0) {
            throw new CryptoException("crypto_box_seal failed");
        }
        return ciphertext;
    }

    public static byte[] open(byte[] ciphertext, byte[] publicKey, byte[] secretKey) {
        byte[] plaintext = new byte[ciphertext.length - SEAL_OVERHEAD];
        int result = CryptoProvider.sodium().crypto_box_seal_open(
                plaintext, ciphertext, ciphertext.length, publicKey, secretKey
        );
        if (result != 0) {
            throw new CryptoException("crypto_box_seal_open failed");
        }
        return plaintext;
    }
}
