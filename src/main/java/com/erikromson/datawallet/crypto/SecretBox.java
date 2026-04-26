package com.erikromson.datawallet.crypto;

public final class SecretBox {

    static final int MAC_BYTES = 16;

    private SecretBox() {}

    public static byte[] seal(byte[] plaintext, byte[] nonce, byte[] key) {
        byte[] ciphertext = new byte[plaintext.length + MAC_BYTES];
        int result = CryptoProvider.sodium().crypto_secretbox_easy(
                ciphertext, plaintext, plaintext.length, nonce, key
        );
        if (result != 0) {
            throw new CryptoException("crypto_secretbox_easy failed");
        }
        return ciphertext;
    }

    public static byte[] open(byte[] ciphertext, byte[] nonce, byte[] key) {
        byte[] plaintext = new byte[ciphertext.length - MAC_BYTES];
        int result = CryptoProvider.sodium().crypto_secretbox_open_easy(
                plaintext, ciphertext, ciphertext.length, nonce, key
        );
        if (result != 0) {
            throw new CryptoException("crypto_secretbox_open_easy failed");
        }
        return plaintext;
    }
}
