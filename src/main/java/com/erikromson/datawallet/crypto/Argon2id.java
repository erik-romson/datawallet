package com.erikromson.datawallet.crypto;

import com.sun.jna.NativeLong;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

public final class Argon2id {

    static final int KEK_LEN = 32;
    static final int ALG_ARGON2ID13 = 2;

    private Argon2id() {}

    /// Derives a 32-byte KEK from the given password and salt using Argon2id.
    public static byte[] deriveKek(String password, byte[] salt, long m, long t, int p) {
        if (p != 1) {
            throw new CryptoException("libsodium requires p=1 for Argon2id, got p=" + p);
        }
        String nfc = Normalizer.normalize(password, Normalizer.Form.NFC);
        byte[] passwordBytes = nfc.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[KEK_LEN];
        int result = CryptoProvider.sodium().crypto_pwhash(
                output,
                KEK_LEN,
                passwordBytes,
                passwordBytes.length,
                salt,
                t,
                new NativeLong(m),
                ALG_ARGON2ID13
        );
        if (result != 0) {
            throw new CryptoException("crypto_pwhash failed (result=" + result + ")");
        }
        return output;
    }
}
