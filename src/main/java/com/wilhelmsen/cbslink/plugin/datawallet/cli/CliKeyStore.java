package com.wilhelmsen.cbslink.plugin.datawallet.cli;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Argon2id;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.SecretBox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * File-based keystore: secretbox-encrypted private key with Argon2id-derived KEK.
 *
 * <p>File format: canonical CBOR {@code { v, alg, kdf_m, kdf_t, kdf_p, salt, nonce, ct }}
 * where {@code salt} is the Argon2id salt, {@code nonce} is the secretbox nonce,
 * and {@code ct} is the secretbox ciphertext of the raw private key bytes.
 */
public final class CliKeyStore {

    static final long DEFAULT_M = 268_435_456L;
    static final long DEFAULT_T = 3L;
    static final int DEFAULT_P = 1;
    static final int NONCE_LEN = 24;
    static final int SALT_LEN = 16;

    private CliKeyStore() {}

    public static void save(Path file, byte[] privateKey, char[] passphrase) throws IOException {
        save(file, privateKey, passphrase, DEFAULT_M, DEFAULT_T, DEFAULT_P);
    }

    public static void save(Path file, byte[] privateKey, char[] passphrase,
                            long m, long t, int p) throws IOException {
        byte[] salt = Random.bytes(SALT_LEN);
        byte[] nonce = Random.bytes(NONCE_LEN);
        byte[] kek = Argon2id.deriveKek(new String(passphrase), salt, m, t, p);
        byte[] ct = SecretBox.seal(privateKey, nonce, kek);

        CanonicalCborMapper cbor = new CanonicalCborMapper();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("v", 1);
        map.put("alg", "secretbox");
        map.put("ct", ct);
        map.put("kdf_m", m);
        map.put("kdf_p", p);
        map.put("kdf_t", t);
        map.put("nonce", nonce);
        map.put("salt", salt);
        Files.write(file, cbor.writeBytes(map));
    }

    @SuppressWarnings("unchecked")
    public static byte[] load(Path file, char[] passphrase) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        CanonicalCborMapper cbor = new CanonicalCborMapper();
        Map<String, Object> map = cbor.readValue(bytes, Map.class);

        int v = ((Number) map.get("v")).intValue();
        if (v != 1) {
            throw new IllegalArgumentException("Unsupported key file version: " + v);
        }
        String alg = (String) map.get("alg");
        if (!"secretbox".equals(alg)) {
            throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }

        byte[] salt = (byte[]) map.get("salt");
        byte[] nonce = (byte[]) map.get("nonce");
        byte[] ct = (byte[]) map.get("ct");
        long m = ((Number) map.get("kdf_m")).longValue();
        long t = ((Number) map.get("kdf_t")).longValue();
        int p = ((Number) map.get("kdf_p")).intValue();

        byte[] kek = Argon2id.deriveKek(new String(passphrase), salt, m, t, p);
        return SecretBox.open(ct, nonce, kek);
    }
}
