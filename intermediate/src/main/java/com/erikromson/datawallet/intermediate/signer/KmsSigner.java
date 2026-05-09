package com.erikromson.datawallet.intermediate.signer;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;

import java.util.Arrays;

/**
 * {@link Signer} backed by a {@link KmsSignerPort}.
 *
 * <p>The public key and key ID are resolved once at construction time and cached.
 * Config-switchable from {@link SoftSigner} via
 * {@code datawallet.intermediate.signer.mode=kms} in {@link SignerConfig}.
 */
public final class KmsSigner implements Signer {

    private static final LazySodiumJava LAZY = new LazySodiumJava(new SodiumJava());

    private final KmsSignerPort port;
    private final byte[] publicKey;
    private final byte[] keyId;

    public KmsSigner(KmsSignerPort port) {
        this.port = port;
        this.publicKey = port.rawEd25519PublicKey();
        this.keyId = computeKeyId(this.publicKey);
    }

    @Override
    public byte[] sign(byte[] message) {
        return port.sign(message);
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public byte[] keyId() {
        return keyId.clone();
    }

    private static byte[] computeKeyId(byte[] publicKey) {
        byte[] hash = new byte[32];
        int result = ((SodiumJava) LAZY.getSodium()).crypto_hash_sha256(hash, publicKey, publicKey.length);
        if (result != 0) {
            throw new IllegalStateException("crypto_hash_sha256 failed");
        }
        return Arrays.copyOf(hash, 16);
    }
}
