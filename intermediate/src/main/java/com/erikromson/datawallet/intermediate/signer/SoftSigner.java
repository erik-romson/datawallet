package com.erikromson.datawallet.intermediate.signer;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.HexFormat;

public final class SoftSigner implements Signer {

    private static final LazySodiumJava LAZY = new LazySodiumJava(new SodiumJava());

    private final byte[] publicKey;
    private final byte[] privateKey;
    private final byte[] keyId;

    public SoftSigner(byte[] seed) {
        byte[] pk = new byte[32];
        byte[] sk = new byte[64];
        int result = ((SodiumJava) LAZY.getSodium()).crypto_sign_seed_keypair(pk, sk, seed);
        if (result != 0) {
            throw new IllegalStateException("crypto_sign_seed_keypair failed");
        }
        this.publicKey = pk;
        this.privateKey = sk;
        this.keyId = computeKeyId(pk);
    }

    @Override
    public byte[] sign(byte[] message) {
        byte[] signature = new byte[64];
        int result = ((SodiumJava) LAZY.getSodium()).crypto_sign_detached(
                signature, Pointer.NULL, message, message.length, privateKey
        );
        if (result != 0) {
            throw new IllegalStateException("crypto_sign_detached failed");
        }
        return signature;
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
