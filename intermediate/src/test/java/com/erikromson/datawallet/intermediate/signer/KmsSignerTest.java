package com.erikromson.datawallet.intermediate.signer;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class KmsSignerTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");

    private static final LazySodiumJava LAZY = new LazySodiumJava(new SodiumJava());

    /** Fake port backed by SoftSigner — stands in for a real cloud HSM in tests. */
    private static KmsSignerPort fakePort(SoftSigner soft) {
        return new KmsSignerPort() {
            @Override public byte[] sign(byte[] message) { return soft.sign(message); }
            @Override public byte[] rawEd25519PublicKey() { return soft.publicKey(); }
        };
    }

    @Test
    void signAndVerifyRoundTrip() {
        SoftSigner soft = new SoftSigner(SEED);
        KmsSigner kms = new KmsSigner(fakePort(soft));

        byte[] message = "hello from kms".getBytes();
        byte[] sig = kms.sign(message);

        assertThat(sig).hasSize(64);
        assertThat(kms.publicKey()).hasSize(32);
        assertThat(kms.keyId()).hasSize(16);

        int result = ((SodiumJava) LAZY.getSodium()).crypto_sign_verify_detached(
                sig, message, message.length, kms.publicKey());
        assertThat(result).isZero();
    }

    @Test
    void keyIdAndPublicKeyMatchSoftSignerForSameSeed() {
        SoftSigner soft = new SoftSigner(SEED);
        KmsSigner kms = new KmsSigner(fakePort(soft));

        assertThat(kms.publicKey()).isEqualTo(soft.publicKey());
        assertThat(kms.keyId()).isEqualTo(soft.keyId());
    }

    @Test
    void publicKeyIsCopiedOnEachCall() {
        KmsSigner kms = new KmsSigner(fakePort(new SoftSigner(SEED)));

        byte[] first = kms.publicKey();
        byte[] second = kms.publicKey();

        assertThat(first).isNotSameAs(second).isEqualTo(second);
    }
}
