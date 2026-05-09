package com.erikromson.datawallet.intermediate.signer;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class SoftSignerTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");

    @Test
    void signAndVerifyRoundTrip() {
        SoftSigner signer = new SoftSigner(SEED);
        byte[] message = "test message".getBytes();
        byte[] signature = signer.sign(message);

        assertThat(signature).hasSize(64);
        assertThat(signer.publicKey()).hasSize(32);
        assertThat(signer.keyId()).hasSize(16);
    }

    @Test
    void deterministicKeyGeneration() {
        SoftSigner a = new SoftSigner(SEED);
        SoftSigner b = new SoftSigner(SEED);

        assertThat(a.publicKey()).isEqualTo(b.publicKey());
        assertThat(a.keyId()).isEqualTo(b.keyId());
    }
}
