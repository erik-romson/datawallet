package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;

public final class EnvelopeSigner {

    private final EnvelopeCodec codec;

    public EnvelopeSigner(EnvelopeCodec codec) {
        this.codec = codec;
    }

    public byte[] sign(SharedEnvelope unsigned, byte[] issuerEd25519Priv) {
        if (unsigned.signature() != null) {
            throw new IllegalArgumentException("Envelope already has a signature");
        }
        byte[] signedBytes = codec.signedBytesOf(unsigned);
        byte[] sig = Ed25519.signDetached(issuerEd25519Priv, signedBytes);
        return codec.encode(unsigned.withSignature(sig));
    }
}
