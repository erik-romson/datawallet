package com.erikromson.datawallet.envelope;

import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Sha256;

import java.util.Arrays;
import java.util.Optional;

public final class EnvelopeVerifier {

    private final EnvelopeCodec codec;
    private final IssuerKeyResolver keyResolver;

    public EnvelopeVerifier(EnvelopeCodec codec, IssuerKeyResolver keyResolver) {
        this.codec = codec;
        this.keyResolver = keyResolver;
    }

    public SharedEnvelope verify(byte[] envelopeBytes) {
        SharedEnvelope envelope = codec.decode(envelopeBytes);

        if (envelope.version() != 1) {
            throw new EnvelopeRejection.UnsupportedVersion(envelope.version());
        }

        Optional<DirectoryKeyView> keyView = keyResolver.resolve(
                envelope.issuerId(), envelope.issuerSigningKeyId(), envelope.createdAt()
        );
        if (keyView.isEmpty()) {
            throw new EnvelopeRejection.IssuerKeyNotActiveAt(
                    "No directory record for issuer key at createdAt=" + envelope.createdAt()
            );
        }
        DirectoryKeyView dk = keyView.get();
        if (envelope.createdAt() < dk.validFrom() || envelope.createdAt() >= dk.validUntil()) {
            throw new EnvelopeRejection.IssuerKeyNotActiveAt(
                    "createdAt=" + envelope.createdAt()
                            + " outside valid range [" + dk.validFrom() + ", " + dk.validUntil() + ")"
            );
        }

        byte[] signedBytes = codec.signedBytesOf(
                envelope.withSignature(null)
        );
        if (!Ed25519.verifyDetached(dk.publicKey(), signedBytes, envelope.signature())) {
            throw new EnvelopeRejection.SignatureInvalid();
        }

        byte[] computedHash = Sha256.hash(envelope.ciphertext());
        if (!Arrays.equals(computedHash, envelope.ciphertextHash())) {
            throw new EnvelopeRejection.CiphertextHashMismatch();
        }

        return envelope;
    }
}
