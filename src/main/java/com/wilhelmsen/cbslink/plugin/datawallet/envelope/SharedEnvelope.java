package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

import java.util.List;
import java.util.UUID;

public record SharedEnvelope(
        int version,
        UUID entryId,
        UUID issuerId,
        String issuerLabel,
        byte[] issuerSigningKeyId,
        long createdAt,
        String description,
        String ciphertextAlg,
        byte[] ciphertextNonce,
        byte[] ciphertext,
        byte[] ciphertextHash,
        List<RecipientWrapping> recipientWrappings,
        byte[] signature
) {

    public SharedEnvelope withSignature(byte[] sig) {
        return new SharedEnvelope(
                version, entryId, issuerId, issuerLabel, issuerSigningKeyId,
                createdAt, description, ciphertextAlg, ciphertextNonce,
                ciphertext, ciphertextHash, recipientWrappings, sig
        );
    }
}
