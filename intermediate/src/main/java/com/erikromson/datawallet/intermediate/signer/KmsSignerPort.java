package com.erikromson.datawallet.intermediate.signer;

/**
 * Abstraction over a cloud HSM / KMS backend that holds an Ed25519 signing key.
 *
 * <p>Production wiring: {@link GcpKmsSignerPort} (GCP Cloud KMS, algorithm EC_SIGN_ED25519).
 * Tests inject a fake implementation backed by {@link SoftSigner}.
 *
 * <p>AWS KMS is explicitly excluded — it does not support Ed25519 signing.
 * GCP Cloud KMS and Azure Key Vault Managed HSM both support EC_SIGN_ED25519.
 */
public interface KmsSignerPort {

    /**
     * Signs {@code message} using the HSM-held Ed25519 private key.
     *
     * @return 64-byte detached Ed25519 signature
     */
    byte[] sign(byte[] message);

    /**
     * Returns the 32-byte raw Ed25519 public key corresponding to the HSM-held private key.
     * Implementations must cache the result; this method may be called on every request.
     */
    byte[] rawEd25519PublicKey();
}
