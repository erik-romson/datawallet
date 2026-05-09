package com.erikromson.datawallet.intermediate.signer;

import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

import java.util.Arrays;
import java.util.Base64;

/**
 * {@link KmsSignerPort} backed by GCP Cloud KMS.
 *
 * <p>The key version must use algorithm {@code EC_SIGN_ED25519}.
 * The key version resource name has the form:
 * {@code projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V}.
 *
 * <p>GCP returns the public key as a PEM-encoded SubjectPublicKeyInfo (SPKI).
 * For Ed25519, the DER-encoded SPKI is 44 bytes; the raw 32-byte key occupies
 * the last 32 bytes. The signature returned by {@code asymmetricSign} for
 * Ed25519 is the raw 64-byte detached signature — no DER wrapping.
 */
public final class GcpKmsSignerPort implements KmsSignerPort {

    private final KeyManagementServiceClient client;
    private final String keyVersionName;
    private volatile byte[] cachedPublicKey;

    public GcpKmsSignerPort(KeyManagementServiceClient client, String keyVersionName) {
        this.client = client;
        this.keyVersionName = keyVersionName;
    }

    @Override
    public byte[] sign(byte[] message) {
        AsymmetricSignRequest request = AsymmetricSignRequest.newBuilder()
                .setName(keyVersionName)
                .setData(ByteString.copyFrom(message))
                .build();
        return client.asymmetricSign(request).getSignature().toByteArray();
    }

    @Override
    public byte[] rawEd25519PublicKey() {
        if (cachedPublicKey != null) {
            return cachedPublicKey.clone();
        }
        synchronized (this) {
            if (cachedPublicKey == null) {
                cachedPublicKey = fetchRawPublicKey();
            }
        }
        return cachedPublicKey.clone();
    }

    private byte[] fetchRawPublicKey() {
        String pem = client.getPublicKey(keyVersionName).getPem()
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pem);
        // Ed25519 SubjectPublicKeyInfo DER is always 44 bytes; raw key is the last 32
        if (der.length < 32) {
            throw new IllegalStateException("GCP KMS returned unexpectedly short public key DER: " + der.length + " bytes");
        }
        return Arrays.copyOfRange(der, der.length - 32, der.length);
    }
}
