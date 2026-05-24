package com.erikromson.datawallet.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "verifiers")
public class VerifierEntity {

    @Id
    @Column(name = "verifier_id", nullable = false)
    private UUID verifierId;

    @Column(name = "handle", nullable = false, unique = true)
    private String handle;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "enc_public_key", nullable = false)
    private byte[] encPublicKey;

    @Column(name = "enc_key_id", nullable = false)
    private byte[] encKeyId;

    @Column(name = "auth_public_key", nullable = false)
    private byte[] authPublicKey;

    @Column(name = "auth_key_id", nullable = false)
    private byte[] authKeyId;

    @Column(name = "wrapped_enc_private_key_blob", nullable = false)
    private byte[] wrappedEncPrivateKeyBlob;

    @Column(name = "wrapped_auth_private_key_blob", nullable = false)
    private byte[] wrappedAuthPrivateKeyBlob;

    @Column(name = "kdf_salt", nullable = false)
    private byte[] kdfSalt;

    @Column(name = "kdf_params", columnDefinition = "jsonb", nullable = false)
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> kdfParams;

    @Column(name = "discoverable", nullable = false)
    private boolean discoverable;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected VerifierEntity() {}

    public VerifierEntity(UUID verifierId, String handle, String displayName,
                          byte[] encPublicKey, byte[] encKeyId,
                          byte[] authPublicKey, byte[] authKeyId,
                          byte[] wrappedEncPrivateKeyBlob, byte[] wrappedAuthPrivateKeyBlob,
                          byte[] kdfSalt, Map<String, Object> kdfParams, String status) {
        this.verifierId = verifierId;
        this.handle = handle;
        this.displayName = displayName;
        this.encPublicKey = encPublicKey;
        this.encKeyId = encKeyId;
        this.authPublicKey = authPublicKey;
        this.authKeyId = authKeyId;
        this.wrappedEncPrivateKeyBlob = wrappedEncPrivateKeyBlob;
        this.wrappedAuthPrivateKeyBlob = wrappedAuthPrivateKeyBlob;
        this.kdfSalt = kdfSalt;
        this.kdfParams = kdfParams;
        this.status = status;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public void updatePasswordBlobs(byte[] wrappedEnc, byte[] wrappedAuth,
                                    byte[] salt, Map<String, Object> kdfParams) {
        this.wrappedEncPrivateKeyBlob = wrappedEnc;
        this.wrappedAuthPrivateKeyBlob = wrappedAuth;
        this.kdfSalt = salt;
        this.kdfParams = kdfParams;
        this.updatedAt = Instant.now();
    }

    public void rotateKeys(byte[] encPub, byte[] encKeyId,
                           byte[] authPub, byte[] authKeyId,
                           byte[] wrappedEnc, byte[] wrappedAuth,
                           byte[] salt, Map<String, Object> kdfParams) {
        this.encPublicKey = encPub;
        this.encKeyId = encKeyId;
        this.authPublicKey = authPub;
        this.authKeyId = authKeyId;
        this.wrappedEncPrivateKeyBlob = wrappedEnc;
        this.wrappedAuthPrivateKeyBlob = wrappedAuth;
        this.kdfSalt = salt;
        this.kdfParams = kdfParams;
        this.updatedAt = Instant.now();
    }

    public UUID getVerifierId() { return verifierId; }
    public String getHandle() { return handle; }
    public String getDisplayName() { return displayName; }
    public byte[] getEncPublicKey() { return encPublicKey; }
    public byte[] getEncKeyId() { return encKeyId; }
    public byte[] getAuthPublicKey() { return authPublicKey; }
    public byte[] getAuthKeyId() { return authKeyId; }
    public byte[] getWrappedEncPrivateKeyBlob() { return wrappedEncPrivateKeyBlob; }
    public byte[] getWrappedAuthPrivateKeyBlob() { return wrappedAuthPrivateKeyBlob; }
    public byte[] getKdfSalt() { return kdfSalt; }
    public Map<String, Object> getKdfParams() { return kdfParams; }
    public boolean isDiscoverable() { return discoverable; }
    public void setDiscoverable(boolean discoverable) { this.discoverable = discoverable; }
    public String getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
