package com.erikromson.datawallet.intermediate.signer;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.util.HexFormat;

@Configuration
public class SignerConfig {

    @Value("${datawallet.intermediate.signer.mode:soft}")
    private String mode;

    @Value("${datawallet.intermediate.signer.seed-hex:}")
    private String seedHex;

    @Value("${datawallet.intermediate.signer.kms.key-version-name:}")
    private String kmsKeyVersionName;

    @Bean
    public Signer signer() {
        return switch (mode) {
            case "soft" -> softSigner();
            case "kms" -> kmsSigner();
            default -> throw new IllegalArgumentException(
                    "Unknown signer mode '" + mode + "' — expected 'soft' or 'kms'");
        };
    }

    private SoftSigner softSigner() {
        if (seedHex == null || seedHex.isBlank()) {
            throw new IllegalStateException(
                    "datawallet.intermediate.signer.seed-hex is required when signer.mode=soft");
        }
        byte[] seed = HexFormat.of().parseHex(seedHex);
        if (seed.length != 32) {
            throw new IllegalArgumentException("Signer seed must be exactly 32 bytes (64 hex chars)");
        }
        return new SoftSigner(seed);
    }

    private KmsSigner kmsSigner() {
        if (kmsKeyVersionName == null || kmsKeyVersionName.isBlank()) {
            throw new IllegalStateException(
                    "datawallet.intermediate.signer.kms.key-version-name is required when signer.mode=kms");
        }
        try {
            KeyManagementServiceClient client = KeyManagementServiceClient.create();
            return new KmsSigner(new GcpKmsSignerPort(client, kmsKeyVersionName));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create GCP KMS client", e);
        }
    }
}
