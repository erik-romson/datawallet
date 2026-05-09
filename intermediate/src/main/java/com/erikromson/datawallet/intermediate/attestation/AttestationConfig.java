package com.erikromson.datawallet.intermediate.attestation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AttestationConfig {

    @Value("${datawallet.intermediate.attestation.mode:stub}")
    private String mode;

    @Bean
    public Attestation attestation() {
        return switch (mode) {
            case "stub" -> new StubAttestation();
            case "play-integrity", "app-attest" -> throw new AttestationModeNotImplemented(
                    "attestation mode '" + mode + "' is configured but not yet implemented. "
                            + "See docs/further-work/app-attestation.md.");
            default -> throw new AttestationModeNotImplemented(
                    "Unknown attestation mode: " + mode);
        };
    }

    public static final class AttestationModeNotImplemented extends RuntimeException {
        public AttestationModeNotImplemented(String message) {
            super(message);
        }
    }
}
