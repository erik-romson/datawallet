package com.erikromson.datawallet.intermediate.signer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HexFormat;

@Configuration
public class SignerConfig {

    @Value("${datawallet.intermediate.signer.seed-hex}")
    private String seedHex;

    @Bean
    public Signer signer() {
        byte[] seed = HexFormat.of().parseHex(seedHex);
        if (seed.length != 32) {
            throw new IllegalArgumentException("Signer seed must be exactly 32 bytes (64 hex chars)");
        }
        return new SoftSigner(seed);
    }
}
