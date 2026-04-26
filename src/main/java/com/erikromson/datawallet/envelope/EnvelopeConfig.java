package com.erikromson.datawallet.envelope;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EnvelopeConfig {

    @Bean
    public EnvelopeCodec envelopeCodec() {
        return new EnvelopeCodec();
    }

    @Bean
    public EnvelopeVerifier envelopeVerifier(EnvelopeCodec codec, IssuerKeyResolver keyResolver) {
        return new EnvelopeVerifier(codec, keyResolver);
    }
}
