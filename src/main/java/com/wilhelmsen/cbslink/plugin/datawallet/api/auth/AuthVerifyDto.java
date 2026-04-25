package com.wilhelmsen.cbslink.plugin.datawallet.api.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record AuthVerifyDto(
        @NotNull @JsonProperty("verifier_id") UUID verifierId,
        @NotBlank @JsonProperty("nonce") String nonce,
        @NotBlank @JsonProperty("signature") String signature
) {}
