package com.erikromson.datawallet.api.entry;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record IssuerSigningKeyRotationDto(
        @NotBlank @Pattern(regexp = BASE64URL) String newPublicKey,
        @NotBlank @Pattern(regexp = BASE64URL) String newKeyId,
        @NotBlank @Pattern(regexp = BASE64URL) String oldKeyId
) {
    static final String BASE64URL = "[A-Za-z0-9_-]+";
}
