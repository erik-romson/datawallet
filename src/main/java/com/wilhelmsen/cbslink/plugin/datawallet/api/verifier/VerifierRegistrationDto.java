package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record VerifierRegistrationDto(
        @NotBlank String handle,
        @Size(max = 64) String displayName,
        @NotBlank @Pattern(regexp = BASE64URL) String encPublicKey,
        @NotBlank @Pattern(regexp = BASE64URL) String encKeyId,
        @NotBlank @Pattern(regexp = BASE64URL) String authPublicKey,
        @NotBlank @Pattern(regexp = BASE64URL) String authKeyId,
        @NotBlank @Pattern(regexp = BASE64URL) String wrappedEncPrivateKeyBlob,
        @NotBlank @Pattern(regexp = BASE64URL) String wrappedAuthPrivateKeyBlob,
        @NotBlank @Pattern(regexp = BASE64URL) String kdfSalt,
        @NotNull @Valid KdfParams kdfParams,
        Integer clientPasswordScore
) {
    static final String BASE64URL = "[A-Za-z0-9_-]+";
}
