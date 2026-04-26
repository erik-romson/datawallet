package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record KeyRotationDto(
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String encPublicKey,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String encKeyId,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String authPublicKey,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String authKeyId,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String wrappedEncPrivateKeyBlob,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String wrappedAuthPrivateKeyBlob,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String kdfSalt,
        @NotNull @Valid KdfParams kdfParams,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String oldEncKeyId,
        @NotBlank @Pattern(regexp = VerifierRegistrationDto.BASE64URL) String oldAuthKeyId
) {}
