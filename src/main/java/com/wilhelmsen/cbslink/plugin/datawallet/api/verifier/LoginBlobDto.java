package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.UUID;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LoginBlobDto(
        UUID verifierId,
        String authPublicKey,
        String authKeyId,
        String encPublicKey,
        String encKeyId,
        String wrappedEncPrivateKeyBlob,
        String wrappedAuthPrivateKeyBlob,
        String kdfSalt,
        KdfParams kdfParams
) {}
