package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record KdfParams(
        @NotBlank String alg,
        @NotNull @Min(1) Long m,
        @NotNull @Min(1) Integer t,
        @NotNull @Min(1) Integer p,
        @NotNull @Min(1) Integer version
) {}
