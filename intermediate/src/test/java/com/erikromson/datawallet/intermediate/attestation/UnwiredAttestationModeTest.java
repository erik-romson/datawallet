package com.erikromson.datawallet.intermediate.attestation;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class UnwiredAttestationModeTest {

    @ParameterizedTest
    @ValueSource(strings = {"play-integrity", "app-attest"})
    void unwiredModeFailsClosed(String mode) {
        new ApplicationContextRunner()
                .withUserConfiguration(AttestationConfig.class)
                .withPropertyValues("datawallet.intermediate.attestation.mode=" + mode)
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(AttestationConfig.AttestationModeNotImplemented.class)
                            .hasMessageContaining(mode)
                            .hasMessageContaining("docs/further-work/app-attestation.md");
                });
    }
}
