package com.erikromson.datawallet.intermediate.attestation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class AttestationConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(AttestationConfig.class);

    @Test
    void stubModeCreatesStubAttestation() {
        runner.withPropertyValues("datawallet.intermediate.attestation.mode=stub")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(Attestation.class);
                    assertThat(ctx.getBean(Attestation.class)).isInstanceOf(StubAttestation.class);
                });
    }

    @Test
    void playIntegrityModeFailsClosed() {
        runner.withPropertyValues("datawallet.intermediate.attestation.mode=play-integrity")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(AttestationConfig.AttestationModeNotImplemented.class)
                            .hasMessageContaining("play-integrity")
                            .hasMessageContaining("docs/further-work/app-attestation.md");
                });
    }

    @Test
    void appAttestModeFailsClosed() {
        runner.withPropertyValues("datawallet.intermediate.attestation.mode=app-attest")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(AttestationConfig.AttestationModeNotImplemented.class)
                            .hasMessageContaining("app-attest")
                            .hasMessageContaining("docs/further-work/app-attestation.md");
                });
    }
}
