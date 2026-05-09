package com.erikromson.datawallet.intermediate;

import com.erikromson.datawallet.intermediate.attestation.Attestation;
import com.erikromson.datawallet.intermediate.attestation.AttestationConfig;
import com.erikromson.datawallet.intermediate.attestation.StubAttestation;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(IntermediateApplicationTest.StubClientConfig.class)
class IntermediateApplicationTest {

    @TestConfiguration
    static class StubClientConfig {
        @Bean
        @Primary
        public DataWalletAdminClient stubAdminClient() {
            return new DataWalletAdminClient("http://localhost:19999") {
                @Override
                public List<RevokedIssuer> getRevokedIssuers() {
                    return Collections.emptyList();
                }
            };
        }
    }

    @Autowired
    private Attestation attestation;

    @Test
    void startsWithStubMode() {
        assertThat(attestation).isInstanceOf(StubAttestation.class);
    }
}
