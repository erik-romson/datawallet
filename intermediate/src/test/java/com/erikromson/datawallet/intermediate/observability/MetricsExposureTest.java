package com.erikromson.datawallet.intermediate.observability;

import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(MetricsExposureTest.StubClientConfig.class)
class MetricsExposureTest {

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
    private TestRestTemplate restTemplate;

    @Test
    void prometheusEndpointExposesAllMetrics() {
        ResponseEntity<String> response = restTemplate.getForEntity("/actuator/prometheus", String.class);
        assertThat(response.getStatusCode().value()).isEqualTo(200);

        String body = response.getBody();
        assertThat(body).isNotNull();

        for (String metric : List.of(
                "enroll_results_total",
                "token_results_total",
                "revoke_results_total",
                "attestation_results_total",
                "denylist_size",
                "denylist_age_seconds",
                "denylist_refresh_failures_total"
        )) {
            assertThat(body).contains(metric);
        }
    }
}
