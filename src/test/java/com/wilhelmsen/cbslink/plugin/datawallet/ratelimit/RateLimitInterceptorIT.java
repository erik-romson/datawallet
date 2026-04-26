package com.wilhelmsen.cbslink.plugin.datawallet.ratelimit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import({PostgresTestcontainer.class, RateLimitInterceptorIT.ClockTestConfig.class})
class RateLimitInterceptorIT {

    /** Shared adjustable clock — advanced between test phases. */
    static final AdjustableClock TEST_CLOCK = new AdjustableClock(Instant.parse("2026-04-25T10:00:00Z"));

    @TestConfiguration(proxyBeanMethods = false)
    static class ClockTestConfig {
        @Bean
        @Primary
        Clock testClock() {
            return TEST_CLOCK;
        }
    }

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @BeforeEach
    void resetState() {
        jdbcTemplate.update("DELETE FROM rate_limits");
        jdbcTemplate.update("DELETE FROM auth_lockouts");
        TEST_CLOCK.reset(Instant.parse("2026-04-25T10:00:00Z"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static String b64(int len) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) 0x42);
        return B64URL.encodeToString(b);
    }

    private UUID registerVerifier() throws Exception {
        byte[] seed = Random.bytes(32);
        Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
        String handle = "rl" + System.nanoTime();

        String json = """
                {
                  "handle": "%s",
                  "display_name": "RL Test",
                  "enc_public_key": "%s",
                  "enc_key_id": "%s",
                  "auth_public_key": "%s",
                  "auth_key_id": "%s",
                  "wrapped_enc_private_key_blob": "%s",
                  "wrapped_auth_private_key_blob": "%s",
                  "kdf_salt": "%s",
                  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19},
                  "client_password_score": 3
                }
                """.formatted(handle, b64(32), b64(16),
                B64URL.encodeToString(kp.publicKey()), b64(16),
                b64(48), b64(48), b64(16));

        MvcResult reg = mvc.perform(post("/v1/verifiers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(reg.getResponse().getContentAsString());
        return UUID.fromString(body.get("verifier_id").asText());
    }

    private MvcResult postChallenge(UUID verifierId) throws Exception {
        String body = """
                {"verifier_id": "%s"}
                """.formatted(verifierId);
        return mvc.perform(post("/v1/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
    }

    // ── tests ────────────────────────────────────────────────────────────────

    @Test
    void sixthChallengeRequest_returns429_andRetryAfterAllowsRecovery() throws Exception {
        UUID verifierId = registerVerifier();

        // burst=5: first 5 should succeed
        for (int i = 0; i < 5; i++) {
            MvcResult result = postChallenge(verifierId);
            assertThat(result.getResponse().getStatus())
                    .as("request %d should be 200", i + 1)
                    .isEqualTo(200);
        }

        // 6th request: denied
        MvcResult denied = postChallenge(verifierId);
        assertThat(denied.getResponse().getStatus()).isEqualTo(429);

        String retryAfterHeader = denied.getResponse().getHeader("Retry-After");
        assertThat(retryAfterHeader).isNotNull();
        long retryAfterSec = Long.parseLong(retryAfterHeader);
        assertThat(retryAfterSec).isGreaterThan(0);

        JsonNode errorBody = objectMapper.readTree(denied.getResponse().getContentAsString());
        assertThat(errorBody.get("error").get("code").asText()).isEqualTo("rate_limited");

        // advance clock past the retry-after window
        TEST_CLOCK.advance(Duration.ofSeconds(retryAfterSec));

        // next request should succeed
        MvcResult recovered = postChallenge(verifierId);
        assertThat(recovered.getResponse().getStatus())
                .as("request after clock advance should be 200")
                .isEqualTo(200);
    }

    @Test
    void concurrent_noOverGrant() throws Exception {
        UUID verifierId = registerVerifier();

        // drain tokens down to 1 remaining (4 requests consume 4 of 5 burst tokens)
        for (int i = 0; i < 4; i++) {
            MvcResult r = postChallenge(verifierId);
            assertThat(r.getResponse().getStatus()).isEqualTo(200);
        }

        // 2 concurrent requests; FOR UPDATE serializes them so exactly 1 succeeds
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger rateLimitedCount = new AtomicInteger(0);

        String body = """
                {"verifier_id": "%s"}
                """.formatted(verifierId);

        Runnable task = () -> {
            ready.countDown();
            try {
                go.await();
                MvcResult r = mvc.perform(post("/v1/auth/challenge")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                        .andReturn();
                int status = r.getResponse().getStatus();
                if (status == 200) successCount.incrementAndGet();
                else if (status == 429) rateLimitedCount.incrementAndGet();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        Thread t1 = new Thread(task);
        Thread t2 = new Thread(task);
        t1.start();
        t2.start();
        ready.await();
        go.countDown();
        t1.join();
        t2.join();

        assertThat(successCount.get()).as("exactly one concurrent request should succeed").isEqualTo(1);
        assertThat(rateLimitedCount.get()).as("exactly one concurrent request should be rate limited").isEqualTo(1);
    }

    // ── adjustable clock ─────────────────────────────────────────────────────

    static class AdjustableClock extends Clock {
        private volatile Instant current;

        AdjustableClock(Instant start) { this.current = start; }

        void advance(Duration d) { current = current.plus(d); }

        void reset(Instant to) { current = to; }

        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return current; }
    }
}
