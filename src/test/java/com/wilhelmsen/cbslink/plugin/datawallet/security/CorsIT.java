package com.wilhelmsen.cbslink.plugin.datawallet.security;

import com.wilhelmsen.cbslink.plugin.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
@TestPropertySource(properties = "datawallet.web-origin=https://wallet.example.com")
class CorsIT {

    @Autowired private MockMvc mvc;

    @Test
    void preflightFromConfiguredOrigin_returnsCorsHeaders() throws Exception {
        mvc.perform(options("/v1/directory/root")
                        .header("Origin", "https://wallet.example.com")
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://wallet.example.com"))
                .andExpect(header().exists("Access-Control-Allow-Methods"));
    }

    @Test
    void preflightFromDifferentOrigin_returnsNoCorsHeaders() throws Exception {
        mvc.perform(options("/v1/directory/root")
                        .header("Origin", "https://evil.example.com")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
