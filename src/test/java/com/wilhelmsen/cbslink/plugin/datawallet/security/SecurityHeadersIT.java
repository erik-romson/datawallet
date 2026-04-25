package com.wilhelmsen.cbslink.plugin.datawallet.security;

import com.wilhelmsen.cbslink.plugin.datawallet.api.entry.FixtureIssuerKeyResolver;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"test", "it"})
@Import({PostgresTestcontainer.class, FixtureIssuerKeyResolver.class})
class SecurityHeadersIT {

    @Autowired private MockMvc mvc;

    @Test
    void everyResponse_includesRequiredSecurityHeaders() throws Exception {
        mvc.perform(get("/v1/directory/root"))
                .andExpect(status().isOk())
                .andExpect(header().string("Strict-Transport-Security",
                        "max-age=63072000; includeSubDomains; preload"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Permissions-Policy",
                        "geolocation=(), camera=(), microphone=(), usb=()"))
                .andExpect(header().string("Content-Security-Policy",
                        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    }

    @Test
    void directoryRoute_hasCacheControlPublic() throws Exception {
        mvc.perform(get("/v1/directory/root"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=300"));
    }

    @Test
    void sensitiveAuthRoute_hasCacheControlNoStore() throws Exception {
        mvc.perform(get("/v1/auth/challenge"))
                .andExpect(header().string("Cache-Control", "no-store, no-cache, must-revalidate, private"))
                .andExpect(header().string("Pragma", "no-cache"));
    }

    @Test
    void sensitiveSharedRoute_hasCacheControlNoStore() throws Exception {
        mvc.perform(get("/v1/shared"))
                .andExpect(header().string("Cache-Control", "no-store, no-cache, must-revalidate, private"));
    }
}
