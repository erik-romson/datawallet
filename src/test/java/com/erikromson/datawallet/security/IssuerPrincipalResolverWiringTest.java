package com.erikromson.datawallet.security;

import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

class IssuerPrincipalResolverWiringTest {

    @Nested
    @SpringBootTest(properties = {
            "datawallet.security.issuer-mtls=true",
            "datawallet.security.admin-mtls=false"
    })
    @ActiveProfiles({"test", "it"})
    @Import(PostgresTestcontainer.class)
    class MtlsTrueDefaultBearer {

        @Autowired
        private ApplicationContext context;

        @Test
        void exactlyOneResolverIsX509() {
            var resolvers = context.getBeansOfType(IssuerPrincipalResolver.class);
            assertThat(resolvers).hasSize(1);
            assertThat(resolvers.values().iterator().next()).isInstanceOf(X509IssuerPrincipalResolver.class);
        }

        @Test
        void mtlsFilterChainIsPresent() {
            var chains = context.getBeansOfType(SecurityFilterChain.class);
            assertThat(chains).containsKey("issuerMtlsFilterChain");
            assertThat(chains).doesNotContainKey("issuerBearerFilterChain");
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "datawallet.security.issuer-mtls=false",
            "datawallet.security.issuer-bearer.enabled=false",
            "datawallet.security.admin-mtls=false"
    })
    @ActiveProfiles({"test", "it"})
    @Import(PostgresTestcontainer.class)
    class MtlsFalseBearerFalse {

        @Autowired
        private ApplicationContext context;

        @Test
        void exactlyOneResolverIsHeader() {
            var resolvers = context.getBeansOfType(IssuerPrincipalResolver.class);
            assertThat(resolvers).hasSize(1);
            assertThat(resolvers.values().iterator().next()).isInstanceOf(HeaderIssuerPrincipalResolver.class);
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "datawallet.security.issuer-mtls=false",
            "datawallet.security.issuer-bearer.enabled=true",
            "datawallet.security.issuer-bearer.audience=urn:datawallet:server",
            "datawallet.security.admin-mtls=false"
    })
    @ActiveProfiles({"test", "it"})
    @Import(PostgresTestcontainer.class)
    class MtlsFalseBearerTrue {

        @Autowired
        private ApplicationContext context;

        @Test
        void exactlyOneResolverIsBearer() {
            var resolvers = context.getBeansOfType(IssuerPrincipalResolver.class);
            assertThat(resolvers).hasSize(1);
            assertThat(resolvers.values().iterator().next()).isInstanceOf(BearerIssuerPrincipalResolver.class);
        }

        @Test
        void bearerFilterChainIsPresent() {
            var chains = context.getBeansOfType(SecurityFilterChain.class);
            assertThat(chains).containsKey("issuerBearerFilterChain");
            assertThat(chains).doesNotContainKey("issuerMtlsFilterChain");
        }
    }

    @Nested
    class MtlsTrueBearerTrueFails {

        @Test
        void startupFails() {
            assertThat(org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () -> {
                new org.springframework.boot.builder.SpringApplicationBuilder(
                        com.erikromson.datawallet.DataWalletApplication.class)
                        .properties(
                                "datawallet.security.issuer-mtls=true",
                                "datawallet.security.issuer-bearer.enabled=true",
                                "datawallet.security.issuer-bearer.audience=urn:datawallet:server",
                                "datawallet.security.admin-mtls=false",
                                "spring.datasource.url=jdbc:tc:postgresql:16:///datawallet",
                                "spring.datasource.username=test",
                                "spring.datasource.password=test",
                                "datawallet.web-origin=https://web.example.com"
                        )
                        .profiles("test")
                        .run();
            })).hasStackTraceContaining("issuer-bearer.enabled=true requires issuer-mtls=false");
        }
    }
}
