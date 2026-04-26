package com.wilhelmsen.cbslink.plugin.datawallet;

import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class DataWalletApplicationTests {

    @Test
    void contextLoads() {
    }
}
