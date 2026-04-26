package com.erikromson.datawallet;

import com.erikromson.datawallet.persistence.PostgresTestcontainer;
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
