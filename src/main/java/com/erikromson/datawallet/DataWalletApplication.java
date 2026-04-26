package com.erikromson.datawallet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class DataWalletApplication {

    public static void main(String[] args) {
        SpringApplication.run(DataWalletApplication.class, args);
    }
}
