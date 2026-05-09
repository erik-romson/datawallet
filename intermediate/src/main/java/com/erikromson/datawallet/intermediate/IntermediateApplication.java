package com.erikromson.datawallet.intermediate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class IntermediateApplication {

    public static void main(String[] args) {
        SpringApplication.run(IntermediateApplication.class, args);
    }
}
