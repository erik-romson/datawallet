package com.erikromson.datawallet.cli;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import picocli.CommandLine;
import picocli.CommandLine.IFactory;

/**
 * Alternate entry point for the offline CLI (no web server, no database).
 *
 * <p>Activate with {@code --spring.profiles.active=cli} or run this class directly.
 * The {@code application-cli.yml} profile disables web, Flyway, and datasource.
 */
@Profile("cli")
@SpringBootApplication(
        scanBasePackages = "com.erikromson.datawallet.cli",
        exclude = {
                DataSourceAutoConfiguration.class,
                HibernateJpaAutoConfiguration.class,
                FlywayAutoConfiguration.class
        }
)
public class CliApplication {

    public static void main(String[] args) {
        System.exit(SpringApplication.exit(
                SpringApplication.run(CliApplication.class, args)));
    }

    @Bean
    public ApplicationRunner cliRunner(DataWalletCli rootCommand, IFactory factory) {
        return (ApplicationArguments args) -> {
            int exitCode = new CommandLine(rootCommand, factory)
                    .execute(args.getSourceArgs());
            if (exitCode != 0) {
                System.exit(exitCode);
            }
        };
    }
}
