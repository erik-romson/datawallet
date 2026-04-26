package com.erikromson.datawallet.cli;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.util.concurrent.Callable;

@Component
@Profile("cli")
@Command(
        name = "datawallet-cli",
        description = "Data Wallet operator and issuer CLI",
        subcommands = {
                GenRootCommand.class,
                SignDirectoryRecordCommand.class,
                SignRootUpdateCommand.class,
                BuildEnvelopeCommand.class,
                UploadEnvelopeCommand.class,
                RegisterVerifierCommand.class,
                InitDevTrustCommand.class,
                ShareWithVerifierCommand.class,
                VerifierFetchCommand.class
        },
        mixinStandardHelpOptions = true
)
public class DataWalletCli implements Callable<Integer> {

    @Override
    public Integer call() {
        new CommandLine(this).usage(System.out);
        return 0;
    }
}
