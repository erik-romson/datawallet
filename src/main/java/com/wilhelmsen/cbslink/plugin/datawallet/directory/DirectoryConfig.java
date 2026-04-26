package com.wilhelmsen.cbslink.plugin.datawallet.directory;

import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.PinnedRootHistoryRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.envelope.IssuerKeyResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Configuration
public class DirectoryConfig {

    @Bean
    public PinnedRootHolder pinnedRootHolder(
            @Value("${datawallet.pinned-root.path:#{null}}") String configuredPath) throws IOException {
        Path path;
        if (configuredPath != null && !configuredPath.isBlank()) {
            path = Path.of(configuredPath);
        } else {
            path = Path.of(System.getProperty("user.dir"), "spec", "fixtures", "directory", "pinned-root.cbor");
        }
        byte[] bytes = Files.readAllBytes(path);
        PinnedRoot initial = new DirectoryRecordCodec().decodePinnedRoot(bytes);
        return new PinnedRootHolder(initial);
    }

    @Bean
    public ApplicationRunner pinnedRootStartupLoader(PinnedRootHolder holder,
                                                      PinnedRootHistoryRepository repository,
                                                      DirectoryRecordCodec codec) {
        return args -> {
            holder.setReloadSource(repository, codec);
            repository.findTopByOrderByIdDesc()
                    .map(entity -> codec.decodePinnedRoot(entity.getPinnedRootCbor()))
                    .ifPresent(holder::update);
        };
    }

    @Bean
    public DirectoryRecordCodec directoryRecordCodec() {
        return new DirectoryRecordCodec();
    }

    @Bean
    public DirectoryRecordVerifier directoryRecordVerifier(DirectoryRecordCodec codec) {
        return new DirectoryRecordVerifier(codec);
    }

    @Bean
    public IssuerKeyResolver issuerKeyResolver(DirectoryRecordRepository repository,
                                               DirectoryRecordVerifier verifier,
                                               PinnedRootHolder pinnedRootHolder) {
        return new IssuerKeyResolverImpl(repository, verifier, pinnedRootHolder);
    }
}
