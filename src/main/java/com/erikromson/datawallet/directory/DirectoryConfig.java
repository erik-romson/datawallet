package com.erikromson.datawallet.directory;

import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.domain.PinnedRootHistoryRepository;
import com.erikromson.datawallet.envelope.IssuerKeyResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
        if (!Files.exists(path)) {
            // No fixture available (e.g. Docker e2e); start empty — DB startup loader will populate.
            return new PinnedRootHolder(new PinnedRoot(1, "ed25519-quorum-v1", 1, List.of()));
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
