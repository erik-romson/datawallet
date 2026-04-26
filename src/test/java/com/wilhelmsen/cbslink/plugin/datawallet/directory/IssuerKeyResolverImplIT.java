package com.wilhelmsen.cbslink.plugin.datawallet.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordEntity;
import com.wilhelmsen.cbslink.plugin.datawallet.domain.DirectoryRecordRepository;
import com.wilhelmsen.cbslink.plugin.datawallet.envelope.DirectoryKeyView;
import com.wilhelmsen.cbslink.plugin.datawallet.envelope.EnvelopeCodec;
import com.wilhelmsen.cbslink.plugin.datawallet.envelope.EnvelopeVerifier;
import com.wilhelmsen.cbslink.plugin.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class IssuerKeyResolverImplIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    @Autowired
    private DirectoryRecordRepository repository;

    private static Path fixturesDir;
    private static PinnedRoot pinnedRoot;
    private static JsonNode directoryMeta;
    private static JsonNode timestamps;

    @BeforeAll
    static void loadFixtures() throws IOException {
        fixturesDir = resolveFixturesDir();
        DirectoryRecordCodec codec = new DirectoryRecordCodec();
        byte[] pinnedRootBytes = Files.readAllBytes(fixturesDir.resolve("directory/pinned-root.cbor"));
        pinnedRoot = codec.decodePinnedRoot(pinnedRootBytes);
        directoryMeta = JSON.readTree(fixturesDir.resolve("directory/directory_meta.json").toFile());
        timestamps = JSON.readTree(fixturesDir.resolve("inputs/timestamps.json").toFile());
    }

    @BeforeEach
    void cleanDb() {
        repository.deleteAll();
    }

    private void insertFixtureRecord(String fixturePath, String recordType, UUID subjectId,
                                      byte[] keyId, String status) throws IOException {
        byte[] signedRecord = Files.readAllBytes(fixturesDir.resolve(fixturePath));
        DirectoryRecordCodec codec = new DirectoryRecordCodec();
        DirectoryRecord parsed = codec.decode(signedRecord);
        DirectoryRecordEntity entity = new DirectoryRecordEntity(
                recordType, subjectId, keyId, status,
                Instant.ofEpochMilli(parsed.validFrom()),
                Instant.ofEpochMilli(parsed.validUntil()),
                Instant.ofEpochMilli(parsed.issuedAt()),
                parsed.rootSignatures().getFirst().rootKeyId(),
                signedRecord
        );
        repository.save(entity);
    }

    @Nested
    class ResolveIssuerKey {

        @Test
        void resolvesAcmeSigningKeyFromDatabase() throws IOException {
            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());

            insertFixtureRecord("directory/issuer-acme-active.cbor", "issuer", issuerId, acmeKeyId, "active");

            long issuedAt = timestamps.get("t_directory_issued").asLong();
            Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(issuedAt + 1000), ZoneOffset.UTC);
            DirectoryRecordVerifier verifier = new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
            IssuerKeyResolverImpl resolver = new IssuerKeyResolverImpl(repository, verifier, new PinnedRootHolder(pinnedRoot));

            long envelopeTime = timestamps.get("t_envelope_basic").asLong();
            Optional<DirectoryKeyView> view = resolver.resolve(issuerId, acmeKeyId, envelopeTime);

            assertThat(view).isPresent();
            assertThat(view.get().status()).isEqualTo("active");
            assertThat(view.get().subjectId()).isEqualTo(issuerId);
        }

        @Test
        void returnsEmptyForUnknownIssuer() throws IOException {
            UUID unknownId = UUID.randomUUID();
            byte[] someKeyId = new byte[16];

            long issuedAt = timestamps.get("t_directory_issued").asLong();
            Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(issuedAt + 1000), ZoneOffset.UTC);
            DirectoryRecordVerifier verifier = new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
            IssuerKeyResolverImpl resolver = new IssuerKeyResolverImpl(repository, verifier, new PinnedRootHolder(pinnedRoot));

            Optional<DirectoryKeyView> view = resolver.resolve(unknownId, someKeyId, issuedAt);
            assertThat(view).isEmpty();
        }

        @Test
        void cacheHitProducesIdenticalResult() throws IOException {
            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());

            insertFixtureRecord("directory/issuer-acme-active.cbor", "issuer", issuerId, acmeKeyId, "active");

            long issuedAt = timestamps.get("t_directory_issued").asLong();
            Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(issuedAt + 1000), ZoneOffset.UTC);
            DirectoryRecordVerifier verifier = new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
            IssuerKeyResolverImpl resolver = new IssuerKeyResolverImpl(repository, verifier, new PinnedRootHolder(pinnedRoot));

            long envelopeTime = timestamps.get("t_envelope_basic").asLong();
            Optional<DirectoryKeyView> first = resolver.resolve(issuerId, acmeKeyId, envelopeTime);
            Optional<DirectoryKeyView> second = resolver.resolve(issuerId, acmeKeyId, envelopeTime);

            assertThat(first).isPresent();
            assertThat(second).isPresent();
            assertThat(first.get().publicKey()).isEqualTo(second.get().publicKey());
            assertThat(first.get().status()).isEqualTo(second.get().status());
        }

        @Test
        void cacheMissAfterClearProducesIdenticalResult() throws IOException {
            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());

            insertFixtureRecord("directory/issuer-acme-active.cbor", "issuer", issuerId, acmeKeyId, "active");

            long issuedAt = timestamps.get("t_directory_issued").asLong();
            Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(issuedAt + 1000), ZoneOffset.UTC);
            DirectoryRecordVerifier verifier = new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
            IssuerKeyResolverImpl resolver = new IssuerKeyResolverImpl(repository, verifier, new PinnedRootHolder(pinnedRoot));

            long envelopeTime = timestamps.get("t_envelope_basic").asLong();
            Optional<DirectoryKeyView> first = resolver.resolve(issuerId, acmeKeyId, envelopeTime);
            resolver.clearCache();
            Optional<DirectoryKeyView> second = resolver.resolve(issuerId, acmeKeyId, envelopeTime);

            assertThat(first).isPresent();
            assertThat(second).isPresent();
            assertThat(first.get().publicKey()).isEqualTo(second.get().publicKey());
        }
    }

    @Nested
    class EnvelopeVerificationWithJpaResolver {

        @Test
        void basicEnvelopeVerifiesAgainstJpaBackedResolver() throws IOException {
            UUID issuerId = bytesToUuid(HEX.parseHex(directoryMeta.get("issuer_id_hex").asText()));
            byte[] acmeKeyId = HEX.parseHex(directoryMeta.get("key_ids").get("acme_sign").asText());

            insertFixtureRecord("directory/issuer-acme-active.cbor", "issuer", issuerId, acmeKeyId, "active");

            long issuedAt = timestamps.get("t_directory_issued").asLong();
            Clock fixedClock = Clock.fixed(Instant.ofEpochMilli(issuedAt + 1000), ZoneOffset.UTC);
            DirectoryRecordVerifier dirVerifier = new DirectoryRecordVerifier(new DirectoryRecordCodec(), fixedClock);
            IssuerKeyResolverImpl resolver = new IssuerKeyResolverImpl(repository, dirVerifier, new PinnedRootHolder(pinnedRoot));

            EnvelopeCodec envelopeCodec = new EnvelopeCodec();
            EnvelopeVerifier envelopeVerifier = new EnvelopeVerifier(envelopeCodec, resolver);

            for (String name : List.of("basic-1-recipient", "three-recipients",
                    "allow-list-update-v2", "unicode-description")) {
                byte[] envelopeBytes = Files.readAllBytes(
                        fixturesDir.resolve("envelopes/" + name + ".cbor"));
                var env = envelopeVerifier.verify(envelopeBytes);
                assertThat(env.version()).as("version for %s", name).isEqualTo(1);
            }
        }
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }

    private static Path resolveFixturesDir() {
        Path dir = Paths.get(System.getProperty("user.dir"));
        for (int i = 0; i < 5; i++) {
            Path candidate = dir.resolve("spec").resolve("fixtures");
            if (Files.isDirectory(candidate) && Files.exists(candidate.resolve("manifest.json"))) {
                return candidate;
            }
            dir = dir.getParent();
            if (dir == null) break;
        }
        return fail("Could not find spec/fixtures directory from " + System.getProperty("user.dir"));
    }
}
