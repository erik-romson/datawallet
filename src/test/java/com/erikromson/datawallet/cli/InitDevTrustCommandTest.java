package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
class InitDevTrustCommandTest {

    @TempDir
    Path stateDir;

    @Autowired
    JdbcTemplate jdbc;

    @Value("${spring.datasource.url}")
    String dsUrl;

    @Value("${spring.datasource.username}")
    String dsUser;

    @Value("${spring.datasource.password}")
    String dsPassword;

    @BeforeEach
    void cleanDb() {
        jdbc.update("DELETE FROM directory_records");
        jdbc.update("DELETE FROM pinned_root_history");
    }

    private InitDevTrustCommand command() {
        var cmd = new InitDevTrustCommand();
        cmd.stateDir = stateDir.toFile();
        cmd.jdbcUrl = dsUrl;
        cmd.jdbcUser = dsUser;
        cmd.jdbcPassword = dsPassword.toCharArray();
        cmd.passphrase = "devpassphrase".toCharArray();
        cmd.rootCount = 1;
        cmd.rootThreshold = 1;
        return cmd;
    }

    @Test
    void initCreatesIntermediateRecord() throws Exception {
        assertThat(command().call()).isEqualTo(0);

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM pinned_root_history", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM directory_records " +
                "WHERE record_type = 'intermediate' AND status = 'active' " +
                "AND parent_key_id IS NULL AND root_key_id IS NOT NULL",
                Integer.class)).isEqualTo(1);
        // regression guard: static-issuer path must stay deleted
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM directory_records WHERE record_type = 'issuer'",
                Integer.class)).isEqualTo(0);
    }

    @Test
    void initWritesExpectedStateFiles() throws Exception {
        assertThat(command().call()).isEqualTo(0);

        assertThat(stateDir.resolve("pinned-root.cbor")).exists();
        assertThat(stateDir.resolve("root-0.privkey.box")).exists();
        assertThat(stateDir.resolve("intermediate.privkey.box")).exists();
        assertThat(stateDir.resolve("intermediate.json")).exists();
        assertThat(stateDir.resolve("issuer.json")).doesNotExist();
        assertThat(stateDir.resolve("issuer.privkey.box")).doesNotExist();
    }

    @Test
    void rootKeyIdInRecordMatchesPinnedRoot() throws Exception {
        assertThat(command().call()).isEqualTo(0);

        byte[] dbRootKeyId = jdbc.queryForObject(
                "SELECT root_key_id FROM directory_records WHERE record_type = 'intermediate'",
                byte[].class);
        byte[] pinnedRootCbor = jdbc.queryForObject(
                "SELECT pinned_root_cbor FROM pinned_root_history",
                byte[].class);

        PinnedRoot root = new DirectoryRecordCodec().decodePinnedRoot(pinnedRootCbor);
        assertThat(dbRootKeyId).isEqualTo(root.roots().get(0).rootKeyId());
    }

    @Test
    void customSeedHexDerivesCorrectPublicKey() throws Exception {
        String seedHex = "ab".repeat(32);
        InitDevTrustCommand cmd = command();
        cmd.intermediateSeedHex = seedHex;
        assertThat(cmd.call()).isEqualTo(0);

        byte[] expectedPubKey = Ed25519.seedKeypair(HexFormat.of().parseHex(seedHex)).publicKey();

        JsonNode meta = new ObjectMapper().readTree(stateDir.resolve("intermediate.json").toFile());
        byte[] actualPubKey = Base64.getUrlDecoder().decode(meta.get("pubkey_b64").asText());

        assertThat(actualPubKey).isEqualTo(expectedPubKey);
    }

    @Test
    void printSeedOnlyEmitsSeedWithNoWrites() throws Exception {
        InitDevTrustCommand cmd = command();
        cmd.printSeedOnly = true;

        PrintStream original = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));
        int exitCode;
        try {
            exitCode = cmd.call();
        } finally {
            System.setOut(original);
        }

        assertThat(exitCode).isEqualTo(0);
        assertThat(baos.toString().trim()).matches("[0-9a-f]{64}");
        assertThat(stateDir.resolve("intermediate.json")).doesNotExist();
        assertThat(stateDir.resolve("pinned-root.cbor")).doesNotExist();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM pinned_root_history", Integer.class))
                .isEqualTo(0);
    }

    @Test
    void idempotentWithoutForce() throws Exception {
        assertThat(command().call()).isEqualTo(0);
        String originalMeta = Files.readString(stateDir.resolve("intermediate.json"));

        // second run without --force: exits early
        assertThat(command().call()).isEqualTo(0);

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM pinned_root_history", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM directory_records WHERE record_type = 'intermediate'",
                Integer.class)).isEqualTo(1);
        assertThat(Files.readString(stateDir.resolve("intermediate.json")))
                .isEqualTo(originalMeta);
    }
}
