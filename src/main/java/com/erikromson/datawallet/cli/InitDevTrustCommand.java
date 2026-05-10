package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.crypto.UuidV7;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.RootSignature;
import com.erikromson.datawallet.directory.RootUpdateCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

/// Bootstraps a development trust chain: generates a root quorum and an intermediate
/// signing key, signs an `intermediate` directory record with the roots, and inserts
/// both into Postgres so the intermediate service can enroll issuers.
///
/// Idempotent: if `<state-dir>/intermediate.json` already exists and `--force` is not
/// given, this command exits without making changes.
///
/// Output: writes root and intermediate private keys, the pinned root, and a JSON
/// metadata file (`intermediate.json`) into `<state-dir>`.
@Component
@Profile("cli")
@Command(
        name = "init-dev-trust",
        description = "Generate dev trust roots + intermediate signing key and seed Postgres",
        mixinStandardHelpOptions = true
)
public class InitDevTrustCommand implements Callable<Integer> {

    @Option(names = "--jdbc-url",
            defaultValue = "jdbc:postgresql://localhost:5432/datawallet",
            description = "JDBC URL (default: ${DEFAULT-VALUE})")
    String jdbcUrl;

    @Option(names = "--jdbc-user", defaultValue = "wallet_app",
            description = "DB user (default: ${DEFAULT-VALUE})")
    String jdbcUser;

    @Option(names = "--jdbc-password", defaultValue = "devpw",
            description = "DB password (default: ${DEFAULT-VALUE} for dev)",
            interactive = true, arity = "0..1")
    char[] jdbcPassword;

    @Option(names = "--state-dir", description = "Where to write keys and intermediate.json")
    File stateDir = new File(System.getProperty("user.home"), ".datawallet/dev");

    @Option(names = "--root-count", description = "Number of root keys (default: 1)")
    int rootCount = 1;

    @Option(names = "--root-threshold", description = "Signature threshold (default: 1)")
    int rootThreshold = 1;

    @Option(names = "--intermediate-label", description = "Intermediate label (default: ${DEFAULT-VALUE})")
    String intermediateLabel = "E2E Dev Intermediate";

    @Option(names = "--intermediate-seed-hex",
            description = "64-hex-char seed override (auto-generated via libsodium if omitted)")
    String intermediateSeedHex;

    @Option(names = "--passphrase", defaultValue = "devpassphrase",
            description = "Passphrase for storing private keys (default: ${DEFAULT-VALUE} for dev)",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Option(names = "--force", description = "Re-init even if state-dir already has intermediate.json")
    boolean force;

    @Option(names = "--print-seed-only",
            description = "Emit only the intermediate seed hex on stdout; no DB or file writes")
    boolean printSeedOnly;

    @Override
    public Integer call() throws Exception {
        if (printSeedOnly) {
            byte[] seed = intermediateSeedHex != null
                    ? HexFormat.of().parseHex(intermediateSeedHex)
                    : Random.bytes(32);
            System.out.println(HexFormat.of().formatHex(seed));
            return 0;
        }

        if (rootThreshold < 1 || rootThreshold > rootCount) {
            System.err.println("--root-threshold must be between 1 and --root-count");
            return 2;
        }

        Path stateDirPath = stateDir.toPath();
        Path intermediateJsonPath = stateDirPath.resolve("intermediate.json");
        if (Files.exists(intermediateJsonPath) && !force) {
            System.out.println("Already initialised: " + intermediateJsonPath);
            System.out.println("Use --force to regenerate.");
            return 0;
        }

        Files.createDirectories(stateDirPath);

        // 1. Root quorum
        System.out.println("Generating " + rootCount + " root keypair(s) (threshold=" + rootThreshold + ")...");
        GenRootCommand.Result roots = GenRootCommand.generate(rootCount, rootThreshold);
        for (int i = 0; i < roots.keyPairs().size(); i++) {
            Path keyFile = stateDirPath.resolve("root-" + i + ".privkey.box");
            CliKeyStore.save(keyFile, roots.keyPairs().get(i).privateKey(), passphrase);
        }
        RootUpdateCodec rootCodec = new RootUpdateCodec();
        byte[] pinnedRootCbor = rootCodec.encodePinnedRoot(roots.pinnedRoot());
        Files.write(stateDirPath.resolve("pinned-root.cbor"), pinnedRootCbor);

        // 2. Intermediate signing key
        System.out.println("Generating intermediate signing key...");
        UUID intermediateId = UuidV7.now();
        byte[] intermediateSeed = intermediateSeedHex != null
                ? HexFormat.of().parseHex(intermediateSeedHex)
                : Random.bytes(32);
        Ed25519.KeyPair intermediateKp = Ed25519.seedKeypair(intermediateSeed);
        byte[] intermediateKeyId = Random.bytes(16);
        Path intermediateKeyFile = stateDirPath.resolve("intermediate.privkey.box");
        CliKeyStore.save(intermediateKeyFile, intermediateKp.privateKey(), passphrase);

        // 3. Sign intermediate directory record with all root keys
        System.out.println("Signing intermediate directory record with root keys...");
        long now = System.currentTimeMillis();
        long validFrom = now - 60_000;                        // 1 min ago, avoid clock skew
        long validUntil = now + 365L * 24 * 3600 * 1000;     // 1 year
        DirectoryRecord unsigned = new DirectoryRecord(
                1, "intermediate", uuidToBytes(intermediateId), intermediateKeyId,
                intermediateKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, List.of(), null, null
        );
        DirectoryRecordCodec dirCodec = new DirectoryRecordCodec();
        byte[] signedBytes = dirCodec.signedBytesOf(unsigned);

        List<RootSignature> sigs = new ArrayList<>();
        for (int i = 0; i < roots.keyPairs().size(); i++) {
            byte[] rootPriv = roots.keyPairs().get(i).privateKey();
            byte[] sig = Ed25519.signDetached(rootPriv, signedBytes);
            sigs.add(new RootSignature(roots.keyIds().get(i), sig));
        }
        DirectoryRecord signed = new DirectoryRecord(
                1, "intermediate", uuidToBytes(intermediateId), intermediateKeyId,
                intermediateKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, sigs, null, null
        );
        byte[] signedRecord = dirCodec.encode(signed);

        // 4. Insert pinned root and intermediate record into Postgres
        System.out.println("Inserting pinned root + intermediate record into Postgres...");
        try (Connection conn = DriverManager.getConnection(jdbcUrl, jdbcUser, new String(jdbcPassword))) {
            conn.setAutoCommit(false);

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO pinned_root_history (pinned_root_cbor) VALUES (?)")) {
                ps.setBytes(1, pinnedRootCbor);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO directory_records " +
                            "(record_type, subject_id, key_id, status, valid_from, valid_until, " +
                            " issued_at, root_key_id, signed_record) " +
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, "intermediate");
                ps.setObject(2, intermediateId);
                ps.setBytes(3, intermediateKeyId);
                ps.setString(4, "active");
                ps.setTimestamp(5, Timestamp.from(Instant.ofEpochMilli(validFrom)));
                ps.setTimestamp(6, Timestamp.from(Instant.ofEpochMilli(validUntil)));
                ps.setTimestamp(7, Timestamp.from(Instant.ofEpochMilli(now)));
                ps.setBytes(8, roots.keyIds().get(0));
                ps.setBytes(9, signedRecord);
                ps.executeUpdate();
            }

            conn.commit();
        }

        java.util.Arrays.fill(jdbcPassword, '\0');

        // 5. Write metadata
        ObjectMapper json = new ObjectMapper();
        ObjectNode meta = json.createObjectNode();
        meta.put("intermediate_id", intermediateId.toString());
        meta.put("key_id", HexFormat.of().formatHex(intermediateKeyId));
        meta.put("pubkey_b64", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(intermediateKp.publicKey()));
        meta.put("seed_hex", HexFormat.of().formatHex(intermediateSeed));
        Files.writeString(intermediateJsonPath,
                json.writerWithDefaultPrettyPrinter().writeValueAsString(meta));

        java.util.Arrays.fill(passphrase, '\0');

        System.out.println();
        System.out.println("Dev trust initialised.");
        System.out.println("  state dir:       " + stateDirPath.toAbsolutePath());
        System.out.println("  intermediate_id: " + intermediateId);
        System.out.println("  label:           " + intermediateLabel);
        System.out.println("  metadata:        " + intermediateJsonPath.toAbsolutePath());
        return 0;
    }

    private static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return buf.array();
    }
}
