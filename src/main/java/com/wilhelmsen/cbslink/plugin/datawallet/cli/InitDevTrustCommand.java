package com.wilhelmsen.cbslink.plugin.datawallet.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.UuidV7;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.DirectoryRecord;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.DirectoryRecordCodec;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.PinnedRoot;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.RootSignature;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.RootUpdateCodec;
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
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

/// Bootstraps a development trust chain: generates a root quorum and an issuer
/// signing key, signs a directory record with the roots, and inserts both into
/// Postgres so the running server will accept envelopes from this issuer.
///
/// Idempotent: if `<state-dir>/issuer.json` already exists and `--force` is not
/// given, this command exits without making changes.
///
/// Output: writes root and issuer private keys, the pinned root, and a JSON
/// metadata file (issuer.json) into `<state-dir>` (default ~/.datawallet/dev).
@Component
@Profile("cli")
@Command(
        name = "init-dev-trust",
        description = "Generate dev trust roots + issuer keys and seed Postgres",
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

    @Option(names = "--state-dir", description = "Where to write keys and issuer.json")
    File stateDir = new File(System.getProperty("user.home"), ".datawallet/dev");

    @Option(names = "--root-count", description = "Number of root keys (default: 1)")
    int rootCount = 1;

    @Option(names = "--root-threshold", description = "Signature threshold (default: 1)")
    int rootThreshold = 1;

    @Option(names = "--issuer-label", description = "Issuer label embedded in envelopes")
    String issuerLabel = "Acme Dev Issuer";

    @Option(names = "--passphrase", defaultValue = "devpassphrase",
            description = "Passphrase for storing private keys (default: ${DEFAULT-VALUE} for dev)",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Option(names = "--force", description = "Re-init even if state-dir already has issuer.json")
    boolean force;

    @Override
    public Integer call() throws Exception {
        Path stateDirPath = stateDir.toPath();
        Path issuerJson = stateDirPath.resolve("issuer.json");
        if (Files.exists(issuerJson) && !force) {
            System.out.println("Already initialised: " + issuerJson);
            System.out.println("Use --force to regenerate.");
            return 0;
        }
        if (rootThreshold < 1 || rootThreshold > rootCount) {
            System.err.println("--root-threshold must be between 1 and --root-count");
            return 2;
        }

        Files.createDirectories(stateDirPath);

        // 1. Root quorum
        System.out.println("Generating " + rootCount + " root keypair(s) (threshold="
                + rootThreshold + ")...");
        GenRootCommand.Result roots = GenRootCommand.generate(rootCount, rootThreshold);
        for (int i = 0; i < roots.keyPairs().size(); i++) {
            Path keyFile = stateDirPath.resolve("root-" + i + ".privkey.box");
            CliKeyStore.save(keyFile, roots.keyPairs().get(i).privateKey(), passphrase);
        }
        RootUpdateCodec rootCodec = new RootUpdateCodec();
        byte[] pinnedRootCbor = rootCodec.encodePinnedRoot(roots.pinnedRoot());
        Files.write(stateDirPath.resolve("pinned-root.cbor"), pinnedRootCbor);

        // 2. Issuer signing key
        System.out.println("Generating issuer signing key...");
        UUID issuerId = UuidV7.now();
        byte[] issuerSeed = Random.bytes(32);
        Ed25519.KeyPair issuerKp = Ed25519.seedKeypair(issuerSeed);
        byte[] issuerKeyId = Random.bytes(16);
        Path issuerKeyFile = stateDirPath.resolve("issuer.privkey.box");
        CliKeyStore.save(issuerKeyFile, issuerKp.privateKey(), passphrase);

        // 3. Sign directory record with all root keys
        System.out.println("Signing issuer directory record with root keys...");
        long now = System.currentTimeMillis();
        long validFrom = now - 60_000;                         // 1 min ago, avoid clock skew
        long validUntil = now + 365L * 24 * 3600 * 1000;       // 1 year
        DirectoryRecord unsigned = new DirectoryRecord(
                1, "issuer", uuidToBytes(issuerId), issuerKeyId,
                issuerKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, List.of()
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
                1, "issuer", uuidToBytes(issuerId), issuerKeyId,
                issuerKp.publicKey(), "sign", "active",
                validFrom, validUntil, now, sigs
        );
        byte[] signedRecord = dirCodec.encode(signed);

        // 4. Insert into Postgres
        System.out.println("Inserting pinned root + directory record into Postgres...");
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
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                            "ON CONFLICT (record_type, subject_id, key_id) DO UPDATE SET " +
                            " status = EXCLUDED.status, valid_from = EXCLUDED.valid_from, " +
                            " valid_until = EXCLUDED.valid_until, issued_at = EXCLUDED.issued_at, " +
                            " root_key_id = EXCLUDED.root_key_id, signed_record = EXCLUDED.signed_record")) {
                ps.setString(1, "issuer");
                ps.setObject(2, issuerId);
                ps.setBytes(3, issuerKeyId);
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

        // 5. Save metadata
        ObjectMapper json = new ObjectMapper();
        ObjectNode meta = json.createObjectNode();
        meta.put("issuer_id", issuerId.toString());
        meta.put("issuer_label", issuerLabel);
        meta.put("issuer_key_id_hex", HexFormat.of().formatHex(issuerKeyId));
        meta.put("issuer_priv_path", issuerKeyFile.toAbsolutePath().toString());
        meta.put("pinned_root_path",
                stateDirPath.resolve("pinned-root.cbor").toAbsolutePath().toString());
        meta.put("valid_from_ms", validFrom);
        meta.put("valid_until_ms", validUntil);
        Files.writeString(issuerJson, json.writerWithDefaultPrettyPrinter().writeValueAsString(meta));

        java.util.Arrays.fill(passphrase, '\0');
        java.util.Arrays.fill(jdbcPassword, '\0');

        System.out.println();
        System.out.println("Dev trust initialised.");
        System.out.println("  state dir:    " + stateDirPath.toAbsolutePath());
        System.out.println("  issuer_id:    " + issuerId);
        System.out.println("  issuer_label: " + issuerLabel);
        System.out.println("  metadata:     " + issuerJson.toAbsolutePath());
        System.out.println();
        System.out.println("Next: bin/cli.sh share-with-verifier --to <handle> --plaintext '...' --dev");
        return 0;
    }

    private static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        return buf.array();
    }
}
