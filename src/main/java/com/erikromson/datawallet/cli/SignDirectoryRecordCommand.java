package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.directory.DirectoryRecord;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.RootSignature;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;

@Component
@Profile("cli")
@Command(
        name = "sign-directory",
        description = "Sign a directory record JSON with one or more root keys",
        mixinStandardHelpOptions = true
)
public class SignDirectoryRecordCommand implements Callable<Integer> {

    @Option(names = "--root-priv", required = true, description = "Root private key file(s) (.privkey.box)")
    List<File> rootPrivFiles;

    @Option(names = "--pinned-root", required = true, description = "pinned-root.cbor for key ID lookup")
    File pinnedRootFile;

    @Option(names = "--in", required = true, description = "Input JSON template file")
    File inFile;

    @Option(names = "--out", required = true, description = "Output canonical CBOR file")
    File outFile;

    @Option(names = "--passphrase",
            description = "Passphrase for key decryption (prompted interactively if omitted)",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Override
    public Integer call() throws Exception {
        HexFormat hex = HexFormat.of();
        ObjectMapper json = new ObjectMapper();
        DirectoryRecordCodec codec = new DirectoryRecordCodec();

        PinnedRoot pinnedRoot = codec.decodePinnedRoot(Files.readAllBytes(pinnedRootFile.toPath()));

        JsonNode template = json.readTree(inFile);
        byte[] subjectId = hex.parseHex(template.get("subject_id").asText());
        byte[] keyId = hex.parseHex(template.get("key_id").asText());
        byte[] publicKey = hex.parseHex(template.get("public_key").asText());
        String keyUse = template.get("key_use").asText();
        String status = template.get("status").asText();
        String recordType = template.get("record_type").asText();
        long validFrom = template.get("valid_from").asLong();
        long validUntil = template.get("valid_until").asLong();
        long issuedAt = template.get("issued_at").asLong();

        DirectoryRecord unsigned = new DirectoryRecord(
                1, recordType, subjectId, keyId, publicKey,
                keyUse, status, validFrom, validUntil, issuedAt, List.of(), null, null
        );

        byte[] signedBytes = codec.signedBytesOf(unsigned);

        List<RootSignature> signatures = new ArrayList<>();
        for (File privFile : rootPrivFiles) {
            byte[] privKey = CliKeyStore.load(privFile.toPath(), passphrase);
            byte[] rootPubKey = extractPublicKey(privKey);
            byte[] rootKeyId = findKeyId(pinnedRoot, rootPubKey);
            byte[] sig = Ed25519.signDetached(privKey, signedBytes);
            signatures.add(new RootSignature(rootKeyId, sig));
        }

        DirectoryRecord signed = new DirectoryRecord(
                1, recordType, subjectId, keyId, publicKey,
                keyUse, status, validFrom, validUntil, issuedAt, signatures, null, null
        );

        Files.write(outFile.toPath(), codec.encode(signed));
        System.out.println("Written signed directory record to: " + outFile);
        return 0;
    }

    /** Extracts the 32-byte public key from a 64-byte expanded Ed25519 private key. */
    static byte[] extractPublicKey(byte[] expandedPrivKey) {
        byte[] pub = new byte[32];
        System.arraycopy(expandedPrivKey, 32, pub, 0, 32);
        return pub;
    }

    private static byte[] findKeyId(PinnedRoot pinned, byte[] publicKey) {
        for (PinnedRoot.RootEntry entry : pinned.roots()) {
            if (Arrays.equals(entry.publicKey(), publicKey)) {
                return entry.rootKeyId();
            }
        }
        throw new IllegalArgumentException(
                "No matching key ID found in pinned-root.cbor for provided private key");
    }
}
