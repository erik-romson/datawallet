package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.directory.PinnedRoot;
import com.erikromson.datawallet.directory.DirectoryRecordCodec;
import com.erikromson.datawallet.directory.RootSignature;
import com.erikromson.datawallet.directory.RootUpdate;
import com.erikromson.datawallet.directory.RootUpdateCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import com.erikromson.datawallet.crypto.CanonicalCborMapper;

@Component
@Profile("cli")
@Command(
        name = "sign-root-update",
        description = "Sign a root-update JSON with the old root keys",
        mixinStandardHelpOptions = true
)
public class SignRootUpdateCommand implements Callable<Integer> {

    @Option(names = "--root-priv", required = true, description = "Old root private key file(s) (.privkey.box)")
    List<File> rootPrivFiles;

    @Option(names = "--pinned-root", required = true, description = "Current pinned-root.cbor for key ID lookup")
    File pinnedRootFile;

    @Option(names = "--in", required = true, description = "Input JSON template for the root update")
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
        DirectoryRecordCodec dirCodec = new DirectoryRecordCodec();
        RootUpdateCodec updateCodec = new RootUpdateCodec();

        PinnedRoot currentRoot = dirCodec.decodePinnedRoot(Files.readAllBytes(pinnedRootFile.toPath()));

        JsonNode template = json.readTree(inFile);
        long issuedAt = template.get("issued_at").asLong();

        // Parse old_root_key_ids from hex strings
        List<byte[]> oldRootKeyIds = new ArrayList<>();
        for (JsonNode kid : template.get("old_root_key_ids")) {
            oldRootKeyIds.add(hex.parseHex(kid.asText()));
        }

        // Parse new_pinned_root inline
        PinnedRoot newPinnedRoot = parseNewPinnedRoot(template.get("new_pinned_root"), hex);

        // Build unsigned RootUpdate map for signing
        byte[] signedBytes = buildSignedBytes(oldRootKeyIds, newPinnedRoot, issuedAt, updateCodec);

        List<RootSignature> signatures = new ArrayList<>();
        for (File privFile : rootPrivFiles) {
            byte[] privKey = CliKeyStore.load(privFile.toPath(), passphrase);
            byte[] rootPubKey = SignDirectoryRecordCommand.extractPublicKey(privKey);
            byte[] rootKeyId = findKeyId(currentRoot, rootPubKey);
            byte[] sig = Ed25519.signDetached(privKey, signedBytes);
            signatures.add(new RootSignature(rootKeyId, sig));
        }

        RootUpdate rootUpdate = new RootUpdate(1, oldRootKeyIds, newPinnedRoot, issuedAt, signatures);

        // Encode: build the full CBOR manually since RootUpdateCodec.encode is not public
        byte[] cborBytes = encodeFull(rootUpdate, updateCodec);
        Files.write(outFile.toPath(), cborBytes);
        System.out.println("Written signed root-update to: " + outFile);
        return 0;
    }

    @SuppressWarnings("unchecked")
    private static PinnedRoot parseNewPinnedRoot(JsonNode node, HexFormat hex) {
        int version = node.get("version").asInt();
        String scheme = node.get("scheme").asText();
        int threshold = node.get("threshold").asInt();
        List<PinnedRoot.RootEntry> roots = new ArrayList<>();
        for (JsonNode entry : node.get("roots")) {
            roots.add(new PinnedRoot.RootEntry(
                    hex.parseHex(entry.get("root_key_id").asText()),
                    hex.parseHex(entry.get("public_key").asText()),
                    entry.get("valid_from").asLong(),
                    entry.get("valid_until").asLong()
            ));
        }
        return new PinnedRoot(version, scheme, threshold, roots);
    }

    private static byte[] buildSignedBytes(List<byte[]> oldRootKeyIds, PinnedRoot newRoot,
                                           long issuedAt, RootUpdateCodec codec) {
        // signed bytes = canonical CBOR without old_root_signatures field
        CanonicalCborMapper cbor = new CanonicalCborMapper();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", 1);
        map.put("issued_at", issuedAt);
        map.put("new_pinned_root", pinnedRootToMap(newRoot));
        map.put("old_root_key_ids", oldRootKeyIds);
        return cbor.writeBytes(map);
    }

    private static byte[] encodeFull(RootUpdate update, RootUpdateCodec codec) {
        CanonicalCborMapper cbor = new CanonicalCborMapper();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", update.version());
        map.put("issued_at", update.issuedAt());
        map.put("new_pinned_root", pinnedRootToMap(update.newPinnedRoot()));
        map.put("old_root_key_ids", update.oldRootKeyIds());
        List<Map<String, Object>> sigs = new ArrayList<>();
        for (RootSignature rs : update.oldRootSignatures()) {
            Map<String, Object> sigMap = new LinkedHashMap<>();
            sigMap.put("root_key_id", rs.rootKeyId());
            sigMap.put("signature", rs.signature());
            sigs.add(sigMap);
        }
        map.put("old_root_signatures", sigs);
        return cbor.writeBytes(map);
    }

    private static Map<String, Object> pinnedRootToMap(PinnedRoot root) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("roots", root.roots().stream().map(e -> {
            Map<String, Object> em = new LinkedHashMap<>();
            em.put("public_key", e.publicKey());
            em.put("root_key_id", e.rootKeyId());
            em.put("valid_from", e.validFrom());
            em.put("valid_until", e.validUntil());
            return em;
        }).toList());
        map.put("scheme", root.scheme());
        map.put("threshold", root.threshold());
        map.put("version", root.version());
        return map;
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
