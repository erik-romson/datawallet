package com.wilhelmsen.cbslink.plugin.datawallet.cli;

import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.PinnedRoot;
import com.wilhelmsen.cbslink.plugin.datawallet.directory.RootUpdateCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Component
@Profile("cli")
@Command(
        name = "gen-root",
        description = "Generate a root quorum keypair set and write a pinned-root.cbor blob",
        mixinStandardHelpOptions = true
)
public class GenRootCommand implements Callable<Integer> {

    @Option(names = {"--threshold", "-t"}, required = true, description = "Signature threshold (M of N)")
    int threshold;

    @Option(names = {"--count", "-n"}, required = true, description = "Number of root keypairs to generate")
    int count;

    @Option(names = {"--out-dir", "-o"}, required = true, description = "Output directory for key files and pinned-root.cbor")
    File outDir;

    @Option(names = "--passphrase",
            description = "Passphrase for key encryption (prompted interactively if omitted)",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Override
    public Integer call() throws Exception {
        if (threshold < 1 || threshold > count) {
            System.err.println("threshold must be between 1 and count");
            return 1;
        }

        Result result = generate(count, threshold);

        Files.createDirectories(outDir.toPath());

        for (int i = 0; i < result.keyPairs().size(); i++) {
            File keyFile = new File(outDir, "root-" + i + ".privkey.box");
            CliKeyStore.save(keyFile.toPath(), result.keyPairs().get(i).privateKey(), passphrase);
        }

        RootUpdateCodec codec = new RootUpdateCodec();
        byte[] pinnedRootBytes = codec.encodePinnedRoot(result.pinnedRoot());
        Files.write(outDir.toPath().resolve("pinned-root.cbor"), pinnedRootBytes);

        System.out.println("Generated " + count + " root keypairs (threshold=" + threshold + ")");
        System.out.println("Written to: " + outDir.getAbsolutePath());
        return 0;
    }

    /**
     * Generates root keypairs and a PinnedRoot with 1-year validity.
     * Extracted for in-process testing.
     */
    public static Result generate(int count, int threshold) {
        long now = System.currentTimeMillis();
        long validFrom = now;
        long validUntil = now + 365L * 24 * 3600 * 1000;

        List<Ed25519.KeyPair> keyPairs = new ArrayList<>();
        List<byte[]> keyIds = new ArrayList<>();
        List<PinnedRoot.RootEntry> roots = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            byte[] seed = Random.bytes(32);
            Ed25519.KeyPair kp = Ed25519.seedKeypair(seed);
            byte[] keyId = Random.bytes(16);
            keyPairs.add(kp);
            keyIds.add(keyId);
            roots.add(new PinnedRoot.RootEntry(keyId, kp.publicKey(), validFrom, validUntil));
        }

        PinnedRoot pinnedRoot = new PinnedRoot(1, "ed25519", threshold, roots);
        return new Result(keyPairs, keyIds, pinnedRoot);
    }

    public record Result(List<Ed25519.KeyPair> keyPairs, List<byte[]> keyIds, PinnedRoot pinnedRoot) {}
}
