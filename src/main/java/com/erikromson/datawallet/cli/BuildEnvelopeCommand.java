package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.crypto.Random;
import com.erikromson.datawallet.crypto.SealedBox;
import com.erikromson.datawallet.crypto.SecretBox;
import com.erikromson.datawallet.crypto.Sha256;
import com.erikromson.datawallet.crypto.UuidV7;
import com.erikromson.datawallet.envelope.EnvelopeCodec;
import com.erikromson.datawallet.envelope.EnvelopeSigner;
import com.erikromson.datawallet.envelope.RecipientWrapping;
import com.erikromson.datawallet.envelope.SharedEnvelope;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

@Component
@Profile("cli")
@Command(
        name = "build-envelope",
        description = "Encrypt plaintext for verifier recipients and produce a signed CBOR envelope",
        mixinStandardHelpOptions = true
)
public class BuildEnvelopeCommand implements Callable<Integer> {

    @Option(names = "--plaintext-file", required = true, description = "File containing plaintext credential")
    File plaintextFile;

    @Option(names = "--issuer-priv", required = true, description = "Issuer private key file (.privkey.box)")
    File issuerPrivFile;

    @Option(names = "--issuer-id", required = true, description = "Issuer UUID")
    UUID issuerId;

    @Option(names = "--issuer-label", required = true, description = "Human-readable issuer label")
    String issuerLabel;

    @Option(names = "--issuer-key-id", required = true, description = "Issuer signing key ID (hex)")
    String issuerKeyIdHex;

    @Option(names = "--description", description = "Entry description")
    String description = "";

    @Option(names = "--recipients", required = true, description = "JSON file listing recipient verifiers")
    File recipientsFile;

    @Option(names = "--out", required = true, description = "Output canonical CBOR envelope file")
    File outFile;

    @Option(names = "--passphrase",
            description = "Passphrase for key decryption (prompted interactively if omitted)",
            interactive = true, arity = "0..1")
    char[] passphrase;

    @Override
    public Integer call() throws Exception {
        HexFormat hex = HexFormat.of();
        ObjectMapper json = new ObjectMapper();

        String plaintextContent = Files.readString(plaintextFile.toPath(), StandardCharsets.UTF_8);
        byte[] issuerPrivKey = CliKeyStore.load(issuerPrivFile.toPath(), passphrase);
        byte[] issuerKeyId = hex.parseHex(issuerKeyIdHex);

        List<RecipientInfo> recipients = new ArrayList<>();
        for (JsonNode node : json.readTree(recipientsFile)) {
            recipients.add(new RecipientInfo(
                    UUID.fromString(node.get("verifier_id").asText()),
                    hex.parseHex(node.get("verifier_key_id").asText()),
                    hex.parseHex(node.get("enc_public_key").asText())
            ));
        }

        UUID entryId = UuidV7.now();
        long createdAt = System.currentTimeMillis();

        byte[] envelopeBytes = buildEnvelope(
                plaintextContent, entryId, issuerId, issuerLabel, issuerKeyId,
                issuerPrivKey, createdAt, description, recipients
        );

        Files.write(outFile.toPath(), envelopeBytes);
        System.out.println("entry_id: " + entryId);
        System.out.println("Written envelope to: " + outFile);
        return 0;
    }

    /**
     * Builds and signs a {@link SharedEnvelope} from plaintext + recipient public keys.
     * Extracted as a static method for in-process testing.
     */
    public static byte[] buildEnvelope(
            String plaintextContent,
            UUID entryId,
            UUID issuerId,
            String issuerLabel,
            byte[] issuerSigningKeyId,
            byte[] issuerPrivKey,
            long createdAt,
            String description,
            List<RecipientInfo> recipients) {

        // NFC-normalize and UTF-8 encode per spec
        String normalized = Normalizer.normalize(plaintextContent, Normalizer.Form.NFC);
        byte[] plaintextBytes = normalized.getBytes(StandardCharsets.UTF_8);

        byte[] dataKey = Random.bytes(32);
        byte[] nonce = Random.bytes(24);

        byte[] ciphertext = SecretBox.seal(plaintextBytes, nonce, dataKey);
        byte[] ciphertextHash = Sha256.hash(ciphertext);

        List<RecipientWrapping> wrappings = new ArrayList<>();
        for (RecipientInfo r : recipients) {
            byte[] wrapped = SealedBox.seal(dataKey, r.encPublicKey());
            wrappings.add(new RecipientWrapping(r.verifierId(), r.verifierKeyId(), wrapped));
        }

        SharedEnvelope unsigned = new SharedEnvelope(
                1, entryId, issuerId, issuerLabel, issuerSigningKeyId,
                createdAt, description, "xsalsa20poly1305", nonce,
                ciphertext, ciphertextHash, wrappings, null
        );

        EnvelopeCodec codec = new EnvelopeCodec();
        EnvelopeSigner signer = new EnvelopeSigner(codec);
        return signer.sign(unsigned, issuerPrivKey);
    }

    public record RecipientInfo(UUID verifierId, byte[] verifierKeyId, byte[] encPublicKey) {}
}
