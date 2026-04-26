package com.erikromson.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.erikromson.datawallet.api.auth.AuthController;
import com.erikromson.datawallet.crypto.Argon2id;
import com.erikromson.datawallet.crypto.CanonicalCborMapper;
import com.erikromson.datawallet.crypto.Ed25519;
import com.erikromson.datawallet.crypto.SealedBox;
import com.erikromson.datawallet.crypto.SecretBox;
import com.erikromson.datawallet.envelope.EnvelopeCodec;
import com.erikromson.datawallet.envelope.RecipientWrapping;
import com.erikromson.datawallet.envelope.SharedEnvelope;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/// Verifier-side CLI: log in, list shared entries, optionally decrypt one.
///
/// Mirrors what the Flutter app does at login time: derives the Argon2id KEK
/// locally, unwraps the auth + enc private keys, signs the auth challenge,
/// and uses the resulting bearer token to call /v1/shared and /v1/shared/{id}.
/// With {@code --entry-id}, decrypts and prints the plaintext to stdout.
@Component
@Profile("cli")
@Command(
        name = "verifier-fetch",
        description = "Verifier login + list / decrypt entries",
        mixinStandardHelpOptions = true
)
public class VerifierFetchCommand implements Callable<Integer> {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    @Option(names = "--url", required = true, description = "Server URL")
    String url;

    @Option(names = "--handle", required = true, description = "Verifier handle")
    String handle;

    @Option(names = "--password",
            description = "Verifier password (prompted interactively if omitted)",
            interactive = true, arity = "0..1", required = true)
    char[] password;

    @Option(names = "--entry-id",
            description = "If set, decrypt this entry and print plaintext; otherwise list entry IDs")
    String entryIdArg;

    @Override
    public Integer call() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        ObjectMapper json = new ObjectMapper();

        // 1. fetch login blob
        HttpResponse<String> blobResp = http.send(
                HttpRequest.newBuilder(URI.create(url + "/v1/verifiers/" + handle + "/login-blob")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (blobResp.statusCode() != 200) {
            System.err.println("login-blob failed: HTTP " + blobResp.statusCode() + " " + blobResp.body());
            return 1;
        }
        JsonNode blob = json.readTree(blobResp.body());
        String verifierId = blob.get("verifier_id").asText();
        byte[] kdfSalt = b64urlDecode(blob.get("kdf_salt").asText());
        JsonNode kdfParams = blob.get("kdf_params");
        long m = kdfParams.get("m").asLong();
        int t = kdfParams.get("t").asInt();
        int p = kdfParams.get("p").asInt();
        byte[] wrappedEnc = b64urlDecode(blob.get("wrapped_enc_private_key_blob").asText());
        byte[] wrappedAuth = b64urlDecode(blob.get("wrapped_auth_private_key_blob").asText());

        // 2. derive KEK and unwrap private keys locally
        byte[] kek = Argon2id.deriveKek(new String(password), kdfSalt, m, t, p);
        Arrays.fill(password, '\0');
        byte[] encPrivKey;
        byte[] authPrivKey;
        try {
            encPrivKey = unwrap(wrappedEnc, kek);
            authPrivKey = unwrap(wrappedAuth, kek);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }

        // 3. challenge / verify → bearer token
        String challengeBody = json.writeValueAsString(Map.of("verifier_id", verifierId));
        HttpResponse<String> chResp = http.send(
                HttpRequest.newBuilder(URI.create(url + "/v1/auth/challenge"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(challengeBody)).build(),
                HttpResponse.BodyHandlers.ofString());
        if (chResp.statusCode() != 200) {
            System.err.println("challenge failed: HTTP " + chResp.statusCode() + " " + chResp.body());
            return 1;
        }
        byte[] nonce = b64urlDecode(json.readTree(chResp.body()).get("nonce").asText());

        byte[] toSign = new byte[AuthController.AUTH_PREFIX.length + nonce.length];
        System.arraycopy(AuthController.AUTH_PREFIX, 0, toSign, 0, AuthController.AUTH_PREFIX.length);
        System.arraycopy(nonce, 0, toSign, AuthController.AUTH_PREFIX.length, nonce.length);
        byte[] signature = Ed25519.signDetached(authPrivKey, toSign);

        Map<String, Object> verifyMap = new LinkedHashMap<>();
        verifyMap.put("verifier_id", verifierId);
        verifyMap.put("nonce", B64URL.encodeToString(nonce));
        verifyMap.put("signature", B64URL.encodeToString(signature));
        HttpResponse<String> vResp = http.send(
                HttpRequest.newBuilder(URI.create(url + "/v1/auth/verify"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(verifyMap))).build(),
                HttpResponse.BodyHandlers.ofString());
        Arrays.fill(authPrivKey, (byte) 0);
        if (vResp.statusCode() != 200) {
            System.err.println("verify failed: HTTP " + vResp.statusCode() + " " + vResp.body());
            return 1;
        }
        String token = json.readTree(vResp.body()).get("session_token").asText();

        // 4. either list entry IDs, or fetch + decrypt one
        if (entryIdArg == null) {
            return listEntries(http, token, json);
        }
        return decryptOne(http, token, encPrivKey, verifierId);
    }

    private int listEntries(HttpClient http, String token, ObjectMapper json) throws Exception {
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create(url + "/v1/shared"))
                        .header("Authorization", "Bearer " + token)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            System.err.println("list failed: HTTP " + resp.statusCode() + " " + resp.body());
            return 1;
        }
        JsonNode items = json.readTree(resp.body()).get("items");
        for (JsonNode item : items) {
            System.out.println(item.get("entry_id").asText());
        }
        return 0;
    }

    private int decryptOne(HttpClient http, String token, byte[] encPrivKey, String verifierId)
            throws Exception {
        HttpResponse<byte[]> resp = http.send(
                HttpRequest.newBuilder(URI.create(url + "/v1/shared/" + entryIdArg))
                        .header("Authorization", "Bearer " + token)
                        .header("Accept", "application/cbor")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200) {
            System.err.println("fetch failed: HTTP " + resp.statusCode());
            return 1;
        }

        SharedEnvelope envelope = new EnvelopeCodec().decode(resp.body());
        java.util.UUID myId = java.util.UUID.fromString(verifierId);
        RecipientWrapping mine = envelope.recipientWrappings().stream()
                .filter(rw -> rw.verifierId().equals(myId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No recipient wrapping for this verifier"));

        // Derive enc public key from secret key (libsodium derives pub from sec for X25519).
        byte[] encPubKey = derivePublicFromSecret(encPrivKey);
        byte[] dataKey = SealedBox.open(mine.wrappedDataKey(), encPubKey, encPrivKey);
        Arrays.fill(encPrivKey, (byte) 0);
        try {
            byte[] plain = SecretBox.open(envelope.ciphertext(), envelope.ciphertextNonce(), dataKey);
            System.out.println(new String(plain, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
        return 0;
    }

    /// X25519 public-from-secret via libsodium's scalarmult-base.
    private static byte[] derivePublicFromSecret(byte[] secret) {
        byte[] pub = new byte[32];
        int rc = com.erikromson.datawallet.crypto.CryptoProvider.sodium()
                .crypto_scalarmult_base(pub, secret);
        if (rc != 0) {
            throw new IllegalStateException("crypto_scalarmult_base failed");
        }
        return pub;
    }

    private static byte[] unwrap(byte[] wrappedCbor, byte[] kek) {
        @SuppressWarnings("unchecked")
        Map<String, Object> map = new CanonicalCborMapper().readValue(wrappedCbor, Map.class);
        byte[] ct = (byte[]) map.get("ct");
        byte[] nonce = (byte[]) map.get("nonce");
        return SecretBox.open(ct, nonce, kek);
    }

    private static byte[] b64urlDecode(String s) {
        // Handle padding-stripped base64url
        int padded = (4 - s.length() % 4) % 4;
        return B64URL_DEC.decode(s + "=".repeat(padded));
    }
}
