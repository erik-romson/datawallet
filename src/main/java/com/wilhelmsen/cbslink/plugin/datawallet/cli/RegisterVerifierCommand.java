package com.wilhelmsen.cbslink.plugin.datawallet.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Argon2id;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.CanonicalCborMapper;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Ed25519;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.Random;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.SecretBox;
import com.wilhelmsen.cbslink.plugin.datawallet.crypto.X25519;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

/// Registers a verifier on the running server, performing the same client-side
/// crypto the Flutter app would do at sign-up time:
///   X25519+Ed25519 keypairs, Argon2id KEK at the native floor (m=256 MiB, t=3),
///   secretbox-wrapped private keys in canonical CBOR, then POST /v1/verifiers.
@Component
@Profile("cli")
@Command(
        name = "register-verifier",
        description = "Register a new verifier (handle + password) on the server",
        mixinStandardHelpOptions = true
)
public class RegisterVerifierCommand implements Callable<Integer> {

    private static final long KDF_M_NATIVE = 268_435_456L;
    private static final long KDF_T = 3L;
    private static final int KDF_P = 1;
    private static final int KDF_VERSION = 19;
    private static final Pattern HANDLE_RE = Pattern.compile("^[a-z0-9_-]{3,32}$");
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Option(names = "--url", defaultValue = "http://localhost:8443",
            description = "Server URL (default: ${DEFAULT-VALUE})")
    String url;

    @Option(names = "--handle", required = true, description = "Verifier handle (lowercase, 3-32 chars)")
    String handle;

    @Option(names = "--display-name", description = "Optional display name (defaults to handle)")
    String displayName;

    @Option(names = "--password", defaultValue = "devpassword",
            description = "Password (default: ${DEFAULT-VALUE} for dev)",
            interactive = true, arity = "0..1")
    char[] password;

    @Override
    public Integer call() throws Exception {
        if (!HANDLE_RE.matcher(handle).matches()) {
            System.err.println("Handle must match ^[a-z0-9_-]{3,32}$");
            return 2;
        }

        System.out.println("Generating keypairs...");
        byte[] encSeed = Random.bytes(32);
        byte[] authSeed = Random.bytes(32);
        X25519.KeyPair encKp = X25519.seedKeypair(encSeed);
        Ed25519.KeyPair authKp = Ed25519.seedKeypair(authSeed);

        byte[] encKeyId = Random.bytes(16);
        byte[] authKeyId = Random.bytes(16);
        byte[] salt = Random.bytes(16);

        System.out.println("Deriving Argon2id KEK (m=256 MiB, t=3) — this takes a few seconds...");
        byte[] kek = Argon2id.deriveKek(new String(password), salt, KDF_M_NATIVE, KDF_T, KDF_P);

        System.out.println("Wrapping private keys...");
        byte[] wrappedEnc = wrap(encKp.secretKey(), kek);
        byte[] wrappedAuth = wrap(authKp.privateKey(), kek);

        // Best-effort zeroing
        java.util.Arrays.fill(kek, (byte) 0);
        java.util.Arrays.fill(encKp.secretKey(), (byte) 0);
        java.util.Arrays.fill(authKp.privateKey(), (byte) 0);
        java.util.Arrays.fill(password, '\0');

        Map<String, Object> kdfParams = new LinkedHashMap<>();
        kdfParams.put("alg", "argon2id");
        kdfParams.put("m", KDF_M_NATIVE);
        kdfParams.put("t", KDF_T);
        kdfParams.put("p", KDF_P);
        kdfParams.put("version", KDF_VERSION);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("handle", handle);
        body.put("display_name", displayName != null ? displayName : handle);
        body.put("enc_public_key", B64URL.encodeToString(encKp.publicKey()));
        body.put("enc_key_id", B64URL.encodeToString(encKeyId));
        body.put("auth_public_key", B64URL.encodeToString(authKp.publicKey()));
        body.put("auth_key_id", B64URL.encodeToString(authKeyId));
        body.put("wrapped_enc_private_key_blob", B64URL.encodeToString(wrappedEnc));
        body.put("wrapped_auth_private_key_blob", B64URL.encodeToString(wrappedAuth));
        body.put("kdf_salt", B64URL.encodeToString(salt));
        body.put("kdf_params", kdfParams);
        body.put("client_password_score", 3);

        ObjectMapper json = new ObjectMapper();
        String requestBody = json.writeValueAsString(body);

        System.out.println("POST " + url + "/v1/verifiers");
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url + "/v1/verifiers"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println("Status: " + resp.statusCode());
        System.out.println(resp.body());
        if (resp.statusCode() != 200 && resp.statusCode() != 201) {
            return 1;
        }

        JsonNode respJson = json.readTree(resp.body());
        JsonNode verifierIdNode = respJson.get("verifier_id");
        if (verifierIdNode != null) {
            System.out.println();
            System.out.println("Registered verifier handle=\"" + handle + "\" id="
                    + verifierIdNode.asText());
        }
        return 0;
    }

    /// Wraps `plaintext` with `kek` using a fresh nonce, encoded as canonical CBOR
    /// matching `crypto-formats.md §3` (field order: v, ct, alg, nonce).
    private static byte[] wrap(byte[] plaintext, byte[] kek) {
        byte[] nonce = Random.bytes(24);
        byte[] ct = SecretBox.seal(plaintext, nonce, kek);
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("v", 1);
        map.put("ct", ct);
        map.put("alg", "secretbox");
        map.put("nonce", nonce);
        return new CanonicalCborMapper().writeBytes(map);
    }
}
