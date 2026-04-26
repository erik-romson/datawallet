package com.erikromson.datawallet.cli;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;

@Component
@Profile("cli")
@Command(
        name = "upload-envelope",
        description = "POST a signed CBOR envelope to the wallet server",
        mixinStandardHelpOptions = true
)
public class UploadEnvelopeCommand implements Callable<Integer> {

    @Option(names = "--url", required = true, description = "Server URL for POST /v1/entries")
    String url;

    @Option(names = "--client-cert", description = "PEM client certificate file for mTLS")
    File clientCertFile;

    @Option(names = "--client-key", description = "DER-encoded PKCS#8 client private key for mTLS")
    File clientKeyFile;

    @Parameters(index = "0", description = "CBOR envelope file to upload")
    File envelopeFile;

    @Override
    public Integer call() throws Exception {
        byte[] envelopeBytes = Files.readAllBytes(envelopeFile.toPath());

        HttpClient client;
        if (clientCertFile != null && clientKeyFile != null) {
            SSLContext sslContext = buildMtlsContext(clientCertFile, clientKeyFile);
            client = HttpClient.newBuilder().sslContext(sslContext).build();
        } else {
            client = HttpClient.newHttpClient();
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/cbor")
                .POST(HttpRequest.BodyPublishers.ofByteArray(envelopeBytes))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());

        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            System.err.println("Server returned HTTP " + status);
            return 1;
        }
        return 0;
    }

    private static SSLContext buildMtlsContext(File certFile, File keyFile) throws Exception {
        // Parse PEM certificate (strip headers, base64-decode)
        String certPem = Files.readString(certFile.toPath());
        byte[] certDer = decodePem(certPem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certDer));

        // Parse PKCS#8 DER private key
        byte[] keyDer = Files.readAllBytes(keyFile.toPath());
        // If it looks like PEM, strip headers
        String keyString = new String(keyDer);
        if (keyString.contains("-----")) {
            keyDer = decodePem(keyString);
        }
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyDer);
        PrivateKey privateKey = tryLoadPrivateKey(keySpec);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", privateKey, new char[0], new Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        return sslContext;
    }

    private static byte[] decodePem(String pem) {
        String stripped = pem
                .replaceAll("-----[^-]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(stripped);
    }

    private static PrivateKey tryLoadPrivateKey(PKCS8EncodedKeySpec spec) throws Exception {
        for (String alg : List.of("EC", "RSA", "EdDSA")) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (Exception ignored) {}
        }
        throw new IllegalArgumentException("Could not determine key algorithm from PKCS#8 DER");
    }
}
