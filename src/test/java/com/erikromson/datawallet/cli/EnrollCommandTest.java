package com.erikromson.datawallet.cli;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/// Pure unit test — no Spring context needed.
/// Uses the JDK's built-in HttpServer to stub the intermediate /enroll endpoint.
class EnrollCommandTest {

    @TempDir
    Path stateDir;

    HttpServer server;
    int port;

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void happyPathWritesFilesAndPrintsUuid() throws Exception {
        byte[] fakeRecord = {1, 2, 3, 4, 5};
        String b64Record = Base64.getUrlEncoder().withoutPadding().encodeToString(fakeRecord);
        String responseBody = "{\"signed_record\":\"" + b64Record + "\",\"token_url\":\"/token\"}";

        server.createContext("/enroll", exchange -> {
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });

        EnrollCommand cmd = new EnrollCommand();
        cmd.intermediateUrl = "http://localhost:" + port;
        cmd.stateDir = stateDir.toFile();
        cmd.passphrase = "testpass".toCharArray();

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
        assertThat(stateDir.resolve("install.privkey.box")).exists();
        assertThat(stateDir.resolve("install.signed_record.cbor")).exists();
        assertThat(Files.readAllBytes(stateDir.resolve("install.signed_record.cbor")))
                .isEqualTo(fakeRecord);
        // stdout must be a single UUID line
        assertThat(baos.toString().trim())
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    @Test
    void serverErrorLeavesNoStateFiles() throws Exception {
        server.createContext("/enroll", exchange -> {
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });

        EnrollCommand cmd = new EnrollCommand();
        cmd.intermediateUrl = "http://localhost:" + port;
        cmd.stateDir = stateDir.toFile();
        cmd.passphrase = "testpass".toCharArray();

        int exitCode = cmd.call();

        assertThat(exitCode).isNotEqualTo(0);
        assertThat(stateDir.resolve("install.privkey.box")).doesNotExist();
        assertThat(stateDir.resolve("install.signed_record.cbor")).doesNotExist();
    }
}
