package com.erikromson.datawallet.intermediate.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class DataWalletAdminClient {

    private static final Logger log = LoggerFactory.getLogger(DataWalletAdminClient.class);
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final String serverBaseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper json;

    public DataWalletAdminClient(String serverBaseUrl) {
        this.serverBaseUrl = serverBaseUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .build();
        this.json = new ObjectMapper();
    }

    protected DataWalletAdminClient(String serverBaseUrl, HttpClient httpClient) {
        this.serverBaseUrl = serverBaseUrl;
        this.httpClient = httpClient;
        this.json = new ObjectMapper();
    }

    public void publishDirectoryRecord(byte[] signedRecordCbor) {
        URI uri = URI.create(serverBaseUrl + "/v1/admin/directory");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/cbor")
                .timeout(TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofByteArray(signedRecordCbor))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new PublishFailedException("Failed to publish directory record", e);
        }

        if (response.statusCode() == 409) {
            throw new RecordStaleException("Server returned 409: " + response.body());
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new PublishFailedException(
                    "Server returned " + response.statusCode() + ": " + response.body());
        }
    }

    public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) {
        URI uri = URI.create(serverBaseUrl + "/v1/directory/issuers/" + installUuid);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new ServerUnavailableException("Failed to fetch issuer record", e);
        }

        if (response.statusCode() == 404) {
            return Optional.empty();
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new ServerUnavailableException(
                    "Server returned " + response.statusCode() + " for issuer lookup");
        }

        try {
            DirectoryEnvelope envelope = json.readValue(response.body(), DirectoryEnvelope.class);
            if (envelope.records() == null || envelope.records().isEmpty()) {
                return Optional.empty();
            }
            DirectoryRecordDto first = envelope.records().getFirst();
            byte[] signedRecord = B64URL_DEC.decode(first.signedRecord());
            return Optional.of(new IssuerRecord(
                    B64URL_DEC.decode(first.keyId()),
                    first.status(),
                    signedRecord
            ));
        } catch (Exception e) {
            throw new ServerUnavailableException("Failed to parse issuer record response", e);
        }
    }

    public ActiveIssuerPage getActiveIssuers(String cursor, int limit) {
        String path = "/v1/admin/directory/active-issuers?limit=" + limit;
        if (cursor != null) {
            path += "&cursor=" + cursor;
        }
        URI uri = URI.create(serverBaseUrl + path);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new ServerUnavailableException("Failed to fetch active issuers", e);
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new ServerUnavailableException(
                    "Server returned " + response.statusCode() + " for active issuers");
        }

        try {
            return json.readValue(response.body(), ActiveIssuerPage.class);
        } catch (Exception e) {
            throw new ServerUnavailableException("Failed to parse active issuers response", e);
        }
    }

    public List<ActiveIssuer> getAllActiveIssuers(int pageSize) {
        List<ActiveIssuer> all = new ArrayList<>();
        String cursor = null;
        do {
            ActiveIssuerPage page = getActiveIssuers(cursor, pageSize);
            all.addAll(page.items());
            cursor = page.nextCursor();
        } while (cursor != null);
        return all;
    }

    public List<RevokedIssuer> getRevokedIssuers() {
        URI uri = URI.create(serverBaseUrl + "/v1/admin/directory/revoked-issuers");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new ServerUnavailableException("Failed to fetch revoked issuers", e);
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new ServerUnavailableException(
                    "Server returned " + response.statusCode() + " for revoked issuers");
        }

        try {
            return List.of(json.readValue(response.body(), RevokedIssuer[].class));
        } catch (Exception e) {
            throw new ServerUnavailableException("Failed to parse revoked issuers response", e);
        }
    }

    public record ActiveIssuer(
            @JsonProperty("subject_id") String subjectId,
            @JsonProperty("key_id") String keyId,
            @JsonProperty("valid_from") long validFrom,
            @JsonProperty("valid_until") long validUntil,
            @JsonProperty("issued_at") long issuedAt,
            @JsonProperty("signed_record") String signedRecord
    ) {}

    public record ActiveIssuerPage(
            List<ActiveIssuer> items,
            @JsonProperty("next_cursor") String nextCursor
    ) {}

    public record IssuerRecord(byte[] keyId, String status, byte[] signedRecord) {}

    public record RevokedIssuer(
            @JsonProperty("install_uuid") String installUuid,
            @JsonProperty("key_id") String keyId
    ) {}

    record DirectoryEnvelope(@JsonProperty("records") List<DirectoryRecordDto> records) {}

    record DirectoryRecordDto(
            @JsonProperty("key_id") String keyId,
            @JsonProperty("status") String status,
            @JsonProperty("signed_record") String signedRecord
    ) {}

    public static final class PublishFailedException extends RuntimeException {
        public PublishFailedException(String message) { super(message); }
        public PublishFailedException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class RecordStaleException extends RuntimeException {
        public RecordStaleException(String message) { super(message); }
    }

    public static final class ServerUnavailableException extends RuntimeException {
        public ServerUnavailableException(String message) { super(message); }
        public ServerUnavailableException(String message, Throwable cause) { super(message, cause); }
    }
}
