package com.erikromson.datawallet.security;

import com.erikromson.datawallet.crypto.Ed25519;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

public final class BearerJwtVerifier {

    private static final int MAX_SEGMENT_BYTES = 8192;
    private static final Duration DEFAULT_SKEW = Duration.ofSeconds(60);
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(5);
    private static final String ISS_PREFIX = "urn:datawallet:issuer:";
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

    private final Clock clock;
    private final Duration skew;
    private final ObjectMapper mapper;

    public BearerJwtVerifier(Clock clock, Duration skew) {
        this.clock = clock;
        this.skew = skew;
        this.mapper = new ObjectMapper();
        this.mapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
    }

    public BearerJwtVerifier(Clock clock) {
        this(clock, DEFAULT_SKEW);
    }

    public BearerClaims verify(String bearer, String expectedAudience, byte[] intermediatePublicKey) {
        String[] parts = bearer.split("\\.", -1);
        if (parts.length != 3) {
            throw new BearerRejection("JWT must have exactly 3 segments");
        }

        for (String part : parts) {
            if (part.length() > MAX_SEGMENT_BYTES) {
                throw new BearerRejection("JWT segment exceeds 8KB limit");
            }
        }

        rejectNonCanonicalBase64url(parts[0]);
        rejectNonCanonicalBase64url(parts[1]);

        byte[] headerBytes = decodeSegment(parts[0]);
        byte[] payloadBytes = decodeSegment(parts[1]);
        byte[] signature = decodeSegment(parts[2]);

        JsonNode header = parseJson(headerBytes);
        JsonNode payload = parseJson(payloadBytes);

        validateHeader(header);
        BearerClaims claims = validatePayload(payload, expectedAudience);

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);

        if (!Ed25519.verifyDetached(intermediatePublicKey, signingInput, signature)) {
            throw new BearerRejection("JWT signature verification failed");
        }

        return claims;
    }

    private void rejectNonCanonicalBase64url(String segment) {
        if (segment.contains("=")) {
            throw new BearerRejection("Non-canonical base64url: padding characters present");
        }
        if (segment.contains("+") || segment.contains("/")) {
            throw new BearerRejection("Non-canonical base64url: standard base64 characters present");
        }
    }

    private byte[] decodeSegment(String segment) {
        try {
            return B64URL.decode(segment);
        } catch (IllegalArgumentException e) {
            throw new BearerRejection("Invalid base64url encoding", e);
        }
    }

    private JsonNode parseJson(byte[] bytes) {
        try {
            return mapper.readTree(bytes);
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("Duplicate")) {
                throw new BearerRejection("Duplicate JSON keys detected", e);
            }
            throw new BearerRejection("Invalid JSON in JWT segment", e);
        }
    }

    private void validateHeader(JsonNode header) {
        JsonNode algNode = header.get("alg");
        if (algNode == null) {
            throw new BearerRejection("Missing required header: alg");
        }
        if (!algNode.isTextual()) {
            throw new BearerRejection("Header 'alg' must be a string");
        }
        if (!"EdDSA".equals(algNode.asText())) {
            throw new BearerRejection("Unsupported algorithm: " + algNode.asText() + "; only EdDSA is accepted");
        }

        JsonNode typNode = header.get("typ");
        if (typNode != null) {
            if (!typNode.isTextual()) {
                throw new BearerRejection("Header 'typ' must be a string");
            }
            if (!"JWT".equals(typNode.asText())) {
                throw new BearerRejection("Unsupported typ: " + typNode.asText() + "; only JWT is accepted");
            }
        }

        if (header.has("cty")) {
            throw new BearerRejection("Header 'cty' is not allowed");
        }

        Set<String> allowedHeaders = Set.of("alg", "typ", "kid");
        Iterator<String> fieldNames = header.fieldNames();
        while (fieldNames.hasNext()) {
            String field = fieldNames.next();
            if (!allowedHeaders.contains(field)) {
                throw new BearerRejection("Unexpected header field: " + field);
            }
        }
    }

    private BearerClaims validatePayload(JsonNode payload, String expectedAudience) {
        JsonNode issNode = requireString(payload, "iss");
        JsonNode audNode = requireString(payload, "aud");
        JsonNode expNode = requireInteger(payload, "exp");
        JsonNode iatNode = requireInteger(payload, "iat");

        JsonNode nbfNode = payload.get("nbf");
        if (nbfNode != null && !nbfNode.isIntegralNumber()) {
            throw new BearerRejection("Claim 'nbf' must be a JSON integer");
        }

        JsonNode cnfNode = payload.get("cnf");
        if (cnfNode == null || !cnfNode.isObject()) {
            throw new BearerRejection("Missing or invalid 'cnf' claim");
        }
        JsonNode jktNode = cnfNode.get("jkt");
        if (jktNode == null || !jktNode.isTextual()) {
            throw new BearerRejection("Missing or invalid 'cnf.jkt' claim");
        }

        String iss = issNode.asText();
        if (!iss.startsWith(ISS_PREFIX)) {
            throw new BearerRejection("Invalid iss prefix: expected " + ISS_PREFIX);
        }
        UUID installUuid;
        try {
            installUuid = UUID.fromString(iss.substring(ISS_PREFIX.length()));
        } catch (IllegalArgumentException e) {
            throw new BearerRejection("Invalid UUID in iss claim", e);
        }

        String aud = audNode.asText();
        if (!expectedAudience.equals(aud)) {
            throw new BearerRejection("Audience mismatch: expected " + expectedAudience + ", got " + aud);
        }

        long expSec = expNode.asLong();
        long iatSec = iatNode.asLong();
        long nowSec = clock.millis() / 1000;

        if (nbfNode != null) {
            long nbfSec = nbfNode.asLong();
            if (nowSec + skew.toSeconds() < nbfSec) {
                throw new BearerRejection("Token not yet valid (nbf)");
            }
        }

        if (nowSec - skew.toSeconds() > expSec) {
            throw new BearerRejection("Token expired");
        }

        long lifetimeSec = expSec - iatSec;
        if (lifetimeSec > MAX_LIFETIME.toSeconds()) {
            throw new BearerRejection("Token lifetime exceeds 5 minutes: " + lifetimeSec + "s");
        }

        String jkt = jktNode.asText();

        return new BearerClaims(installUuid, jkt, expSec * 1000);
    }

    private JsonNode requireString(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        if (node == null) {
            throw new BearerRejection("Missing required claim: " + field);
        }
        if (!node.isTextual()) {
            throw new BearerRejection("Claim '" + field + "' must be a JSON string");
        }
        return node;
    }

    private JsonNode requireInteger(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        if (node == null) {
            throw new BearerRejection("Missing required claim: " + field);
        }
        if (!node.isIntegralNumber()) {
            throw new BearerRejection("Claim '" + field + "' must be a JSON integer");
        }
        return node;
    }
}
