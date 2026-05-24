package com.erikromson.datawallet.api.verifier;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerifierListDto(
        @JsonProperty("items") List<Item> items,
        @JsonProperty("next_cursor") String nextCursor
) {
    public record Item(
            @JsonProperty("verifier_id") String verifierId,
            @JsonProperty("handle") String handle,
            @JsonProperty("display_name") String displayName,
            @JsonProperty("enc_key_id") String encKeyId,
            @JsonProperty("key_fingerprint") String keyFingerprint,
            @JsonProperty("created_at") String createdAt
    ) {}
}
