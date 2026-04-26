package com.erikromson.datawallet.api.shared;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SharedListDto(
        @JsonProperty("items") List<Item> items,
        @JsonProperty("next_cursor") String nextCursor
) {
    public record Item(
            @JsonProperty("entry_id") String entryId,
            @JsonProperty("issuer_id") String issuerId,
            @JsonProperty("issuer_label") String issuerLabel,
            @JsonProperty("issuer_signing_key_id") String issuerSigningKeyId,
            @JsonProperty("created_at") String createdAt,
            @JsonProperty("description") String description
    ) {}
}
