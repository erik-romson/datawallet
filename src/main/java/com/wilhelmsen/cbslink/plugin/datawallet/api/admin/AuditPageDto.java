package com.wilhelmsen.cbslink.plugin.datawallet.api.admin;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuditPageDto(
        @JsonProperty("items") List<AuditItemDto> items,
        @JsonProperty("head") ChainHeadDto head
) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuditItemDto(
            @JsonProperty("seq") long seq,
            @JsonProperty("ts") String ts,
            @JsonProperty("event_type") String eventType,
            @JsonProperty("actor_id") String actorId,
            @JsonProperty("entry_id") String entryId,
            @JsonProperty("payload") Map<String, Object> payload,
            @JsonProperty("hash") String hash
    ) {}

    public record ChainHeadDto(
            @JsonProperty("seq") long seq,
            @JsonProperty("hash") String hash
    ) {}

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    public static String encodeHash(byte[] hash) {
        return hash == null ? null : B64URL.encodeToString(hash);
    }
}
