package com.erikromson.datawallet.api.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        @JsonProperty("error") ErrorBody error,
        @JsonProperty("trace_id") String traceId
) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ErrorBody(
            @JsonProperty("code") String code,
            @JsonProperty("message") String message,
            @JsonProperty("details") Map<String, Object> details
    ) {}

    public static ApiError of(String code, String message, String traceId) {
        return new ApiError(new ErrorBody(code, message, null), traceId);
    }

    public static ApiError of(String code, String message, Map<String, Object> details, String traceId) {
        return new ApiError(new ErrorBody(code, message, details), traceId);
    }
}
