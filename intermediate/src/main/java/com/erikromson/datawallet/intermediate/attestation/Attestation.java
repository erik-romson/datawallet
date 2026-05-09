package com.erikromson.datawallet.intermediate.attestation;

import java.util.Map;
import java.util.UUID;

public interface Attestation {

    Result verify(String token, UUID installUuid);

    record Result(
            boolean accepted,
            String rejectionCode,
            Map<String, String> capturedFields
    ) {
        public static Result ok() {
            return new Result(true, null, Map.of());
        }

        public static Result reject(String code) {
            return new Result(false, code, Map.of());
        }
    }
}
