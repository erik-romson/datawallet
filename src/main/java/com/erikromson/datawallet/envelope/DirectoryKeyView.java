package com.erikromson.datawallet.envelope;

import java.util.UUID;

public record DirectoryKeyView(
        UUID subjectId,
        byte[] keyId,
        byte[] publicKey,
        String status,
        long validFrom,
        long validUntil
) {}
