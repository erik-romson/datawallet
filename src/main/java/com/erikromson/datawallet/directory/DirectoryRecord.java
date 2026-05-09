package com.erikromson.datawallet.directory;

import java.util.List;

public record DirectoryRecord(
        int version,
        String recordType,
        byte[] subjectId,
        byte[] keyId,
        byte[] publicKey,
        String keyUse,
        String status,
        long validFrom,
        long validUntil,
        long issuedAt,
        List<RootSignature> rootSignatures,  // non-null, empty when parent-signed
        byte[] parentKeyId,                   // null when root-signed
        byte[] parentSignature               // null when root-signed
) {}
