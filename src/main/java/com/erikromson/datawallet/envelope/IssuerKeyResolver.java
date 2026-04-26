package com.erikromson.datawallet.envelope;

import java.util.Optional;
import java.util.UUID;

public interface IssuerKeyResolver {

    Optional<DirectoryKeyView> resolve(UUID issuerId, byte[] keyId, long atMs);
}
