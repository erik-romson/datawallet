package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

import java.util.UUID;

public record RecipientWrapping(UUID verifierId, byte[] verifierKeyId, byte[] wrappedDataKey) {}
