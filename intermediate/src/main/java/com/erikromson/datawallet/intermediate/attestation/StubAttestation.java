package com.erikromson.datawallet.intermediate.attestation;

import java.util.UUID;

public class StubAttestation implements Attestation {

    @Override
    public Result verify(String token, UUID installUuid) {
        return Result.ok();
    }
}
