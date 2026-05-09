package com.erikromson.datawallet.intermediate.signer;

public interface Signer {

    byte[] sign(byte[] message);

    byte[] publicKey();

    byte[] keyId();
}
