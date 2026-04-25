package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

public class KdfBelowFloor extends RuntimeException {

    public KdfBelowFloor(String message) {
        super(message);
    }
}
