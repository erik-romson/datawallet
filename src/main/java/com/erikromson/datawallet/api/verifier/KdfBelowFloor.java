package com.erikromson.datawallet.api.verifier;

public class KdfBelowFloor extends RuntimeException {

    public KdfBelowFloor(String message) {
        super(message);
    }
}
