package com.erikromson.datawallet.api.verifier;

public class HandleInvalid extends RuntimeException {

    public HandleInvalid(String message) {
        super(message);
    }
}
