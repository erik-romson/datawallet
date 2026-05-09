package com.erikromson.datawallet.security;

public class BearerRejection extends RuntimeException {

    public BearerRejection(String message) {
        super(message);
    }

    public BearerRejection(String message, Throwable cause) {
        super(message, cause);
    }
}
