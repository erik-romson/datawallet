package com.wilhelmsen.cbslink.plugin.datawallet.crypto;

public class CanonicalCborException extends RuntimeException {

    public CanonicalCborException(String message) {
        super(message);
    }

    public CanonicalCborException(String message, Throwable cause) {
        super(message, cause);
    }
}
