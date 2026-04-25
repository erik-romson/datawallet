package com.wilhelmsen.cbslink.plugin.datawallet.api.verifier;

public class HandleReserved extends RuntimeException {

    public HandleReserved(String handle) {
        super("Handle is reserved: " + handle);
    }
}
