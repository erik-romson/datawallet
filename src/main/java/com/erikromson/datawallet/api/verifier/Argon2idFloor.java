package com.erikromson.datawallet.api.verifier;

public final class Argon2idFloor {

    static final long NATIVE_M_FLOOR = 268_435_456L;
    static final long WEB_M_FLOOR = 67_108_864L;
    static final int MIN_T = 3;
    static final int REQUIRED_P = 1;
    static final int REQUIRED_VERSION = 19;

    private Argon2idFloor() {}

    public static void enforce(KdfParams params, boolean webOrigin) {
        if (!"argon2id".equals(params.alg())) {
            throw new KdfBelowFloor("alg must be argon2id");
        }
        if (params.version() != REQUIRED_VERSION) {
            throw new KdfBelowFloor("version must be " + REQUIRED_VERSION);
        }
        if (params.t() < MIN_T) {
            throw new KdfBelowFloor("t must be >= " + MIN_T);
        }
        if (params.p() != REQUIRED_P) {
            throw new KdfBelowFloor("p must be " + REQUIRED_P);
        }

        long mFloor = webOrigin ? WEB_M_FLOOR : NATIVE_M_FLOOR;
        if (params.m() < mFloor) {
            throw new KdfBelowFloor("m must be >= " + mFloor + (webOrigin ? " (web)" : " (native)"));
        }
    }
}
