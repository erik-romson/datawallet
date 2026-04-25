package com.wilhelmsen.cbslink.plugin.datawallet.crypto;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;

public final class CryptoProvider {

    private static final LazySodiumJava INSTANCE = new LazySodiumJava(new SodiumJava());

    private CryptoProvider() {}

    public static LazySodiumJava lazySodium() {
        return INSTANCE;
    }

    public static SodiumJava sodium() {
        return (SodiumJava) INSTANCE.getSodium();
    }
}
