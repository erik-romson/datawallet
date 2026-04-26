package com.erikromson.datawallet.api.verifier;

import java.text.Normalizer;
import java.util.Set;
import java.util.regex.Pattern;

public final class HandleValidator {

    private static final Pattern HANDLE_REGEX =
            Pattern.compile("^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$");

    private static final Set<String> RESERVED = Set.of(
            "admin", "root", "system", "wallet", "operator", "support", "null", "undefined"
    );

    private HandleValidator() {}

    public static void validate(String handle) {
        if (handle == null || !HANDLE_REGEX.matcher(handle).matches()) {
            throw new HandleInvalid("Handle does not match required format");
        }

        if (!Normalizer.normalize(handle, Normalizer.Form.NFC).equals(handle)) {
            throw new HandleInvalid("Handle is not NFC-normalized");
        }

        if (handle.startsWith("_") || RESERVED.contains(handle)) {
            throw new HandleReserved(handle);
        }
    }
}
