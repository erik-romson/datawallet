package com.wilhelmsen.cbslink.plugin.datawallet.envelope;

public sealed class EnvelopeRejection extends RuntimeException {

    EnvelopeRejection(String message) {
        super(message);
    }

    EnvelopeRejection(String message, Throwable cause) {
        super(message, cause);
    }

    public static final class MalformedCbor extends EnvelopeRejection {
        public MalformedCbor(String message) { super(message); }
        public MalformedCbor(String message, Throwable cause) { super(message, cause); }
    }

    public static final class UnsupportedVersion extends EnvelopeRejection {
        public UnsupportedVersion(int version) {
            super("Unsupported envelope version: " + version);
        }
    }

    public static final class SignatureInvalid extends EnvelopeRejection {
        public SignatureInvalid() { super("Envelope signature verification failed"); }
    }

    public static final class IssuerKeyNotActiveAt extends EnvelopeRejection {
        public IssuerKeyNotActiveAt(String detail) { super(detail); }
    }

    public static final class CiphertextHashMismatch extends EnvelopeRejection {
        public CiphertextHashMismatch() { super("SHA-256 of ciphertext does not match ciphertext_hash"); }
    }

    public static final class RecipientNotPresent extends EnvelopeRejection {
        public RecipientNotPresent(String detail) { super(detail); }
    }
}
