package com.wilhelmsen.cbslink.plugin.datawallet.directory;

public sealed class DirectoryRejection extends RuntimeException {

    DirectoryRejection(String message) {
        super(message);
    }

    DirectoryRejection(String message, Throwable cause) {
        super(message, cause);
    }

    public static final class MalformedCbor extends DirectoryRejection {
        public MalformedCbor(String message) { super(message); }
        public MalformedCbor(String message, Throwable cause) { super(message, cause); }
    }

    public static final class UnsupportedVersion extends DirectoryRejection {
        public UnsupportedVersion(int version) {
            super("Unsupported directory record version: " + version);
        }
    }

    public static final class InvalidRecordType extends DirectoryRejection {
        public InvalidRecordType(String type) {
            super("Invalid record_type: " + type);
        }
    }

    public static final class InvalidKeyUse extends DirectoryRejection {
        public InvalidKeyUse(String use) {
            super("Invalid key_use: " + use);
        }
    }

    public static final class InvalidStatus extends DirectoryRejection {
        public InvalidStatus(String status) {
            super("Invalid status: " + status);
        }
    }

    public static final class FreshnessExpired extends DirectoryRejection {
        public FreshnessExpired(String detail) {
            super(detail);
        }
    }

    public static final class QuorumBelowThreshold extends DirectoryRejection {
        public QuorumBelowThreshold(int valid, int threshold) {
            super("Quorum below threshold: " + valid + " valid signatures, " + threshold + " required");
        }
    }

    public static final class SignatureInvalid extends DirectoryRejection {
        public SignatureInvalid(String detail) {
            super(detail);
        }
    }

    public static final class RootKeyNotFound extends DirectoryRejection {
        public RootKeyNotFound(String detail) {
            super(detail);
        }
    }

    public static final class RootKeyExpired extends DirectoryRejection {
        public RootKeyExpired(String detail) {
            super(detail);
        }
    }
}
