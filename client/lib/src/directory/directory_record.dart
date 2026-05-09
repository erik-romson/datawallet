import 'dart:typed_data';

/// A single root signature in a [DirectoryRecord].
class RootSignature {
  final Uint8List rootKeyId;   // 16 bytes
  final Uint8List signature;   // 64 bytes (Ed25519)

  const RootSignature({required this.rootKeyId, required this.signature});
}

/// A directory record describing a verifier, issuer, or intermediate key.
class DirectoryRecord {
  final int version;
  final String recordType;      // "verifier" | "issuer" | "intermediate"
  final Uint8List subjectId;    // 16 bytes
  final Uint8List keyId;        // 16 bytes
  final Uint8List publicKey;    // 32 bytes (Ed25519 or X25519)
  final String keyUse;          // "enc" | "auth" | "sign"
  final String status;          // "active" | "superseded" | "revoked"
  final int validFrom;          // Unix epoch ms (inclusive)
  final int validUntil;         // Unix epoch ms (exclusive)
  final int issuedAt;           // Unix epoch ms
  final List<RootSignature> rootSignatures;   // non-empty when root-signed
  final Uint8List? parentKeyId;               // non-null when intermediate-signed
  final Uint8List? parentSignature;           // non-null when intermediate-signed

  const DirectoryRecord({
    required this.version,
    required this.recordType,
    required this.subjectId,
    required this.keyId,
    required this.publicKey,
    required this.keyUse,
    required this.status,
    required this.validFrom,
    required this.validUntil,
    required this.issuedAt,
    required this.rootSignatures,
    this.parentKeyId,
    this.parentSignature,
  });
}

/// A single root key entry inside a [PinnedRoot].
class RootEntry {
  final Uint8List rootKeyId;  // 16 bytes
  final Uint8List publicKey;  // 32 bytes (Ed25519)
  final int validFrom;        // Unix epoch ms (inclusive)
  final int validUntil;       // Unix epoch ms (exclusive)

  const RootEntry({
    required this.rootKeyId,
    required this.publicKey,
    required this.validFrom,
    required this.validUntil,
  });
}

/// The pinned trust anchor, loaded once at application startup.
class PinnedRoot {
  final int version;
  final String scheme;     // "ed25519-quorum-v1"
  final int threshold;     // minimum valid signatures required
  final List<RootEntry> roots;

  const PinnedRoot({
    required this.version,
    required this.scheme,
    required this.threshold,
    required this.roots,
  });
}
