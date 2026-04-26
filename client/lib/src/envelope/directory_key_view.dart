import 'dart:typed_data';

/// A resolved issuer signing key from the directory.
class DirectoryKeyView {
  final Uint8List issuerId;   // 16 bytes
  final Uint8List keyId;      // 16 bytes
  final Uint8List publicKey;  // 32 bytes (Ed25519)
  final String status;
  final int validFrom;        // Unix epoch ms (inclusive)
  final int validUntil;       // Unix epoch ms (exclusive)

  const DirectoryKeyView({
    required this.issuerId,
    required this.keyId,
    required this.publicKey,
    required this.status,
    required this.validFrom,
    required this.validUntil,
  });
}
