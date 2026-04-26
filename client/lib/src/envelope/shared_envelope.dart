import 'dart:typed_data';

/// A single recipient's wrapped data key inside a [SharedEnvelope].
class RecipientWrapping {
  final Uint8List verifierId;      // 16 bytes
  final Uint8List verifierKeyId;   // 16 bytes
  final Uint8List wrappedDataKey;

  const RecipientWrapping({
    required this.verifierId,
    required this.verifierKeyId,
    required this.wrappedDataKey,
  });
}

/// The shared envelope data structure.
class SharedEnvelope {
  final int version;
  final Uint8List entryId;              // 16 bytes (UUIDv7 raw)
  final Uint8List issuerId;             // 16 bytes (UUIDv7 raw)
  final String issuerLabel;
  final Uint8List issuerSigningKeyId;   // 16 bytes
  final int createdAt;                  // Unix epoch ms
  final String description;
  final String ciphertextAlg;
  final Uint8List ciphertextNonce;
  final Uint8List ciphertext;
  final Uint8List ciphertextHash;
  final List<RecipientWrapping> recipientWrappings;
  final Uint8List? signature;

  const SharedEnvelope({
    required this.version,
    required this.entryId,
    required this.issuerId,
    required this.issuerLabel,
    required this.issuerSigningKeyId,
    required this.createdAt,
    required this.description,
    required this.ciphertextAlg,
    required this.ciphertextNonce,
    required this.ciphertext,
    required this.ciphertextHash,
    required this.recipientWrappings,
    this.signature,
  });

  /// Returns a copy of this envelope with [signature] replaced by [sig].
  SharedEnvelope withSignature(Uint8List? sig) => SharedEnvelope(
        version: version,
        entryId: entryId,
        issuerId: issuerId,
        issuerLabel: issuerLabel,
        issuerSigningKeyId: issuerSigningKeyId,
        createdAt: createdAt,
        description: description,
        ciphertextAlg: ciphertextAlg,
        ciphertextNonce: ciphertextNonce,
        ciphertext: ciphertext,
        ciphertextHash: ciphertextHash,
        recipientWrappings: recipientWrappings,
        signature: sig,
      );
}
