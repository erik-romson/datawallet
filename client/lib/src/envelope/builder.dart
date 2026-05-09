import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../crypto/random.dart';
import '../crypto/sealed_box.dart';
import '../crypto/secret_box.dart';
import '../crypto/sha256.dart';
import '../crypto/uuid_v7.dart';
import 'envelope_codec.dart';
import 'envelope_signer.dart';
import 'shared_envelope.dart';

/// Recipient descriptor for [EnvelopeBuilder].
class RecipientDescriptor {
  final Uint8List verifierId;
  final Uint8List verifierKeyId;
  final Uint8List encPublicKey;

  const RecipientDescriptor({
    required this.verifierId,
    required this.verifierKeyId,
    required this.encPublicKey,
  });
}

/// Result of [EnvelopeBuilder.build].
class BuiltEnvelope {
  final Uint8List signedEnvelopeBytes;
  final Uint8List ciphertextHash;

  const BuiltEnvelope({
    required this.signedEnvelopeBytes,
    required this.ciphertextHash,
  });
}

/// Builds and signs CBOR envelopes — symmetric counterpart of
/// Java's `BuildEnvelopeCommand.buildEnvelope()`.
///
/// Encrypts plaintext with SecretBox, wraps the data key for each
/// recipient with SealedBox, builds canonical CBOR, signs with Ed25519.
class EnvelopeBuilder {
  final Sodium _sodium;
  final EnvelopeCodec _codec;
  final EnvelopeSigner _signer;

  EnvelopeBuilder(this._sodium)
      : _codec = EnvelopeCodec(),
        _signer = EnvelopeSigner(_sodium);

  /// Builds a signed envelope from [plaintextContent] for [recipients].
  ///
  /// Uses [signFn] instead of taking a raw secret key, so callers can
  /// delegate to [Keystore.sign] without exposing key bytes.
  ///
  /// Zeros the data key and plaintext bytes before returning.
  BuiltEnvelope build({
    required String plaintextContent,
    required Uint8List entryId,
    required Uint8List issuerId,
    required String issuerLabel,
    required Uint8List issuerSigningKeyId,
    required Uint8List issuerSecretKey,
    required int createdAt,
    required String description,
    required List<RecipientDescriptor> recipients,
  }) {
    final normalized = plaintextContent; // caller normalizes if needed
    final plaintextBytes = Uint8List.fromList(utf8.encode(normalized));

    final dataKey = Rand.bytes(_sodium, 32);
    final nonce = Rand.bytes(_sodium, 24);

    try {
      final ciphertext =
          SecretBoxCrypto.seal(_sodium, plaintextBytes, nonce, dataKey);
      final ciphertextHash = Sha256.hash(ciphertext);

      final wrappings = recipients.map((r) {
        final wrapped = SealedBox.seal(_sodium, dataKey, r.encPublicKey);
        return RecipientWrapping(
          verifierId: r.verifierId,
          verifierKeyId: r.verifierKeyId,
          wrappedDataKey: wrapped,
        );
      }).toList();

      final unsigned = SharedEnvelope(
        version: 1,
        entryId: entryId,
        issuerId: issuerId,
        issuerLabel: issuerLabel,
        issuerSigningKeyId: issuerSigningKeyId,
        createdAt: createdAt,
        description: description,
        ciphertextAlg: 'xsalsa20poly1305',
        ciphertextNonce: nonce,
        ciphertext: ciphertext,
        ciphertextHash: ciphertextHash,
        recipientWrappings: wrappings,
      );

      final signedBytes = _signer.sign(unsigned, issuerSecretKey);

      return BuiltEnvelope(
        signedEnvelopeBytes: signedBytes,
        ciphertextHash: ciphertextHash,
      );
    } finally {
      _zeroBytes(dataKey);
      _zeroBytes(plaintextBytes);
    }
  }

  /// Deterministic build for fixture round-trips: caller supplies data key,
  /// nonce, and pre-wrapped recipient data keys.
  BuiltEnvelope buildDeterministic({
    required String plaintextContent,
    required Uint8List entryId,
    required Uint8List issuerId,
    required String issuerLabel,
    required Uint8List issuerSigningKeyId,
    required Uint8List issuerSecretKey,
    required int createdAt,
    required String description,
    required Uint8List dataKey,
    required Uint8List ciphertextNonce,
    required List<RecipientWrapping> recipientWrappings,
  }) {
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintextContent));

    try {
      final ciphertext =
          SecretBoxCrypto.seal(_sodium, plaintextBytes, ciphertextNonce, dataKey);
      final ciphertextHash = Sha256.hash(ciphertext);

      final unsigned = SharedEnvelope(
        version: 1,
        entryId: entryId,
        issuerId: issuerId,
        issuerLabel: issuerLabel,
        issuerSigningKeyId: issuerSigningKeyId,
        createdAt: createdAt,
        description: description,
        ciphertextAlg: 'xsalsa20poly1305',
        ciphertextNonce: ciphertextNonce,
        ciphertext: ciphertext,
        ciphertextHash: ciphertextHash,
        recipientWrappings: recipientWrappings,
      );

      final signedBytes = _signer.sign(unsigned, issuerSecretKey);

      return BuiltEnvelope(
        signedEnvelopeBytes: signedBytes,
        ciphertextHash: ciphertextHash,
      );
    } finally {
      _zeroBytes(plaintextBytes);
    }
  }

  static void _zeroBytes(Uint8List bytes) {
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }
}
