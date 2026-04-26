import 'dart:typed_data';

import '../crypto/canonical_cbor.dart';
import 'envelope_rejection.dart';
import 'shared_envelope.dart';

/// Encodes and decodes [SharedEnvelope] to/from canonical CBOR.
class EnvelopeCodec {
  final CanonicalCborMapper _cbor = CanonicalCborMapper();

  /// Encodes [envelope] to canonical CBOR, including [signature] if present.
  Uint8List encode(SharedEnvelope envelope) {
    final map = _toMap(envelope);
    if (envelope.signature != null) {
      map['signature'] = envelope.signature!;
    }
    return _cbor.writeBytes(map);
  }

  /// Decodes [bytes] into a [SharedEnvelope].
  ///
  /// Throws [MalformedCbor] if the bytes cannot be parsed or are non-canonical.
  SharedEnvelope decode(Uint8List bytes) {
    Map<String, dynamic> map;
    try {
      map = _cbor.readValue(bytes);
    } catch (e) {
      throw MalformedCbor('Failed to parse envelope CBOR', e);
    }
    return _fromMap(map);
  }

  /// Returns the bytes that are covered by the issuer signature (no signature field).
  Uint8List signedBytesOf(SharedEnvelope envelope) {
    return _cbor.writeBytes(_toMap(envelope));
  }

  Map<String, Object?> _toMap(SharedEnvelope env) {
    final map = <String, Object?>{};
    map['version'] = env.version;
    map['entry_id'] = env.entryId;
    map['issuer_id'] = env.issuerId;
    map['issuer_label'] = env.issuerLabel;
    map['issuer_signing_key_id'] = env.issuerSigningKeyId;
    map['created_at'] = env.createdAt;
    map['description'] = env.description;
    map['ciphertext_alg'] = env.ciphertextAlg;
    map['ciphertext_nonce'] = env.ciphertextNonce;
    map['ciphertext'] = env.ciphertext;
    map['ciphertext_hash'] = env.ciphertextHash;

    final wrappings = env.recipientWrappings.map((rw) {
      return <String, Object?>{
        'verifier_id': rw.verifierId,
        'verifier_key_id': rw.verifierKeyId,
        'wrapped_data_key': rw.wrappedDataKey,
      };
    }).toList();
    map['recipient_wrappings'] = wrappings;
    return map;
  }

  SharedEnvelope _fromMap(Map<String, dynamic> map) {
    final version = (map['version'] as int);
    final entryId = map['entry_id'] as Uint8List;
    final issuerId = map['issuer_id'] as Uint8List;
    final issuerLabel = map['issuer_label'] as String;
    final issuerSigningKeyId = map['issuer_signing_key_id'] as Uint8List;
    final createdAt = map['created_at'] as int;
    final description = map['description'] as String;
    final ciphertextAlg = map['ciphertext_alg'] as String;
    final ciphertextNonce = map['ciphertext_nonce'] as Uint8List;
    final ciphertext = map['ciphertext'] as Uint8List;
    final ciphertextHash = map['ciphertext_hash'] as Uint8List;
    final signature = map['signature'] as Uint8List?;

    final rawWrappings = map['recipient_wrappings'] as List<dynamic>;
    final wrappings = rawWrappings.map((rw) {
      final rwMap = rw as Map<String, dynamic>;
      return RecipientWrapping(
        verifierId: rwMap['verifier_id'] as Uint8List,
        verifierKeyId: rwMap['verifier_key_id'] as Uint8List,
        wrappedDataKey: rwMap['wrapped_data_key'] as Uint8List,
      );
    }).toList();

    return SharedEnvelope(
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
      recipientWrappings: wrappings,
      signature: signature,
    );
  }
}
