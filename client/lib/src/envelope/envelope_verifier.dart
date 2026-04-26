import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../crypto/ed25519.dart';
import '../crypto/sha256.dart';
import 'envelope_codec.dart';
import 'envelope_rejection.dart';
import 'issuer_key_resolver.dart';
import 'shared_envelope.dart';

/// Verifies a [SharedEnvelope] against the issuer directory.
///
/// Rejection order (mirrors Java):
/// 1. Parse / canonical check → [MalformedCbor]
/// 2. Version check           → [UnsupportedVersion]
/// 3. Key lookup + validity   → [IssuerKeyNotActiveAt]
/// 4. Signature check         → [SignatureInvalid]
/// 5. Ciphertext hash check   → [CiphertextHashMismatch]
class EnvelopeVerifier {
  final EnvelopeCodec _codec;
  final IssuerKeyResolver _keyResolver;
  final Sodium _sodium;

  EnvelopeVerifier(this._sodium, this._keyResolver) : _codec = EnvelopeCodec();

  /// Verifies [envelopeBytes] and returns the parsed [SharedEnvelope].
  ///
  /// Throws a subtype of [EnvelopeRejection] on any verification failure.
  SharedEnvelope verify(Uint8List envelopeBytes) {
    final envelope = _codec.decode(envelopeBytes); // may throw MalformedCbor

    if (envelope.version != 1) {
      throw UnsupportedVersion(envelope.version);
    }

    final keyView = _keyResolver(
        envelope.issuerId, envelope.issuerSigningKeyId, envelope.createdAt);
    if (keyView == null) {
      throw IssuerKeyNotActiveAt(
          'No directory record for issuer key at createdAt=${envelope.createdAt}');
    }
    if (envelope.createdAt < keyView.validFrom ||
        envelope.createdAt >= keyView.validUntil) {
      throw IssuerKeyNotActiveAt(
          'createdAt=${envelope.createdAt} outside valid range '
          '[${keyView.validFrom}, ${keyView.validUntil})');
    }

    final signedBytes =
        _codec.signedBytesOf(envelope.withSignature(null));
    if (!Ed25519.verifyDetached(
        _sodium, keyView.publicKey, signedBytes, envelope.signature!)) {
      throw const SignatureInvalid();
    }

    final computedHash = Sha256.hash(envelope.ciphertext);
    if (!_bytesEqual(computedHash, envelope.ciphertextHash)) {
      throw const CiphertextHashMismatch();
    }

    return envelope;
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
