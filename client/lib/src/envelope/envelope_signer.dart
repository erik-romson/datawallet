import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../crypto/ed25519.dart';
import 'envelope_codec.dart';
import 'shared_envelope.dart';

/// Signs a [SharedEnvelope] with an Ed25519 issuer key.
class EnvelopeSigner {
  final EnvelopeCodec _codec;
  final Sodium _sodium;

  EnvelopeSigner(this._sodium) : _codec = EnvelopeCodec();

  /// Signs [unsigned] with [issuerEd25519SecretKey] and returns the encoded bytes.
  ///
  /// Throws [ArgumentError] if [unsigned] already carries a signature.
  Uint8List sign(SharedEnvelope unsigned, Uint8List issuerEd25519SecretKey) {
    if (unsigned.signature != null) {
      throw ArgumentError('Envelope already has a signature');
    }
    final signedBytes = _codec.signedBytesOf(unsigned);
    final sig = Ed25519.signDetached(_sodium, issuerEd25519SecretKey, signedBytes);
    return _codec.encode(unsigned.withSignature(sig));
  }
}
