import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import 'canonical_cbor.dart';
import 'crypto_exception.dart';
import 'secret_box.dart';

/// A secretbox-wrapped private key blob (crypto-formats.md §3).
///
/// CBOR map key order (lexicographic over encoded length): v, ct, alg, nonce.
class WrappedBlob {
  final Uint8List nonce; // 24 bytes
  final Uint8List ct;    // secretbox ciphertext

  const WrappedBlob({required this.nonce, required this.ct});

  /// Decodes a wrapped-blob from canonical CBOR bytes.
  ///
  /// Throws [CryptoException] if the CBOR is malformed or version/alg unknown.
  static WrappedBlob decode(Uint8List bytes) {
    Map<String, dynamic> map;
    try {
      map = CanonicalCborMapper().readValue(bytes);
    } catch (e) {
      throw CryptoException('Invalid wrapped blob CBOR', e);
    }
    final v = map['v'];
    final alg = map['alg'];
    if (v != 1) throw CryptoException('Unsupported wrap format version: $v');
    if (alg != 'secretbox') {
      throw CryptoException('Unsupported wrap alg: $alg');
    }
    return WrappedBlob(
      nonce: map['nonce'] as Uint8List,
      ct: map['ct'] as Uint8List,
    );
  }

  /// Encodes this blob as canonical CBOR (used for testing / CLI round-trips).
  Uint8List encode() => CanonicalCborMapper().writeBytes({
        'v': 1,
        'ct': ct,
        'alg': 'secretbox',
        'nonce': nonce,
      });

  /// Decrypts the wrapped private key with [kek].
  ///
  /// Throws [CryptoException] on authentication failure (wrong password path).
  Uint8List open(Sodium sodium, Uint8List kek) =>
      SecretBoxCrypto.open(sodium, ct, nonce, kek);
}
