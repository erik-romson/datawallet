import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import 'crypto_exception.dart';

/// Anonymous sealed-box encryption backed by libsodium (crypto_box_seal).
class SealedBox {
  SealedBox._();

  /// Encrypts [plaintext] for [publicKey] using an ephemeral sender key.
  ///
  /// The ciphertext is not reproducible (ephemeral key is random each call).
  static Uint8List seal(
      Sodium sodium, Uint8List plaintext, Uint8List publicKey) {
    return sodium.crypto.box.seal(message: plaintext, publicKey: publicKey);
  }

  /// Decrypts [ciphertext] using the recipient's [publicKey] and [secretKey].
  ///
  /// Throws [CryptoException] if authentication fails.
  static Uint8List open(Sodium sodium, Uint8List ciphertext,
      Uint8List publicKey, Uint8List secretKey) {
    final secKey = SecureKey.fromList(sodium, secretKey);
    try {
      return sodium.crypto.box.sealOpen(
          cipherText: ciphertext, publicKey: publicKey, secretKey: secKey);
    } catch (e) {
      throw CryptoException('SealedBox decryption failed', e);
    } finally {
      secKey.dispose();
    }
  }
}
