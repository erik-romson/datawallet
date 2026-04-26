import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import 'crypto_exception.dart';

/// XSalsa20-Poly1305 symmetric encryption (secretbox) backed by libsodium.
class SecretBoxCrypto {
  SecretBoxCrypto._();

  /// Encrypts [plaintext] with [key] and [nonce].
  ///
  /// [key] must be 32 bytes; [nonce] must be 24 bytes.
  static Uint8List seal(
      Sodium sodium, Uint8List plaintext, Uint8List nonce, Uint8List key) {
    final secKey = SecureKey.fromList(sodium, key);
    try {
      return sodium.crypto.secretBox
          .easy(message: plaintext, nonce: nonce, key: secKey);
    } finally {
      secKey.dispose();
    }
  }

  /// Decrypts [ciphertext] with [key] and [nonce].
  ///
  /// Throws [CryptoException] if authentication fails.
  static Uint8List open(
      Sodium sodium, Uint8List ciphertext, Uint8List nonce, Uint8List key) {
    final secKey = SecureKey.fromList(sodium, key);
    try {
      return sodium.crypto.secretBox
          .openEasy(cipherText: ciphertext, nonce: nonce, key: secKey);
    } catch (e) {
      throw CryptoException('SecretBox decryption failed', e);
    } finally {
      secKey.dispose();
    }
  }
}
