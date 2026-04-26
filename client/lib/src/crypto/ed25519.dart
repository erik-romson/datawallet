import 'dart:typed_data';

import 'package:sodium/sodium.dart';

/// Ed25519 key pair (public + secret key as raw bytes).
class Ed25519KeyPair {
  final Uint8List publicKey;
  final Uint8List secretKey;

  const Ed25519KeyPair({required this.publicKey, required this.secretKey});
}

/// Ed25519 signing primitives backed by libsodium.
class Ed25519 {
  Ed25519._();

  /// Derives an Ed25519 key pair from a 32-byte [seed].
  static Ed25519KeyPair seedKeyPair(Sodium sodium, Uint8List seed) {
    final secKey = SecureKey.fromList(sodium, seed);
    try {
      final kp = sodium.crypto.sign.seedKeyPair(secKey);
      final rawSecret = kp.secretKey.extractBytes();
      kp.secretKey.dispose();
      return Ed25519KeyPair(publicKey: kp.publicKey, secretKey: rawSecret);
    } finally {
      secKey.dispose();
    }
  }

  /// Signs [message] with [secretKey] and returns the 64-byte detached signature.
  static Uint8List signDetached(
      Sodium sodium, Uint8List secretKey, Uint8List message) {
    final secKey = SecureKey.fromList(sodium, secretKey);
    try {
      return sodium.crypto.sign
          .detached(message: message, secretKey: secKey);
    } finally {
      secKey.dispose();
    }
  }

  /// Verifies [signature] over [message] with [publicKey].
  static bool verifyDetached(Sodium sodium, Uint8List publicKey,
      Uint8List message, Uint8List signature) {
    return sodium.crypto.sign.verifyDetached(
        message: message, signature: signature, publicKey: publicKey);
  }
}
