import 'dart:typed_data';

import 'package:sodium/sodium.dart';

/// X25519 (box) key pair (public + secret key as raw bytes).
class X25519KeyPair {
  final Uint8List publicKey;
  final Uint8List secretKey;

  const X25519KeyPair({required this.publicKey, required this.secretKey});
}

/// X25519 key-derivation primitives backed by libsodium box.
class X25519 {
  X25519._();

  /// Derives an X25519 key pair from a 32-byte [seed].
  ///
  /// Note: this hashes the seed (libsodium's seed_keypair = SHA-512 + clamp).
  /// Do NOT pass an already-derived X25519 secret key as [seed] — that
  /// produces a different keypair than the one the secret key belongs to.
  /// To recover a public key for an existing secret key, fetch it from the
  /// server (login blob, directory record) instead of recomputing.
  static X25519KeyPair seedKeyPair(Sodium sodium, Uint8List seed) {
    final secKey = SecureKey.fromList(sodium, seed);
    try {
      final kp = sodium.crypto.box.seedKeyPair(secKey);
      final rawSecret = kp.secretKey.extractBytes();
      kp.secretKey.dispose();
      return X25519KeyPair(publicKey: kp.publicKey, secretKey: rawSecret);
    } finally {
      secKey.dispose();
    }
  }
}
