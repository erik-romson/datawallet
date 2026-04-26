import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'crypto_exception.dart';

/// Argon2id key-derivation function backed by libsodium (sumo variant).
class Argon2id {
  Argon2id._();

  static const int _kekLength = 32;

  /// Derives a 256-bit KEK (key-encryption key) from [password] and [salt].
  ///
  /// Parameters:
  /// - [m] memory limit in bytes (e.g. 268435456 = 256 MiB)
  /// - [t] iterations (ops limit)
  /// - [p] parallelism — must be 1 (libsodium enforces this implicitly)
  ///
  /// Throws [CryptoException] if [p] ≠ 1.
  static Uint8List deriveKek(SodiumSumo sodium, String password, Uint8List salt,
      int m, int t, int p) {
    if (p != 1) {
      throw CryptoException('Argon2id parallelism must be p=1, got p=$p');
    }
    final passwordBytes = Int8List.fromList(utf8.encode(password));
    final key = sodium.crypto.pwhash(
      outLen: _kekLength,
      password: passwordBytes,
      salt: salt,
      opsLimit: t,
      memLimit: m,
      alg: CryptoPwhashAlgorithm.argon2id13,
    );
    try {
      return key.extractBytes();
    } finally {
      key.dispose();
    }
  }
}
