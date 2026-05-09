import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../crypto/ed25519.dart';
import '../crypto/random.dart';
import '../crypto/secret_box.dart';
import 'secure_storage.dart';

const String _kekStorageKey = 'issuer_kek';
const String _wrappedKeyStorageKey = 'issuer_wrapped_key';
const String _publicKeyStorageKey = 'issuer_public_key';

/// Ed25519 keystore backed by OS-keystore-wrapped key material.
///
/// The private key seed is encrypted with a random KEK via SecretBox.
/// The KEK is stored in [SecureStorage] (flutter_secure_storage in prod).
/// On sign, the seed is unwrapped, used, and zeroed within a single call.
class Keystore {
  final Sodium _sodium;
  final SecureStorage _storage;

  Keystore(this._sodium, this._storage);

  /// Generates a new Ed25519 keypair and persists the wrapped seed.
  ///
  /// Returns the 32-byte public key.
  Future<Uint8List> generate() async {
    final seed = Rand.bytes(_sodium, 32);
    try {
      final kp = Ed25519.seedKeyPair(_sodium, seed);
      final kek = Rand.bytes(_sodium, 32);
      final nonce = Rand.bytes(_sodium, 24);
      final ct = SecretBoxCrypto.seal(_sodium, seed, nonce, kek);

      final wrappedBlob = Uint8List(24 + ct.length);
      wrappedBlob.setRange(0, 24, nonce);
      wrappedBlob.setRange(24, wrappedBlob.length, ct);

      await _storage.write(_kekStorageKey, kek);
      await _storage.write(_wrappedKeyStorageKey, wrappedBlob);
      await _storage.write(_publicKeyStorageKey, kp.publicKey);

      return Uint8List.fromList(kp.publicKey);
    } finally {
      _zeroBytes(seed);
    }
  }

  /// Returns the stored 32-byte public key, or null if not generated.
  Future<Uint8List?> publicKey() async {
    return _storage.read(_publicKeyStorageKey);
  }

  /// Signs [message] with the stored private key.
  ///
  /// Reads the wrapped blob, unwraps, signs, then zeros all key material.
  Future<Uint8List> sign(Uint8List message) async {
    final kek = await _storage.read(_kekStorageKey);
    final wrappedBlob = await _storage.read(_wrappedKeyStorageKey);
    if (kek == null || wrappedBlob == null) {
      throw StateError('No keypair stored — call generate() first');
    }

    final nonce = Uint8List.sublistView(wrappedBlob, 0, 24);
    final ct = Uint8List.sublistView(wrappedBlob, 24);
    final seed = SecretBoxCrypto.open(_sodium, ct, nonce, kek);
    try {
      final kp = Ed25519.seedKeyPair(_sodium, seed);
      try {
        return Ed25519.signDetached(_sodium, kp.secretKey, message);
      } finally {
        _zeroBytes(kp.secretKey);
      }
    } finally {
      _zeroBytes(seed);
    }
  }

  /// Purges all stored key material.
  Future<void> destroy() async {
    await _storage.delete(_kekStorageKey);
    await _storage.delete(_wrappedKeyStorageKey);
    await _storage.delete(_publicKeyStorageKey);
  }

  static void _zeroBytes(Uint8List bytes) {
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }
}
