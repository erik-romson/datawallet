import 'dart:typed_data';

/// An active verifier session.
///
/// Holds the bearer token and in-memory key material.
/// Call [zero] on logout or idle timeout to clear sensitive key material.
class Session {
  final Uint8List verifierId;    // 16 bytes
  final String token;            // opaque bearer token
  final Uint8List authPublicKey; // 32 bytes, Ed25519 — used for fingerprint
  final Uint8List encPublicKey;  // 32 bytes, X25519 — for SealedBox.open

  final Uint8List _encPrivKey;   // 32 bytes, X25519
  final Uint8List _authPrivKey;  // 64 bytes, Ed25519 expanded

  Session({
    required this.verifierId,
    required this.token,
    required this.authPublicKey,
    required this.encPublicKey,
    required Uint8List encPrivKey,
    required Uint8List authPrivKey,
  })  : _encPrivKey = encPrivKey,
        _authPrivKey = authPrivKey;

  Uint8List get encPrivKey => _encPrivKey;
  Uint8List get authPrivKey => _authPrivKey;

  /// Zeros all key material in place.
  void zero() {
    _encPrivKey.fillRange(0, _encPrivKey.length, 0);
    _authPrivKey.fillRange(0, _authPrivKey.length, 0);
  }
}
