import 'dart:typed_data';

import 'package:sodium/sodium.dart';

/// Randomness sourced exclusively from libsodium.
class Rand {
  Rand._();

  /// Returns [length] cryptographically-random bytes via libsodium.
  static Uint8List bytes(Sodium sodium, int length) {
    return sodium.randombytes.buf(length);
  }
}
