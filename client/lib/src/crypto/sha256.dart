import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

/// SHA-256 helper backed by [package:crypto].
class Sha256 {
  Sha256._();

  /// Returns the SHA-256 digest of [data].
  static Uint8List hash(Uint8List data) {
    final digest = pkg_crypto.sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }
}
