import 'dart:typed_data';

import 'sha256.dart';

/// Public-key fingerprint renderer (crypto-formats.md §8).
class Fingerprint {
  Fingerprint._();

  static const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /// Renders [publicKey] as a dash-separated base32 fingerprint string.
  ///
  /// Algorithm: SHA-256(publicKey)[0:10] → base32(RFC 4648) → XXXX-XXXX-XXXX-XXXX
  static String render(Uint8List publicKey) {
    final hash = Sha256.hash(publicKey);
    final truncated = Uint8List.fromList(hash.sublist(0, 10));
    final b32 = _base32Encode(truncated);
    return '${b32.substring(0, 4)}-'
        '${b32.substring(4, 8)}-'
        '${b32.substring(8, 12)}-'
        '${b32.substring(12, 16)}';
  }

  static String _base32Encode(Uint8List data) {
    final sb = StringBuffer();
    var buffer = 0;
    var bitsLeft = 0;
    for (final b in data) {
      buffer = (buffer << 8) | (b & 0xFF);
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        bitsLeft -= 5;
        sb.write(_alphabet[(buffer >> bitsLeft) & 0x1F]);
      }
    }
    if (bitsLeft > 0) {
      sb.write(_alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
    }
    return sb.toString();
  }
}
