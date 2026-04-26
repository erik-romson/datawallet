import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import 'random.dart';

/// UUIDv7 generator (crypto-formats.md §10).
class UuidV7 {
  UuidV7._();

  static const int _randBytesLen = 10;

  /// Generates a UUIDv7 from an explicit [tsMs] (Unix epoch ms) and
  /// exactly 10 [randBytes] (rand_a 2 bytes + rand_b 8 bytes).
  ///
  /// Returns the 16-byte raw UUID (big-endian).
  static Uint8List generate(int tsMs, Uint8List randBytes) {
    if (randBytes.length != _randBytesLen) {
      throw ArgumentError(
          'randBytes must be $_randBytesLen bytes, got ${randBytes.length}');
    }

    // Most-significant 64 bits:
    //   48 bits  unix_ts_ms
    //    4 bits  version = 7
    //   12 bits  rand_a  (randBytes[0] low nibble + randBytes[1])
    var msb = 0;
    msb |= (tsMs & 0xFFFFFFFFFFFF) << 16;
    msb |= 0x7000;
    msb |= (randBytes[0] & 0x0F) << 8;
    msb |= (randBytes[1] & 0xFF);

    // Least-significant 64 bits:
    //   2 bits   variant = 10
    //  62 bits   rand_b (randBytes[2..9])
    var lsb = 0;
    lsb |= 0x80 << 56;
    lsb |= (randBytes[2] & 0x3F) << 56;
    lsb |= (randBytes[3] & 0xFF) << 48;
    lsb |= (randBytes[4] & 0xFF) << 40;
    lsb |= (randBytes[5] & 0xFF) << 32;
    lsb |= (randBytes[6] & 0xFF) << 24;
    lsb |= (randBytes[7] & 0xFF) << 16;
    lsb |= (randBytes[8] & 0xFF) << 8;
    lsb |= (randBytes[9] & 0xFF);

    final bytes = Uint8List(16);
    final bd = ByteData.sublistView(bytes);
    bd.setInt64(0, msb, Endian.big);
    bd.setInt64(8, lsb, Endian.big);
    return bytes;
  }

  /// Generates a UUIDv7 using the current wall-clock time and libsodium randomness.
  static Uint8List now(Sodium sodium) {
    final tsMs = DateTime.now().millisecondsSinceEpoch;
    final randBytes = Rand.bytes(sodium, _randBytesLen);
    return generate(tsMs, randBytes);
  }
}
