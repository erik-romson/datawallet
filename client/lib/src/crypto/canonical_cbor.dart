import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';

/// Thrown when CBOR data cannot be encoded/decoded or is not in canonical form.
class CanonicalCborException implements Exception {
  final String message;
  final Object? cause;

  const CanonicalCborException(this.message, [this.cause]);

  @override
  String toString() => cause != null
      ? 'CanonicalCborException: $message (cause: $cause)'
      : 'CanonicalCborException: $message';
}

/// Canonical CBOR encoder/decoder (RFC 8949 §4.2.1).
///
/// Keys in maps are sorted lexicographically by their CBOR-encoded text-string
/// byte representation, matching the Java [CanonicalCborMapper] exactly.
class CanonicalCborMapper {
  /// Encodes [value] as canonical CBOR bytes.
  ///
  /// [value] may be a [Map<String, dynamic>], [List], [int], [String],
  /// [Uint8List], [bool], or null — nested arbitrarily.
  Uint8List writeBytes(Object? value) {
    try {
      final sorted = _sortKeys(value);
      final cborVal = _toCborValue(sorted);
      return Uint8List.fromList(CborEncoder().convert(cborVal));
    } on CanonicalCborException {
      rethrow;
    } catch (e) {
      throw CanonicalCborException('Failed to write canonical CBOR', e);
    }
  }

  /// Decodes [bytes] and validates that they are canonical.
  ///
  /// Throws [CanonicalCborException] if the bytes cannot be decoded or are
  /// not in canonical form.
  Map<String, dynamic> readValue(Uint8List bytes) {
    _requireCanonical(bytes);
    try {
      final decoded = CborDecoder().convert(bytes);
      return _fromCborValue(decoded) as Map<String, dynamic>;
    } on CanonicalCborException {
      rethrow;
    } catch (e) {
      throw CanonicalCborException('Failed to read CBOR', e);
    }
  }

  /// Re-encodes [canonicalCbor] and verifies the result is byte-identical.
  ///
  /// Throws [CanonicalCborException] if the bytes are not canonical.
  Uint8List reencode(Uint8List canonicalCbor) {
    final reencoded = _doReencode(canonicalCbor);
    if (!_bytesEqual(canonicalCbor, reencoded)) {
      throw const CanonicalCborException(
          'Input is not canonical CBOR: re-encoding produced different bytes');
    }
    return reencoded;
  }

  void _requireCanonical(Uint8List bytes) {
    final reencoded = _doReencode(bytes);
    if (!_bytesEqual(bytes, reencoded)) {
      throw const CanonicalCborException('Input is not canonical CBOR');
    }
  }

  Uint8List _doReencode(Uint8List bytes) {
    try {
      final decoded = CborDecoder().convert(bytes);
      final native = _fromCborValue(decoded);
      final sorted = _sortKeys(native);
      final cborVal = _toCborValue(sorted);
      return Uint8List.fromList(CborEncoder().convert(cborVal));
    } on CanonicalCborException {
      rethrow;
    } catch (e) {
      throw CanonicalCborException('Failed to re-encode CBOR', e);
    }
  }

  Object? _sortKeys(Object? value) {
    if (value is Uint8List) return value;
    if (value is Map) {
      final entries = value.entries
          .map((e) => MapEntry(e.key as String, _sortKeys(e.value)))
          .toList()
        ..sort((a, b) => _compareCanonicalKeys(a.key, b.key));
      return Map<String, Object?>.fromEntries(entries);
    }
    if (value is List) {
      return value.map(_sortKeys).toList();
    }
    return value;
  }

  CborValue _toCborValue(Object? value) {
    if (value == null) return const CborNull();
    if (value is bool) return CborBool(value);
    if (value is int) return CborSmallInt(value);
    if (value is String) return CborString(value);
    if (value is Uint8List) return CborBytes(value);
    if (value is List) {
      return CborList(value.map(_toCborValue).toList());
    }
    if (value is Map) {
      final entries = value.entries.map((e) {
        return MapEntry<CborValue, CborValue>(
            CborString(e.key as String), _toCborValue(e.value));
      }).toList()
        ..sort((a, b) => _compareCanonicalKeys(
            (a.key as CborString).toString(),
            (b.key as CborString).toString()));
      return CborMap(Map<CborValue, CborValue>.fromEntries(entries));
    }
    throw CanonicalCborException('Unsupported type: ${value.runtimeType}');
  }

  Object? _fromCborValue(CborValue value) {
    if (value is CborNull) return null;
    if (value is CborBool) return value.value;
    if (value is CborBytes) return Uint8List.fromList(value.bytes);
    if (value is CborString) return value.toString();
    if (value is CborInt) return value.toInt();
    if (value is CborList) {
      return value.map(_fromCborValue).toList();
    }
    if (value is CborMap) {
      final result = <String, dynamic>{};
      value.forEach((k, v) {
        result[(k as CborString).toString()] = _fromCborValue(v);
      });
      return result;
    }
    throw CanonicalCborException(
        'Unsupported CBOR type: ${value.runtimeType}');
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// Encodes [key] as a CBOR text-string header + UTF-8 bytes for ordering.
  static Uint8List _cborEncodeKey(String key) {
    final utf8Bytes = utf8.encode(key);
    final len = utf8Bytes.length;
    List<int> header;
    if (len <= 23) {
      header = [0x60 + len];
    } else if (len <= 0xFF) {
      header = [0x78, len];
    } else if (len <= 0xFFFF) {
      header = [0x79, (len >> 8) & 0xFF, len & 0xFF];
    } else {
      header = [
        0x7A,
        (len >> 24) & 0xFF,
        (len >> 16) & 0xFF,
        (len >> 8) & 0xFF,
        len & 0xFF,
      ];
    }
    return Uint8List.fromList([...header, ...utf8Bytes]);
  }

  /// Compares two map keys in canonical CBOR order.
  static int _compareCanonicalKeys(String a, String b) {
    final aBytes = _cborEncodeKey(a);
    final bBytes = _cborEncodeKey(b);
    final minLen =
        aBytes.length < bBytes.length ? aBytes.length : bBytes.length;
    for (var i = 0; i < minLen; i++) {
      final diff = (aBytes[i] & 0xFF) - (bBytes[i] & 0xFF);
      if (diff != 0) return diff;
    }
    return aBytes.length - bBytes.length;
  }
}
