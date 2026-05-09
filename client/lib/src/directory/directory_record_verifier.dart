import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../crypto/ed25519.dart';
import 'directory_record.dart';
import 'directory_record_codec.dart';
import 'directory_rejection.dart';
import 'root_quorum.dart';

/// Resolves a parent intermediate record by its key_id.
/// Returns the raw signed CBOR bytes, or throws [ParentNotFound].
typedef ParentLookup = Uint8List Function(Uint8List parentKeyId);

/// Verifies a [DirectoryRecord] against a [PinnedRoot].
///
/// Rejection order (mirrors Java):
/// 1. Parse / canonical check   → [MalformedCbor]
/// 2. Version check             → [UnsupportedVersion]
/// 3. record_type validation    → [InvalidRecordType]
/// 4. key_use validation        → [InvalidKeyUse]
/// 5. status validation         → [InvalidStatus]
/// 6. Freshness check           → [FreshnessExpired]
/// 7. Signature container XOR   → [SignatureContainerConflict] / [SignatureContainerMissing]
/// 8. Root quorum / parent chain check
class DirectoryRecordVerifier {
  static const Duration _maxAge = Duration(days: 7);
  static const int _maxDepth = 2;

  static const _validRecordTypes = {'verifier', 'issuer', 'intermediate'};
  static const _validKeyUses = {'enc', 'auth', 'sign'};
  static const _validStatuses = {'active', 'superseded', 'revoked'};

  final DirectoryRecordCodec _codec;
  final Sodium _sodium;
  final int Function() _nowMs;

  DirectoryRecordVerifier(this._sodium, {int Function()? nowMs})
      : _codec = DirectoryRecordCodec(),
        _nowMs = nowMs ?? (() => DateTime.now().millisecondsSinceEpoch);

  /// Verifies [recordBytes] against [pinned].
  ///
  /// Fails fast if a parent chain is required and no [lookup] is supplied.
  DirectoryRecord verify(Uint8List recordBytes, PinnedRoot pinned,
      [ParentLookup? lookup]) {
    return _verifyAtDepth(recordBytes, pinned, lookup, 1);
  }

  DirectoryRecord _verifyAtDepth(Uint8List recordBytes, PinnedRoot pinned,
      ParentLookup? lookup, int depth) {
    final record = _codec.decode(recordBytes); // may throw MalformedCbor / XOR

    if (record.version != 1) {
      throw UnsupportedVersion(record.version);
    }
    if (!_validRecordTypes.contains(record.recordType)) {
      throw InvalidRecordType(record.recordType);
    }
    if (!_validKeyUses.contains(record.keyUse)) {
      throw InvalidKeyUse(record.keyUse);
    }
    if (!_validStatuses.contains(record.status)) {
      throw InvalidStatus(record.status);
    }

    final nowMs = _nowMs();
    final ageMs = nowMs - record.issuedAt;
    if (ageMs > _maxAge.inMilliseconds) {
      throw FreshnessExpired(
          'Record issued_at=${record.issuedAt} is older than 7 days '
          '(age=${ageMs}ms)');
    }

    final signedBytes = _codec.signedBytesOfEncoded(recordBytes);

    if (record.parentKeyId == null) {
      RootQuorum.verify(
          _sodium, signedBytes, record.rootSignatures, record.issuedAt, pinned);
    } else {
      _verifyParentChain(record, signedBytes, pinned, lookup, depth);
    }

    return record;
  }

  void _verifyParentChain(DirectoryRecord record, Uint8List signedBytes,
      PinnedRoot pinned, ParentLookup? lookup, int depth) {
    if (depth >= _maxDepth) {
      throw ChainTooDeep('Chain depth exceeds maximum of $_maxDepth');
    }

    if (lookup == null) {
      throw ParentNotFound(
          'Parent lookup not available for key_id=${_hex(record.parentKeyId!)}');
    }

    final parentBytes = lookup(record.parentKeyId!);
    final parent = _codec.decode(parentBytes);

    if (parent.recordType != 'intermediate') {
      throw ParentNotIntermediate(
          "Parent record_type='${parent.recordType}' is not 'intermediate'");
    }
    if (parent.status != 'active') {
      throw ParentInactive("Parent status='${parent.status}' is not 'active'");
    }
    final now = _nowMs();
    if (now < parent.validFrom || now >= parent.validUntil) {
      throw ParentInactive(
          'Current time $now is outside parent valid window '
          '[${parent.validFrom}, ${parent.validUntil})');
    }

    if (!Ed25519.verifyDetached(
        _sodium, parent.publicKey, signedBytes, record.parentSignature!)) {
      throw ParentSignatureInvalid(
          'Parent signature invalid for key_id=${_hex(record.parentKeyId!)}');
    }

    _verifyAtDepth(parentBytes, pinned, lookup, depth + 1);
  }

  static String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
