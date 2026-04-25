import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import 'directory_record.dart';
import 'directory_record_codec.dart';
import 'directory_rejection.dart';
import 'root_quorum.dart';

/// Verifies a [DirectoryRecord] against a [PinnedRoot].
///
/// Rejection order (mirrors Java):
/// 1. Parse / canonical check  → [MalformedCbor]
/// 2. Version check            → [UnsupportedVersion]
/// 3. record_type validation   → [InvalidRecordType]
/// 4. key_use validation       → [InvalidKeyUse]
/// 5. status validation        → [InvalidStatus]
/// 6. Freshness check          → [FreshnessExpired]
/// 7. Root quorum check        → [QuorumBelowThreshold] / [SignatureInvalid] / etc.
class DirectoryRecordVerifier {
  static const Duration _maxAge = Duration(days: 7);

  static const _validRecordTypes = {'verifier', 'issuer'};
  static const _validKeyUses = {'enc', 'auth', 'sign'};
  static const _validStatuses = {'active', 'superseded', 'revoked'};

  final DirectoryRecordCodec _codec;
  final Sodium _sodium;
  final int Function() _nowMs;

  DirectoryRecordVerifier(this._sodium,
      {int Function()? nowMs})
      : _codec = DirectoryRecordCodec(),
        _nowMs = nowMs ?? (() => DateTime.now().millisecondsSinceEpoch);

  /// Verifies [recordBytes] against [pinned] and returns the parsed record.
  ///
  /// Throws a subtype of [DirectoryRejection] on any verification failure.
  DirectoryRecord verify(Uint8List recordBytes, PinnedRoot pinned) {
    final record = _codec.decode(recordBytes); // may throw MalformedCbor

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
    RootQuorum.verify(
        _sodium, signedBytes, record.rootSignatures, record.issuedAt, pinned);

    return record;
  }
}
