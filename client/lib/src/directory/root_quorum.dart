import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../crypto/ed25519.dart';
import 'directory_record.dart';
import 'directory_rejection.dart';

/// Verifies that a set of root signatures meets the quorum threshold.
class RootQuorum {
  RootQuorum._();

  /// Verifies [sigs] over [signedBytes] at [issuedAtMs] against [pinned].
  ///
  /// - Duplicate key IDs count as a single valid signature.
  /// - Every signature must reference a known, in-window root key.
  /// - Throws a subtype of [DirectoryRejection] on any failure.
  static void verify(
    Sodium sodium,
    Uint8List signedBytes,
    List<RootSignature> sigs,
    int issuedAtMs,
    PinnedRoot pinned,
  ) {
    final validKeyIds = <String>{};

    for (final sig in sigs) {
      final root = _findRoot(sig.rootKeyId, pinned);
      if (root == null) {
        throw RootKeyNotFound(
            'Root key not found: ${_hex(sig.rootKeyId)}');
      }

      if (issuedAtMs < root.validFrom || issuedAtMs >= root.validUntil) {
        throw RootKeyExpired(
            'Root key outside valid window at issued_at=$issuedAtMs');
      }

      if (!Ed25519.verifyDetached(
          sodium, root.publicKey, signedBytes, sig.signature)) {
        throw SignatureInvalid(
            'Signature invalid for root key: ${_hex(sig.rootKeyId)}');
      }

      validKeyIds.add(_hex(sig.rootKeyId));
    }

    if (validKeyIds.length < pinned.threshold) {
      throw QuorumBelowThreshold(validKeyIds.length, pinned.threshold);
    }
  }

  static RootEntry? _findRoot(Uint8List rootKeyId, PinnedRoot pinned) {
    for (final entry in pinned.roots) {
      if (_bytesEqual(entry.rootKeyId, rootKeyId)) return entry;
    }
    return null;
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static String _hex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
