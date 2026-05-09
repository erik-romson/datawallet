import 'dart:typed_data';

import 'secure_storage.dart';

const String _installUuidKey = 'install_uuid';
const String _signedRecordKey = 'install_signed_record';

/// Persists the install UUID and signed directory record from enrollment.
///
/// Encrypted-at-rest via the same OS-keystore-backed [SecureStorage]
/// as [Keystore].
class InstallIdentity {
  final SecureStorage _storage;

  InstallIdentity(this._storage);

  /// Persists the enrollment receipt.
  Future<void> save(Uint8List installUuid, Uint8List signedRecord) async {
    await _storage.write(_installUuidKey, installUuid);
    await _storage.write(_signedRecordKey, signedRecord);
  }

  /// Returns the stored install UUID, or null if not enrolled.
  Future<Uint8List?> installUuid() async {
    return _storage.read(_installUuidKey);
  }

  /// Returns the signed directory record from enrollment, or null.
  Future<Uint8List?> signedRecord() async {
    return _storage.read(_signedRecordKey);
  }

  /// Returns true if enrollment data is present.
  Future<bool> isEnrolled() async {
    final uuid = await _storage.read(_installUuidKey);
    return uuid != null;
  }

  /// Purges all enrollment data.
  Future<void> destroy() async {
    await _storage.delete(_installUuidKey);
    await _storage.delete(_signedRecordKey);
  }
}
