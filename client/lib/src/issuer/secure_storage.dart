import 'dart:typed_data';

/// Abstraction over OS-keystore-backed secure storage.
///
/// Production: backed by `flutter_secure_storage` with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (iOS) /
/// `EncryptedSharedPreferences` (Android).
/// Tests: [InMemorySecureStorage].
abstract class SecureStorage {
  Future<Uint8List?> read(String key);
  Future<void> write(String key, Uint8List value);
  Future<void> delete(String key);
}

/// In-memory [SecureStorage] for tests.
class InMemorySecureStorage implements SecureStorage {
  final Map<String, Uint8List> _store = {};

  @override
  Future<Uint8List?> read(String key) async => _store[key];

  @override
  Future<void> write(String key, Uint8List value) async {
    _store[key] = Uint8List.fromList(value);
  }

  @override
  Future<void> delete(String key) async {
    _store.remove(key);
  }
}
