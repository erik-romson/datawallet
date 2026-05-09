import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

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

/// Production [SecureStorage] backed by [FlutterSecureStorage].
///
/// Values are base64-encoded for storage compatibility.
class FlutterSecureStorageAdapter implements SecureStorage {
  static const _options = AndroidOptions(encryptedSharedPreferences: true);
  final _store = const FlutterSecureStorage(aOptions: _options);

  @override
  Future<Uint8List?> read(String key) async {
    final raw = await _store.read(key: key);
    if (raw == null) return null;
    return base64.decode(raw);
  }

  @override
  Future<void> write(String key, Uint8List value) async {
    await _store.write(key: key, value: base64.encode(value));
  }

  @override
  Future<void> delete(String key) async {
    await _store.delete(key: key);
  }
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
