import 'dart:typed_data';

import 'package:datawallet/src/crypto/ed25519.dart';
import 'package:datawallet/src/issuer/keystore.dart';
import 'package:datawallet/src/issuer/secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';

void main() {
  late SodiumSumo sodium;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
  });

  test('generate produces 32-byte public key', () async {
    final storage = InMemorySecureStorage();
    final keystore = Keystore(sodium, storage);

    final pubKey = await keystore.generate();

    expect(pubKey.length, equals(32));
  });

  test('publicKey returns stored key after generate', () async {
    final storage = InMemorySecureStorage();
    final keystore = Keystore(sodium, storage);

    final pubKey = await keystore.generate();
    final stored = await keystore.publicKey();

    expect(stored, equals(pubKey));
  });

  test('sign produces verifiable Ed25519 signature', () async {
    final storage = InMemorySecureStorage();
    final keystore = Keystore(sodium, storage);

    final pubKey = await keystore.generate();
    final message = Uint8List.fromList('test message'.codeUnits);
    final signature = await keystore.sign(message);

    expect(signature.length, equals(64));
    expect(
      Ed25519.verifyDetached(sodium, pubKey, message, signature),
      isTrue,
    );
  });

  test('sign round-trips across simulated app restart', () async {
    final storage = InMemorySecureStorage();
    final keystore1 = Keystore(sodium, storage);

    final pubKey = await keystore1.generate();
    final message = Uint8List.fromList('restart test'.codeUnits);

    // Simulate restart: new Keystore instance, same storage
    final keystore2 = Keystore(sodium, storage);
    final signature = await keystore2.sign(message);

    expect(
      Ed25519.verifyDetached(sodium, pubKey, message, signature),
      isTrue,
    );
  });

  test('destroy leaves no recoverable wrapped key', () async {
    final storage = InMemorySecureStorage();
    final keystore = Keystore(sodium, storage);

    await keystore.generate();
    await keystore.destroy();

    expect(await keystore.publicKey(), isNull);
    expect(
      () => keystore.sign(Uint8List(1)),
      throwsA(isA<StateError>()),
    );
  });

  test('sign throws StateError before generate', () async {
    final storage = InMemorySecureStorage();
    final keystore = Keystore(sodium, storage);

    expect(
      () => keystore.sign(Uint8List(1)),
      throwsA(isA<StateError>()),
    );
  });
}
