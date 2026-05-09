import 'dart:typed_data';

import 'package:datawallet/src/issuer/install_identity.dart';
import 'package:datawallet/src/issuer/keystore.dart';
import 'package:datawallet/src/issuer/secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';

void main() {
  late SodiumSumo sodium;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
  });

  test('destroy removes wrapped key blob and KEK handle', () async {
    final storage = InMemorySecureStorage();
    final keystore = Keystore(sodium, storage);
    final installIdentity = InstallIdentity(storage);

    // Enroll: generate keypair and persist receipt.
    await keystore.generate();
    final fakeUuid = Uint8List.fromList(List.filled(16, 0x01));
    final fakeRecord = Uint8List.fromList(List.filled(32, 0x02));
    await installIdentity.save(fakeUuid, fakeRecord);

    expect(await installIdentity.isEnrolled(), isTrue);
    expect(await keystore.publicKey(), isNotNull);

    // Simulate logout / uninstall: destroy both keystores.
    await keystore.destroy();
    await installIdentity.destroy();

    // Wrapped blob and KEK handle are gone — no key material recoverable.
    expect(await keystore.publicKey(), isNull);
    expect(
      () => keystore.sign(Uint8List(1)),
      throwsA(isA<StateError>()),
    );

    // Enrollment receipt is gone.
    expect(await installIdentity.isEnrolled(), isFalse);
    expect(await installIdentity.installUuid(), isNull);
    expect(await installIdentity.signedRecord(), isNull);
  });
}
