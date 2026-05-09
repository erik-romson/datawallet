import 'dart:convert';
import 'dart:typed_data';

import 'package:datawallet/src/api/directory_client.dart';
import 'package:datawallet/src/api/issuer_client.dart';
import 'package:datawallet/src/crypto/x25519.dart';
import 'package:datawallet/src/directory/directory_record.dart';
import 'package:datawallet/src/directory/directory_record_codec.dart';
import 'package:datawallet/src/envelope/builder.dart';
import 'package:datawallet/src/issuer/bearer.dart';
import 'package:datawallet/src/issuer/install_identity.dart';
import 'package:datawallet/src/issuer/keystore.dart';
import 'package:datawallet/src/issuer/secure_storage.dart';
import 'package:datawallet/src/screens/share_screen.dart';
import 'package:datawallet/src/state/issuer_state.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sodium/sodium_sumo.dart';

class _MockDirectoryClient extends Mock implements DirectoryClient {}

class _MockIssuerClient extends Mock implements IssuerClient {}

void main() {
  setUpAll(() {
    registerFallbackValue(Uint8List(0));
  });

  late SodiumSumo sodium;
  // Fixed verifier X25519 enc key pair (seeded for reproducibility).
  late X25519KeyPair verifierEncKp;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    verifierEncKp = X25519.seedKeyPair(
      sodium,
      Uint8List.fromList(List.filled(32, 0x42)),
    );
  });

  // Builds a valid CBOR-encoded directory record usable in tests.
  Uint8List _encodedRecord({
    required Uint8List subjectId,
    required Uint8List keyId,
    required Uint8List publicKey,
    required String keyUse,
    required String status,
  }) {
    final record = DirectoryRecord(
      version: 1,
      recordType: keyUse == 'enc' ? 'verifier' : 'issuer',
      subjectId: subjectId,
      keyId: keyId,
      publicKey: publicKey,
      keyUse: keyUse,
      status: status,
      validFrom: 0,
      validUntil: 9999999999000,
      issuedAt: 0,
      rootSignatures: [],
    );
    return DirectoryRecordCodec().encode(record);
  }

  // Pre-populates storage so IssuerState.init() finds an enrolled identity.
  Future<({IssuerState state, Uint8List issuerKeyId})> _buildIssuerState({
    required InMemorySecureStorage storage,
    required Keystore keystore,
    required InstallIdentity installIdentity,
    required http.Client bearerHttp,
  }) async {
    await keystore.generate();
    final pubKey = (await keystore.publicKey())!;

    final installUuid = Uint8List.fromList(List.filled(16, 0x77));
    final issuerKeyId = Uint8List.fromList(List.filled(16, 0x11));

    final encodedRecord = _encodedRecord(
      subjectId: installUuid,
      keyId: issuerKeyId,
      publicKey: pubKey,
      keyUse: 'sign',
      status: 'active',
    );
    await installIdentity.save(installUuid, encodedRecord);

    final bearer = BearerProvider(
      intermediateUrl: 'http://intermediate',
      keystore: keystore,
      httpClient: bearerHttp,
    );

    final state = IssuerState(
      identity: installIdentity,
      keystore: keystore,
      bearerProvider: bearer,
    );
    await state.init();
    return (state: state, issuerKeyId: issuerKeyId);
  }

  DirectoryRecordWrapper _verifierWrapper(Uint8List encodedRecord) =>
      DirectoryRecordWrapper(
        keyId: 'verifier-key-id',
        status: 'active',
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: '2030-01-01T00:00:00Z',
        issuedAt: '2026-01-01T00:00:00Z',
        signedRecord: encodedRecord,
      );

  Widget _buildScreen({
    required IssuerState issuerState,
    required DirectoryClient directoryClient,
    required IssuerClient issuerClient,
  }) =>
      MaterialApp(
        home: ShareScreen(
          issuerState: issuerState,
          directoryClient: directoryClient,
          issuerClient: issuerClient,
          builder: EnvelopeBuilder(sodium),
          sodium: sodium,
        ),
      );

  group('ShareScreen happy path', () {
    testWidgets('builds envelope, posts it, navigates back on success',
        (tester) async {
      final storage = InMemorySecureStorage();
      final keystore = Keystore(sodium, storage);
      final installIdentity = InstallIdentity(storage);

      final bearerHttp = MockClient((_) async =>
          http.Response(jsonEncode({'bearer': 'test-bearer-token'}), 200));

      final (:state, :issuerKeyId) = await _buildIssuerState(
        storage: storage,
        keystore: keystore,
        installIdentity: installIdentity,
        bearerHttp: bearerHttp,
      );

      final verifierId = Uint8List.fromList(List.filled(16, 0x33));
      final verifierKeyId = Uint8List.fromList(List.filled(16, 0x22));
      final verifierEncBytes = _encodedRecord(
        subjectId: verifierId,
        keyId: verifierKeyId,
        publicKey: verifierEncKp.publicKey,
        keyUse: 'enc',
        status: 'active',
      );

      final mockDir = _MockDirectoryClient();
      final mockIssuer = _MockIssuerClient();

      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => [_verifierWrapper(verifierEncBytes)]);
      when(() => mockIssuer.submitEntry(any(), any()))
          .thenAnswer((_) async =>
              const EntryIngestResponse(entryId: 'e1', version: 1));

      // Wrap the screen in a Navigator so pop() works.
      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (ctx) => Scaffold(
            body: ElevatedButton(
              key: const Key('open_share'),
              onPressed: () => Navigator.of(ctx).push(MaterialPageRoute(
                builder: (_) => ShareScreen(
                  issuerState: state,
                  directoryClient: mockDir,
                  issuerClient: mockIssuer,
                  builder: EnvelopeBuilder(sodium),
                  sodium: sodium,
                ),
              )),
              child: const Text('Open'),
            ),
          ),
        ),
      ));

      await tester.tap(find.byKey(const Key('open_share')));
      await tester.pumpAndSettle();

      await tester.enterText(
          find.byKey(const Key('verifier_id_field')),
          '33333333-3333-3333-3333-333333333333');
      await tester.enterText(
          find.byKey(const Key('description_field')), 'Test description');
      await tester.enterText(
          find.byKey(const Key('plaintext_field')), 'Secret content');

      await tester.tap(find.byKey(const Key('submit_button')));
      await tester.pumpAndSettle(const Duration(seconds: 5));

      // Navigated back — ShareScreen is no longer in tree.
      expect(find.byType(ShareScreen), findsNothing);

      // submitEntry was called with the bearer token.
      verify(() => mockIssuer.submitEntry('test-bearer-token', any())).called(1);

      // Cancel idle timer started by resetIdle() in _submit before test ends.
      state.dispose();
    });
  });

  group('ShareScreen verifier lookup failure', () {
    testWidgets(
        'directory error shows error message and disables submit',
        (tester) async {
      final storage = InMemorySecureStorage();
      final keystore = Keystore(sodium, storage);
      final installIdentity = InstallIdentity(storage);
      final bearerHttp = MockClient((_) async =>
          http.Response(jsonEncode({'bearer': 'tok'}), 200));

      final (:state, issuerKeyId: _) = await _buildIssuerState(
        storage: storage,
        keystore: keystore,
        installIdentity: installIdentity,
        bearerHttp: bearerHttp,
      );

      final mockDir = _MockDirectoryClient();
      final mockIssuer = _MockIssuerClient();

      // Return no records → no active enc key found.
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => []);

      await tester.pumpWidget(_buildScreen(
        issuerState: state,
        directoryClient: mockDir,
        issuerClient: mockIssuer,
      ));
      await tester.pumpAndSettle();

      await tester.enterText(
          find.byKey(const Key('verifier_id_field')), 'some-verifier-id');
      await tester.enterText(
          find.byKey(const Key('description_field')), 'desc');
      await tester.enterText(
          find.byKey(const Key('plaintext_field')), 'text');

      await tester.tap(find.byKey(const Key('submit_button')));
      await tester.pumpAndSettle();

      // Error shown.
      expect(find.byKey(const Key('share_error')), findsOneWidget);

      // Submit button is now disabled (onPressed == null).
      final btn = tester.widget<ElevatedButton>(
          find.byKey(const Key('submit_button')));
      expect(btn.onPressed, isNull);

      // submitEntry was never called.
      verifyNever(() => mockIssuer.submitEntry(any(), any()));
    });
  });

  group('ShareScreen plaintext lifecycle', () {
    testWidgets('clearPlaintext zeros the plaintext field', (tester) async {
      final storage = InMemorySecureStorage();
      final keystore = Keystore(sodium, storage);
      final installIdentity = InstallIdentity(storage);
      final bearerHttp = MockClient((_) async =>
          http.Response(jsonEncode({'bearer': 'tok'}), 200));

      final (:state, issuerKeyId: _) = await _buildIssuerState(
        storage: storage,
        keystore: keystore,
        installIdentity: installIdentity,
        bearerHttp: bearerHttp,
      );
      addTearDown(state.dispose);

      final mockDir = _MockDirectoryClient();
      final mockIssuer = _MockIssuerClient();

      await tester.pumpWidget(_buildScreen(
        issuerState: state,
        directoryClient: mockDir,
        issuerClient: mockIssuer,
      ));
      await tester.pumpAndSettle();

      await tester.enterText(
          find.byKey(const Key('plaintext_field')), 'secret data');

      final screenState =
          tester.state<ShareScreenState>(find.byType(ShareScreen));
      expect(screenState.plaintextController.text, equals('secret data'));

      // clearPlaintext is called by dispose(); verify it works via the
      // @visibleForTesting accessor.
      screenState.clearPlaintext();
      expect(screenState.plaintextController.text, isEmpty);
    });

    testWidgets('plaintext cleared on AppLifecycleState.paused',
        (tester) async {
      final storage = InMemorySecureStorage();
      final keystore = Keystore(sodium, storage);
      final installIdentity = InstallIdentity(storage);
      final bearerHttp = MockClient((_) async =>
          http.Response(jsonEncode({'bearer': 'tok'}), 200));

      final (:state, issuerKeyId: _) = await _buildIssuerState(
        storage: storage,
        keystore: keystore,
        installIdentity: installIdentity,
        bearerHttp: bearerHttp,
      );
      addTearDown(state.dispose);

      final mockDir = _MockDirectoryClient();
      final mockIssuer = _MockIssuerClient();

      await tester.pumpWidget(_buildScreen(
        issuerState: state,
        directoryClient: mockDir,
        issuerClient: mockIssuer,
      ));
      await tester.pumpAndSettle();

      await tester.enterText(
          find.byKey(const Key('plaintext_field')), 'confidential');

      // Simulate app going to background.
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      await tester.pump();

      final screenState =
          tester.state<ShareScreenState>(find.byType(ShareScreen));
      expect(screenState.plaintextController.text, isEmpty);
    });
  });
}
