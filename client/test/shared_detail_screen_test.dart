import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/api/directory_client.dart';
import 'package:datawallet/src/api/shared_client.dart';
import 'package:datawallet/src/crypto/ed25519.dart';
import 'package:datawallet/src/crypto/x25519.dart';
import 'package:datawallet/src/directory/directory_record_codec.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:datawallet/src/screens/shared_detail_screen.dart';
import 'package:datawallet/src/state/session.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sodium/sodium_sumo.dart';

class _MockSharedClient extends Mock implements SharedClient {}

class _MockDirectoryClient extends Mock implements DirectoryClient {}

void main() {
  late SodiumSumo sodium;
  late Directory fixturesDir;
  late Map<String, dynamic> directoryMeta;
  late Map<String, dynamic> keypairs;
  late Map<String, dynamic> plaintexts;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    fixturesDir = resolveFixturesDir();
    directoryMeta =
        _readJson('${fixturesDir.path}/directory/directory_meta.json');
    keypairs = _readJson('${fixturesDir.path}/inputs/keypairs.json');
    plaintexts = _readJson('${fixturesDir.path}/inputs/plaintexts.json');
  });

  Session _aliceSession() {
    final encSeed =
        _fromHex(keypairs['alice_enc']['seed_hex'] as String);
    final authSeed =
        _fromHex(keypairs['alice_auth']['seed_hex'] as String);
    final encKp = X25519.seedKeyPair(sodium, encSeed);
    final authKp = Ed25519.seedKeyPair(sodium, authSeed);

    return Session(
      verifierId:
          _fromHex(directoryMeta['verifier_ids']['alice'] as String),
      token: 'test-token',
      authPublicKey: authKp.publicKey,
      encPublicKey: encKp.publicKey,
      encPrivKey: encKp.secretKey,
      authPrivKey: authKp.secretKey,
    );
  }

  /// Returns a [DirectoryRecordWrapper] built from the fixture CBOR file.
  DirectoryRecordWrapper _acmeDirectoryRecord() {
    final signedRecord =
        File('${fixturesDir.path}/directory/issuer-acme-active.cbor')
            .readAsBytesSync();
    final codec = DirectoryRecordCodec();
    final rec = codec.decode(signedRecord);
    return DirectoryRecordWrapper(
      keyId: 'placeholder',
      status: rec.status,
      validFrom: '2025-01-01T00:00:00Z',
      validUntil: '2026-01-01T00:00:00Z',
      issuedAt: '2025-01-01T00:00:00Z',
      signedRecord: signedRecord,
    );
  }

  Widget _buildScreen(
    SharedClient sharedClient,
    DirectoryClient directoryClient,
    String entryId,
    Session session,
  ) {
    return MaterialApp(
      home: SharedDetailScreen(
        sharedClient: sharedClient,
        directoryClient: directoryClient,
        session: session,
        sodium: sodium,
        entryId: entryId,
      ),
    );
  }

  group('SharedDetailScreen happy path', () {
    testWidgets('decrypts and renders fixture plaintext', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final session = _aliceSession();

      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();

      // Use any() to avoid string-format matching brittleness.
      when(() => mockShared.getShared(any(), any()))
          .thenAnswer((_) async => envelopeBytes);
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => [_acmeDirectoryRecord()]);

      await tester.pumpWidget(
          _buildScreen(mockShared, mockDir, 'some-entry-id', session));
      await tester.pumpAndSettle();

      // Fail with the actual error message if the error widget is showing.
      final errorFinder = find.byKey(const Key('detail_error'));
      if (errorFinder.evaluate().isNotEmpty) {
        fail('Unexpected detail error: '
            '${tester.widget<Text>(errorFinder).data}');
      }

      // Plaintext renders
      expect(find.byKey(const Key('plaintext')), findsOneWidget);
      final text = tester.widget<SelectableText>(
          find.byKey(const Key('plaintext'))).data;
      expect(text, equals(plaintexts['basic'] as String));
    });

    testWidgets('issuer fingerprint renders on success', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final session = _aliceSession();

      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();

      when(() => mockShared.getShared(any(), any()))
          .thenAnswer((_) async => envelopeBytes);
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => [_acmeDirectoryRecord()]);

      await tester.pumpWidget(
          _buildScreen(mockShared, mockDir, 'some-entry-id', session));
      await tester.pumpAndSettle();

      final errorFinder = find.byKey(const Key('detail_error'));
      if (errorFinder.evaluate().isNotEmpty) {
        fail('Unexpected detail error: '
            '${tester.widget<Text>(errorFinder).data}');
      }

      expect(find.byKey(const Key('issuer_fingerprint')), findsOneWidget);
    });
  });

  group('SharedDetailScreen signature invalid', () {
    testWidgets('wrong-issuer-key renders error, no plaintext', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final session = _aliceSession();

      // wrong-issuer-key.cbor has a valid acme key resolver but the signature
      // was made with a different key → SignatureInvalid
      final invalidEnvelopeBytes = File(
              '${fixturesDir.path}/envelopes/invalid/wrong-issuer-key.cbor')
          .readAsBytesSync();

      when(() => mockShared.getShared(any(), any()))
          .thenAnswer((_) async => invalidEnvelopeBytes);
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => [_acmeDirectoryRecord()]);

      await tester.pumpWidget(
          _buildScreen(mockShared, mockDir, 'some-entry-id', session));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('detail_error')), findsOneWidget);
      expect(find.byKey(const Key('plaintext')), findsNothing);

      // verify was not called (can't check SealedBox.open which is static,
      // but plaintext absent confirms decryption was never reached)
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Map<String, dynamic> _readJson(String path) =>
    jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;

Uint8List _fromHex(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

String _uuidString(Uint8List bytes) {
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}
