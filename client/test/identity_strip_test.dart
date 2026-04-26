import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/crypto/fingerprint.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:datawallet/src/widgets/identity_strip.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory fixturesDir;
  late List<dynamic> fpVectors;

  setUpAll(() {
    fixturesDir = resolveFixturesDir();
    fpVectors = jsonDecode(
      File('${fixturesDir.path}/fingerprints/pubkey-to-fp.json')
          .readAsStringSync(),
    ) as List<dynamic>;
  });

  Widget _buildStrip({
    required String handle,
    required Uint8List publicKey,
    String? displayName,
  }) {
    return MaterialApp(
      home: Scaffold(
        body: IdentityStrip(
          handle: handle,
          publicKey: publicKey,
          displayName: displayName,
        ),
      ),
    );
  }

  group('IdentityStrip', () {
    test('Fingerprint.render matches fixture pubkey-to-fp.json vectors', () {
      for (final entry in fpVectors) {
        final map = entry as Map<String, dynamic>;
        final pubKey = _fromHex(map['public_key_hex'] as String);
        final expected = map['expected_fp_render'] as String;
        expect(Fingerprint.render(pubKey), equals(expected),
            reason: 'fingerprint for ${map['name']}');
      }
    });

    testWidgets('renders handle and fingerprint for alice_enc key',
        (tester) async {
      final vector = fpVectors
          .firstWhere((e) => (e as Map)['name'] == 'alice_enc')
          as Map<String, dynamic>;
      final pubKey = _fromHex(vector['public_key_hex'] as String);
      final expectedFp = vector['expected_fp_render'] as String;

      await tester.pumpWidget(_buildStrip(handle: 'alice', publicKey: pubKey));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('identity_handle')), findsOneWidget);
      expect(find.byKey(const Key('identity_fingerprint')), findsOneWidget);

      final handleText =
          tester.widget<Text>(find.byKey(const Key('identity_handle'))).data;
      expect(handleText, equals('@alice'));

      final fpText =
          tester.widget<Text>(find.byKey(const Key('identity_fingerprint'))).data;
      expect(fpText, equals(expectedFp));
    });

    testWidgets('fingerprint is the load-bearing identity, not display_name',
        (tester) async {
      final vector = fpVectors
          .firstWhere((e) => (e as Map)['name'] == 'alice_enc')
          as Map<String, dynamic>;
      final pubKey = _fromHex(vector['public_key_hex'] as String);
      final expectedFp = vector['expected_fp_render'] as String;

      // Simulate a malicious display name designed to impersonate another key.
      const maliciousName = '2BWZ-M3AH-ISQG-WXHR (admin)';

      await tester.pumpWidget(_buildStrip(
        handle: 'alice',
        publicKey: pubKey,
        displayName: maliciousName,
      ));
      await tester.pumpAndSettle();

      // Fingerprint still renders independently from the display name.
      final fpText =
          tester.widget<Text>(find.byKey(const Key('identity_fingerprint'))).data;
      expect(fpText, equals(expectedFp),
          reason: 'cryptographic fingerprint must not be influenced by display_name');

      // Display name rendered with "presentation only" caveat.
      expect(find.byKey(const Key('identity_display_name')), findsOneWidget);
      expect(
          find.byKey(const Key('identity_presentation_only_badge')), findsOneWidget);

      final badgeText = tester
          .widget<Text>(find.byKey(const Key('identity_presentation_only_badge')))
          .data;
      expect(badgeText, equals('presentation only'));
    });

    testWidgets('no display_name hides display_name row', (tester) async {
      final pubKey = _fromHex(
        (fpVectors.first as Map<String, dynamic>)['public_key_hex'] as String,
      );

      await tester.pumpWidget(
          _buildStrip(handle: 'bob', publicKey: pubKey, displayName: null));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('identity_display_name')), findsNothing);
      expect(
          find.byKey(const Key('identity_presentation_only_badge')), findsNothing);
    });

    testWidgets('fingerprint renders identically to Fingerprint.render()',
        (tester) async {
      // Uses the acme_sign vector to cross-check widget rendering vs pure function.
      final vector = fpVectors
          .firstWhere((e) => (e as Map)['name'] == 'acme_sign')
          as Map<String, dynamic>;
      final pubKey = _fromHex(vector['public_key_hex'] as String);
      final expected = Fingerprint.render(pubKey);

      await tester.pumpWidget(_buildStrip(handle: 'acme', publicKey: pubKey));
      await tester.pumpAndSettle();

      final fpText =
          tester.widget<Text>(find.byKey(const Key('identity_fingerprint'))).data;
      expect(fpText, equals(expected));
      expect(fpText, equals(vector['expected_fp_render']));
    });
  });
}

Uint8List _fromHex(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}
