import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/crypto/canonical_cbor.dart';
import 'package:datawallet/src/crypto/ed25519.dart';
import 'package:datawallet/src/crypto/sealed_box.dart';
import 'package:datawallet/src/crypto/secret_box.dart';
import 'package:datawallet/src/crypto/sha256.dart';
import 'package:datawallet/src/crypto/x25519.dart';
import 'package:datawallet/src/envelope/builder.dart';
import 'package:datawallet/src/envelope/directory_key_view.dart';
import 'package:datawallet/src/envelope/envelope_codec.dart';
import 'package:datawallet/src/envelope/envelope_signer.dart';
import 'package:datawallet/src/envelope/envelope_verifier.dart';
import 'package:datawallet/src/envelope/issuer_key_resolver.dart';
import 'package:datawallet/src/envelope/shared_envelope.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';

void main() {
  late SodiumSumo sodium;
  late Directory fixturesDir;

  late Map<String, dynamic> keypairsInput;
  late Map<String, dynamic> plaintexts;
  late Map<String, dynamic> timestamps;
  late Map<String, dynamic> mobileMeta;
  late Map<String, dynamic> directoryMeta;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    fixturesDir = resolveFixturesDir();

    keypairsInput = _readJson('${fixturesDir.path}/inputs/keypairs.json');
    plaintexts = _readJson('${fixturesDir.path}/inputs/plaintexts.json');
    timestamps = _readJson('${fixturesDir.path}/inputs/timestamps.json');
    mobileMeta = _readJson(
        '${fixturesDir.path}/envelopes/mobile-built/mobile_meta.json');
    directoryMeta =
        _readJson('${fixturesDir.path}/directory/directory_meta.json');
  });

  Ed25519KeyPair mobileSignKeyPair() {
    final seed =
        _fromHex(keypairsInput['mobile_install_sign']['seed_hex'] as String);
    return Ed25519.seedKeyPair(sodium, seed);
  }

  IssuerKeyResolver mobileKeyResolver() {
    final mobile = mobileSignKeyPair();
    final mobileKeyId =
        _fromHex(directoryMeta['key_ids']['mobile_install_sign'] as String);
    final meta = mobileMeta['single-recipient'] as Map<String, dynamic>;
    final expectedIssuerId = _fromHex(meta['issuer_id_hex'] as String);
    final validFrom = directoryMeta['acme_signing_key_valid_from'] as int;
    final validUntil = directoryMeta['acme_signing_key_valid_until'] as int;

    return (issuerId, signingKeyId, atMs) {
      if (_bytesEqual(issuerId, expectedIssuerId) &&
          _bytesEqual(signingKeyId, mobileKeyId)) {
        return DirectoryKeyView(
          issuerId: expectedIssuerId,
          keyId: mobileKeyId,
          publicKey: mobile.publicKey,
          status: 'active',
          validFrom: validFrom,
          validUntil: validUntil,
        );
      }
      return null;
    };
  }

  group('MobileEnvelopeFixture', () {
    test('mobile-built envelope parses and verifies', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/mobile-built/single-recipient.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, mobileKeyResolver());
      final env = verifier.verify(bytes);

      expect(env.version, equals(1));
      expect(env.issuerLabel, equals('Mobile Install'));
      expect(env.description, equals('Mobile-issued credential'));
      expect(env.recipientWrappings, hasLength(1));
    });

    test('signed bytes match .signed fixture', () {
      final codec = EnvelopeCodec();
      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/mobile-built/single-recipient.cbor')
              .readAsBytesSync();
      final expectedSigned =
          File('${fixturesDir.path}/envelopes/mobile-built/single-recipient.signed')
              .readAsBytesSync();
      final env = codec.decode(envelopeBytes);
      final signedBytes = codec.signedBytesOf(env.withSignature(null));
      expect(signedBytes, equals(expectedSigned));
    });

    test('signature verifies under mobile_install_sign public key', () {
      final codec = EnvelopeCodec();
      final mobile = mobileSignKeyPair();

      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/mobile-built/single-recipient.cbor')
              .readAsBytesSync();
      final env = codec.decode(envelopeBytes);
      final signedBytes = codec.signedBytesOf(env.withSignature(null));
      final valid = Ed25519.verifyDetached(
          sodium, mobile.publicKey, signedBytes, env.signature!);
      expect(valid, isTrue);
    });

    test('build from inputs produces byte-identical fixture', () {
      final meta = mobileMeta['single-recipient'] as Map<String, dynamic>;
      final dataKey = _fromHex(meta['data_key_hex'] as String);
      final ctNonce = _fromHex(meta['ciphertext_nonce_hex'] as String);
      final plaintext = plaintexts[meta['plaintext_key'] as String] as String;
      final issuerId = _fromHex(meta['issuer_id_hex'] as String);
      final mobileKeyId =
          _fromHex(directoryMeta['key_ids']['mobile_install_sign'] as String);
      final aliceVerifierId =
          _fromHex(directoryMeta['verifier_ids']['alice'] as String);
      final aliceKeyId =
          _fromHex(directoryMeta['key_ids']['alice_enc'] as String);

      final existingEnvelopeBytes =
          File('${fixturesDir.path}/envelopes/mobile-built/single-recipient.cbor')
              .readAsBytesSync();
      final existingMap =
          CanonicalCborMapper().readValue(existingEnvelopeBytes);
      final existingWrappings =
          existingMap['recipient_wrappings'] as List<dynamic>;
      final wrappedDataKey =
          (existingWrappings.first as Map<String, dynamic>)['wrapped_data_key']
              as Uint8List;

      final uuidsExpected =
          _readJsonList('${fixturesDir.path}/inputs/uuids.expected.json');
      final entryMobileHex = uuidsExpected
          .firstWhere((e) => e['name'] == 'entry_mobile')['expected_hex'] as String;
      final entryId = _fromHex(entryMobileHex);

      final builder = EnvelopeBuilder(sodium);
      final mobile = mobileSignKeyPair();
      final result = builder.buildDeterministic(
        plaintextContent: plaintext,
        entryId: entryId,
        issuerId: issuerId,
        issuerLabel: 'Mobile Install',
        issuerSigningKeyId: mobileKeyId,
        issuerSecretKey: mobile.secretKey,
        createdAt: timestamps['t_envelope_v2'] as int,
        description: 'Mobile-issued credential',
        dataKey: dataKey,
        ciphertextNonce: ctNonce,
        recipientWrappings: [
          RecipientWrapping(
            verifierId: aliceVerifierId,
            verifierKeyId: aliceKeyId,
            wrappedDataKey: wrappedDataKey,
          ),
        ],
      );

      expect(result.signedEnvelopeBytes, equals(existingEnvelopeBytes));
    });

    test('decrypt mobile envelope end-to-end', () {
      final verifier = EnvelopeVerifier(sodium, mobileKeyResolver());
      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/mobile-built/single-recipient.cbor')
              .readAsBytesSync();
      final env = verifier.verify(envelopeBytes);

      final aliceSeed =
          _fromHex(keypairsInput['alice_enc']['seed_hex'] as String);
      final aliceKp = X25519.seedKeyPair(sodium, aliceSeed);

      final wrappedDataKey = env.recipientWrappings.first.wrappedDataKey;
      final dataKey = SealedBox.open(
          sodium, wrappedDataKey, aliceKp.publicKey, aliceKp.secretKey);
      final decrypted = SecretBoxCrypto.open(
          sodium, env.ciphertext, env.ciphertextNonce, dataKey);
      final text = utf8.decode(decrypted);

      final verifiedMeta = _readJson(
          '${fixturesDir.path}/envelopes/server-side-verified/single-recipient.json');
      final expected = (verifiedMeta['single-recipient']
          as Map<String, dynamic>)['expected_plaintext'] as String;
      expect(text, equals(expected));
    });
  });

  group('V1EnvelopeUnchanged', () {
    test('existing v1 envelopes still round-trip byte-identically', () {
      final codec = EnvelopeCodec();
      for (final name in [
        'basic-1-recipient',
        'three-recipients',
        'allow-list-update-v2',
        'unicode-description',
      ]) {
        final bytes =
            File('${fixturesDir.path}/envelopes/$name.cbor').readAsBytesSync();
        final env = codec.decode(bytes);
        final reencoded = codec.encode(env);
        expect(reencoded, equals(bytes), reason: 'round-trip for $name');
      }
    });
  });

  group('BinaryPayloadFixture', () {
    late Map<String, dynamic> binaryVerifiedMeta;

    setUp(() {
      binaryVerifiedMeta = _readJson(
          '${fixturesDir.path}/envelopes/server-side-verified/binary-payload.json');
    });

    test('binary-payload envelope parses and verifies', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/mobile-built/binary-payload.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, mobileKeyResolver());
      final env = verifier.verify(bytes);

      expect(env.version, equals(1));
      expect(env.issuerLabel, equals('Mobile Install'));
      expect(env.description, equals('Binary payload test credential'));
      expect(env.recipientWrappings, hasLength(1));
    });

    test('binary-payload decrypt end-to-end', () {
      final verifier = EnvelopeVerifier(sodium, mobileKeyResolver());
      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/mobile-built/binary-payload.cbor')
              .readAsBytesSync();
      final env = verifier.verify(envelopeBytes);

      final aliceSeed =
          _fromHex(keypairsInput['alice_enc']['seed_hex'] as String);
      final aliceKp = X25519.seedKeyPair(sodium, aliceSeed);

      final wrappedDataKey = env.recipientWrappings.first.wrappedDataKey;
      final dataKey = SealedBox.open(
          sodium, wrappedDataKey, aliceKp.publicKey, aliceKp.secretKey);
      final decrypted =
          SecretBoxCrypto.open(sodium, env.ciphertext, env.ciphertextNonce, dataKey);

      final expected = _fromHex(
          (binaryVerifiedMeta['binary-payload'] as Map<String, dynamic>)['expected_payload_bytes_hex']
              as String);
      expect(decrypted, equals(expected));
    });

    test('binary-payload-multi envelope parses and verifies', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/mobile-built/binary-payload-multi.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, mobileKeyResolver());
      final env = verifier.verify(bytes);

      expect(env.version, equals(1));
      expect(env.issuerLabel, equals('Mobile Install'));
      expect(env.description,
          equals('Binary payload multi-recipient test credential'));
      expect(env.recipientWrappings, hasLength(2));
    });

    test('binary-payload-multi decrypt end-to-end (alice)', () {
      final verifier = EnvelopeVerifier(sodium, mobileKeyResolver());
      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/mobile-built/binary-payload-multi.cbor')
              .readAsBytesSync();
      final env = verifier.verify(envelopeBytes);

      final aliceSeed =
          _fromHex(keypairsInput['alice_enc']['seed_hex'] as String);
      final aliceKp = X25519.seedKeyPair(sodium, aliceSeed);

      final wrappedDataKey = env.recipientWrappings.first.wrappedDataKey;
      final dataKey = SealedBox.open(
          sodium, wrappedDataKey, aliceKp.publicKey, aliceKp.secretKey);
      final decrypted =
          SecretBoxCrypto.open(sodium, env.ciphertext, env.ciphertextNonce, dataKey);

      final expected = _fromHex(
          (binaryVerifiedMeta['binary-payload-multi'] as Map<String, dynamic>)['expected_payload_bytes_hex']
              as String);
      expect(decrypted, equals(expected));
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

Map<String, dynamic> _readJson(String path) =>
    jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;

List<Map<String, dynamic>> _readJsonList(String path) =>
    (jsonDecode(File(path).readAsStringSync()) as List<dynamic>)
        .cast<Map<String, dynamic>>();

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
