import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/crypto/canonical_cbor.dart';
import 'package:datawallet/src/crypto/ed25519.dart';
import 'package:datawallet/src/crypto/sealed_box.dart';
import 'package:datawallet/src/crypto/secret_box.dart';
import 'package:datawallet/src/crypto/sha256.dart';
import 'package:datawallet/src/crypto/x25519.dart';
import 'package:datawallet/src/envelope/directory_key_view.dart';
import 'package:datawallet/src/envelope/envelope_codec.dart';
import 'package:datawallet/src/envelope/envelope_rejection.dart';
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
  late Map<String, dynamic> envelopeMeta;
  late Map<String, dynamic> directoryMeta;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    fixturesDir = resolveFixturesDir();

    keypairsInput = _readJson('${fixturesDir.path}/inputs/keypairs.json');
    plaintexts = _readJson('${fixturesDir.path}/inputs/plaintexts.json');
    timestamps = _readJson('${fixturesDir.path}/inputs/timestamps.json');
    envelopeMeta =
        _readJson('${fixturesDir.path}/envelopes/envelope_meta.json');
    directoryMeta =
        _readJson('${fixturesDir.path}/directory/directory_meta.json');
  });

  Ed25519KeyPair acmeSignKeyPair() {
    final seed = _fromHex(keypairsInput['acme_sign']['seed_hex'] as String);
    return Ed25519.seedKeyPair(sodium, seed);
  }

  IssuerKeyResolver acmeKeyResolver() {
    final acme = acmeSignKeyPair();
    final acmeKeyId =
        _fromHex(directoryMeta['key_ids']['acme_sign'] as String);
    final expectedIssuerId =
        _fromHex(directoryMeta['issuer_id_hex'] as String);
    final validFrom = directoryMeta['acme_signing_key_valid_from'] as int;
    final validUntil = directoryMeta['acme_signing_key_valid_until'] as int;

    return (issuerId, signingKeyId, atMs) {
      if (_bytesEqual(issuerId, expectedIssuerId) &&
          _bytesEqual(signingKeyId, acmeKeyId)) {
        return DirectoryKeyView(
          issuerId: expectedIssuerId,
          keyId: acmeKeyId,
          publicKey: acme.publicKey,
          status: 'active',
          validFrom: validFrom,
          validUntil: validUntil,
        );
      }
      return null;
    };
  }

  // ---------------------------------------------------------------------------
  // Positive
  // ---------------------------------------------------------------------------

  group('Positive', () {
    test('basic envelope parses', () {
      final codec = EnvelopeCodec();
      final bytes =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();
      final env = codec.decode(bytes);

      expect(env.version, equals(1));
      expect(env.issuerLabel, equals('Acme Corp'));
      expect(env.signature, isNotNull);
      expect(env.recipientWrappings, hasLength(1));
    });

    test('all positive envelopes parse and verify', () {
      final verifier = EnvelopeVerifier(sodium, acmeKeyResolver());

      for (final name in [
        'basic-1-recipient',
        'three-recipients',
        'allow-list-update-v2',
        'unicode-description',
      ]) {
        final bytes =
            File('${fixturesDir.path}/envelopes/$name.cbor').readAsBytesSync();
        final env = verifier.verify(bytes);
        expect(env.version, equals(1), reason: 'version for $name');
      }
    });

    test('signed bytes match .signed fixtures', () {
      final codec = EnvelopeCodec();
      for (final name in [
        'basic-1-recipient',
        'three-recipients',
        'allow-list-update-v2',
        'unicode-description',
      ]) {
        final envelopeBytes =
            File('${fixturesDir.path}/envelopes/$name.cbor').readAsBytesSync();
        final expectedSigned =
            File('${fixturesDir.path}/envelopes/$name.signed')
                .readAsBytesSync();
        final env = codec.decode(envelopeBytes);
        final signedBytes = codec.signedBytesOf(env.withSignature(null));
        expect(signedBytes, equals(expectedSigned),
            reason: 'signed bytes for $name');
      }
    });

    test('signature verifies under acme_sign public key', () {
      final codec = EnvelopeCodec();
      final acme = acmeSignKeyPair();

      for (final name in [
        'basic-1-recipient',
        'three-recipients',
        'allow-list-update-v2',
        'unicode-description',
      ]) {
        final envelopeBytes =
            File('${fixturesDir.path}/envelopes/$name.cbor').readAsBytesSync();
        final env = codec.decode(envelopeBytes);
        final signedBytes = codec.signedBytesOf(env.withSignature(null));
        final valid = Ed25519.verifyDetached(
            sodium, acme.publicKey, signedBytes, env.signature!);
        expect(valid, isTrue, reason: 'signature valid for $name');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Round-trip
  // ---------------------------------------------------------------------------

  group('RoundTrip', () {
    test('build basic envelope from inputs matches fixture', () {
      final basicMeta =
          envelopeMeta['basic-1-recipient'] as Map<String, dynamic>;
      final dataKey = _fromHex(basicMeta['data_key_hex'] as String);
      final ctNonce = _fromHex(basicMeta['ciphertext_nonce_hex'] as String);
      final plaintext =
          Uint8List.fromList(utf8.encode(plaintexts['basic'] as String));

      final ciphertext =
          SecretBoxCrypto.seal(sodium, plaintext, ctNonce, dataKey);
      final ciphertextHash = Sha256.hash(ciphertext);

      final aliceSeed =
          _fromHex(keypairsInput['alice_enc']['seed_hex'] as String);
      final aliceKp = X25519.seedKeyPair(sodium, aliceSeed);

      final issuerId = _fromHex(directoryMeta['issuer_id_hex'] as String);
      final entryId = _fromHex('0194244fd80072428242424242424242');
      final acmeKeyId =
          _fromHex(directoryMeta['key_ids']['acme_sign'] as String);
      final aliceVerifierId =
          _fromHex(directoryMeta['verifier_ids']['alice'] as String);
      final aliceKeyId =
          _fromHex(directoryMeta['key_ids']['alice_enc'] as String);

      // Retrieve the existing wrapped data key from the fixture
      final existingEnvelopeBytes =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();
      final existingMap = CanonicalCborMapper().readValue(existingEnvelopeBytes);
      final existingWrappings =
          existingMap['recipient_wrappings'] as List<dynamic>;
      final wrappedDataKey =
          (existingWrappings.first as Map<String, dynamic>)['wrapped_data_key']
              as Uint8List;

      final unsigned = SharedEnvelope(
        version: 1,
        entryId: entryId,
        issuerId: issuerId,
        issuerLabel: 'Acme Corp',
        issuerSigningKeyId: acmeKeyId,
        createdAt: timestamps['t_envelope_basic'] as int,
        description: 'Basic test credential',
        ciphertextAlg: 'xsalsa20poly1305',
        ciphertextNonce: ctNonce,
        ciphertext: ciphertext,
        ciphertextHash: ciphertextHash,
        recipientWrappings: [
          RecipientWrapping(
            verifierId: aliceVerifierId,
            verifierKeyId: aliceKeyId,
            wrappedDataKey: wrappedDataKey,
          )
        ],
      );

      final signer = EnvelopeSigner(sodium);
      final acme = acmeSignKeyPair();
      final finalBytes = signer.sign(unsigned, acme.secretKey);

      final expected =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();
      expect(finalBytes, equals(expected));
    });

    test('decrypt basic envelope end-to-end', () {
      final verifier = EnvelopeVerifier(sodium, acmeKeyResolver());

      final envelopeBytes =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();
      final env = verifier.verify(envelopeBytes);

      final aliceSeed =
          _fromHex(keypairsInput['alice_enc']['seed_hex'] as String);
      final aliceKp = X25519.seedKeyPair(sodium, aliceSeed);

      final wrappedDataKey = env.recipientWrappings.first.wrappedDataKey;
      final dataKey = SealedBox.open(
          sodium, wrappedDataKey, aliceKp.publicKey, aliceKp.secretKey);
      final plaintext = SecretBoxCrypto.open(
          sodium, env.ciphertext, env.ciphertextNonce, dataKey);
      final text = utf8.decode(plaintext);

      expect(text, equals(plaintexts['basic'] as String));
    });
  });

  // ---------------------------------------------------------------------------
  // Negative
  // ---------------------------------------------------------------------------

  group('Negative', () {
    test('non-canonical CBOR throws MalformedCbor', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/invalid/non-canonical-cbor.cbor')
              .readAsBytesSync();
      final codec = EnvelopeCodec();
      expect(() => codec.decode(bytes), throwsA(isA<MalformedCbor>()));
    });

    test('future version throws UnsupportedVersion', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/invalid/future-version.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, acmeKeyResolver());
      expect(
          () => verifier.verify(bytes), throwsA(isA<UnsupportedVersion>()));
    });

    test('wrong issuer key throws SignatureInvalid', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/invalid/wrong-issuer-key.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, acmeKeyResolver());
      expect(
          () => verifier.verify(bytes), throwsA(isA<SignatureInvalid>()));
    });

    test('tampered ciphertext throws SignatureInvalid', () {
      // The fixture also updates ciphertext_hash, so the signature is
      // over wrong bytes → SignatureInvalid fires before CiphertextHashMismatch.
      final bytes =
          File('${fixturesDir.path}/envelopes/invalid/tampered-ciphertext.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, acmeKeyResolver());
      expect(
          () => verifier.verify(bytes), throwsA(isA<SignatureInvalid>()));
    });

    test('stale key ID throws IssuerKeyNotActiveAt', () {
      final bytes =
          File('${fixturesDir.path}/envelopes/invalid/stale-key-id.cbor')
              .readAsBytesSync();
      final verifier = EnvelopeVerifier(sodium, acmeKeyResolver());
      expect(() => verifier.verify(bytes),
          throwsA(isA<IssuerKeyNotActiveAt>()));
    });
  });

  // ---------------------------------------------------------------------------
  // Verification order
  // ---------------------------------------------------------------------------

  group('VerificationOrder', () {
    test('sha256 check happens after signature verification', () {
      final codec = EnvelopeCodec();

      final fakeSeed = Uint8List.fromList(List.filled(32, 0xFF));
      final fakeKey = Ed25519.seedKeyPair(sodium, fakeSeed);

      final acmeKeyId =
          _fromHex(directoryMeta['key_ids']['acme_sign'] as String);
      final expectedIssuerId =
          _fromHex(directoryMeta['issuer_id_hex'] as String);
      final validFrom = directoryMeta['acme_signing_key_valid_from'] as int;
      final validUntil = directoryMeta['acme_signing_key_valid_until'] as int;

      final originalBytes =
          File('${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
              .readAsBytesSync();
      final original = codec.decode(originalBytes);

      final tamperedCt = Uint8List.fromList(original.ciphertext);
      tamperedCt[0] ^= 0xFF;
      final tamperedHash = Sha256.hash(tamperedCt);

      final tamperedUnsigned = SharedEnvelope(
        version: original.version,
        entryId: original.entryId,
        issuerId: original.issuerId,
        issuerLabel: original.issuerLabel,
        issuerSigningKeyId: original.issuerSigningKeyId,
        createdAt: original.createdAt,
        description: original.description,
        ciphertextAlg: original.ciphertextAlg,
        ciphertextNonce: original.ciphertextNonce,
        ciphertext: tamperedCt,
        ciphertextHash: tamperedHash,
        recipientWrappings: original.recipientWrappings,
      );

      final signer = EnvelopeSigner(sodium);
      final signedWithFakeKey =
          signer.sign(tamperedUnsigned, fakeKey.secretKey);

      final acme = acmeSignKeyPair();
      IssuerKeyResolver acmeResolver = (issuerId, signingKeyId, atMs) {
        if (_bytesEqual(issuerId, expectedIssuerId) &&
            _bytesEqual(signingKeyId, acmeKeyId)) {
          return DirectoryKeyView(
            issuerId: expectedIssuerId,
            keyId: acmeKeyId,
            publicKey: acme.publicKey,
            status: 'active',
            validFrom: validFrom,
            validUntil: validUntil,
          );
        }
        return null;
      };

      final verifier = EnvelopeVerifier(sodium, acmeResolver);
      expect(() => verifier.verify(signedWithFakeKey),
          throwsA(isA<SignatureInvalid>()));
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Uint8List _fromHex(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

Map<String, dynamic> _readJson(String path) =>
    jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
