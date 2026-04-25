import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/crypto/argon2id.dart';
import 'package:datawallet/src/crypto/canonical_cbor.dart';
import 'package:datawallet/src/crypto/crypto_exception.dart';
import 'package:datawallet/src/crypto/ed25519.dart';
import 'package:datawallet/src/crypto/fingerprint.dart';
import 'package:datawallet/src/crypto/random.dart';
import 'package:datawallet/src/crypto/sealed_box.dart';
import 'package:datawallet/src/crypto/secret_box.dart';
import 'package:datawallet/src/crypto/sha256.dart';
import 'package:datawallet/src/crypto/uuid_v7.dart';
import 'package:datawallet/src/crypto/x25519.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';

void main() {
  late SodiumSumo sodium;
  late Directory fixturesDir;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    fixturesDir = resolveFixturesDir();
  });

  // ---------------------------------------------------------------------------
  // KEK derivation
  // ---------------------------------------------------------------------------

  group('KekDerivation', () {
    test('all password fixtures produce expected KEK', () {
      final raw = File('${fixturesDir.path}/inputs/passwords.expected.json')
          .readAsStringSync();
      final rows = jsonDecode(raw) as List<dynamic>;

      for (final row in rows) {
        final name = row['name'] as String;
        final password = row['password'] as String;
        final salt = _fromHex(row['kdf_salt_hex'] as String);
        final params = row['kdf_params'] as Map<String, dynamic>;
        final m = params['m'] as int;
        final t = params['t'] as int;
        final p = params['p'] as int;
        final expectedKek = row['expected_kek_hex'] as String;

        final kek = Argon2id.deriveKek(sodium, password, salt, m, t, p);

        expect(_toHex(kek), equals(expectedKek),
            reason: 'KEK for $name');
      }
    });

    test('rejects parallelism != 1', () {
      final salt = Uint8List(16);
      expect(
        () => Argon2id.deriveKek(sodium, 'test', salt, 65536, 1, 2),
        throwsA(isA<CryptoException>()),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // SecretBox round-trip
  // ---------------------------------------------------------------------------

  group('SecretBoxRoundTrip', () {
    test('encrypt and decrypt round-trip', () {
      final key = Rand.bytes(sodium, 32);
      final nonce = Rand.bytes(sodium, 24);
      final plaintext = utf8.encode('hello secretbox') as Uint8List;

      final ciphertext = SecretBoxCrypto.seal(sodium, plaintext, nonce, key);
      final recovered = SecretBoxCrypto.open(sodium, ciphertext, nonce, key);

      expect(recovered, equals(plaintext));
    });

    test('wrong key fails to decrypt', () {
      final key = Rand.bytes(sodium, 32);
      final wrongKey = Rand.bytes(sodium, 32);
      final nonce = Rand.bytes(sodium, 24);
      final plaintext = utf8.encode('test') as Uint8List;

      final ciphertext = SecretBoxCrypto.seal(sodium, plaintext, nonce, key);

      expect(
        () => SecretBoxCrypto.open(sodium, ciphertext, nonce, wrongKey),
        throwsA(isA<CryptoException>()),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // SealedBox
  // ---------------------------------------------------------------------------

  group('SealedBoxOpen', () {
    test('seal and open round-trip', () {
      final keypairsJson = _readJson('${fixturesDir.path}/inputs/keypairs.json');
      final seed = _fromHex(keypairsJson['alice_enc']['seed_hex'] as String);
      final kp = X25519.seedKeyPair(sodium, seed);

      final plaintext = utf8.encode('sealed box test') as Uint8List;
      final ciphertext = SealedBox.seal(sodium, plaintext, kp.publicKey);
      final recovered =
          SealedBox.open(sodium, ciphertext, kp.publicKey, kp.secretKey);

      expect(recovered, equals(plaintext));
    });

    test('open wrapped data key from fixture', () {
      final keypairsJson = _readJson('${fixturesDir.path}/inputs/keypairs.json');
      final aliceSeed = _fromHex(keypairsJson['alice_enc']['seed_hex'] as String);
      final aliceKp = X25519.seedKeyPair(sodium, aliceSeed);

      final metaJson =
          _readJson('${fixturesDir.path}/envelopes/envelope_meta.json');
      final expectedDataKey =
          _fromHex(metaJson['basic-1-recipient']['data_key_hex'] as String);

      final cbor = CanonicalCborMapper();
      final envelopeBytes = File(
              '${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
          .readAsBytesSync();
      final envelope = cbor.readValue(envelopeBytes);
      final wrappings = envelope['recipient_wrappings'] as List<dynamic>;
      final wrappedDataKey =
          (wrappings.first as Map<String, dynamic>)['wrapped_data_key']
              as Uint8List;

      final dataKey =
          SealedBox.open(sodium, wrappedDataKey, aliceKp.publicKey, aliceKp.secretKey);
      expect(dataKey, equals(expectedDataKey));
    });
  });

  // ---------------------------------------------------------------------------
  // Ed25519 determinism
  // ---------------------------------------------------------------------------

  group('Ed25519Determinism', () {
    test('seedKeyPair matches expected Ed25519 public keys', () {
      final keypairsIn = _readJson('${fixturesDir.path}/inputs/keypairs.json');
      final keypairsExp =
          _readJson('${fixturesDir.path}/inputs/keypairs.expected.json');

      for (final name in keypairsIn.keys) {
        final entry = keypairsIn[name] as Map<String, dynamic>;
        if (entry['type'] != 'ed25519') continue;

        final seed = _fromHex(entry['seed_hex'] as String);
        final kp = Ed25519.seedKeyPair(sodium, seed);
        final expectedPub =
            keypairsExp[name]['public_key_hex'] as String;

        expect(_toHex(kp.publicKey), equals(expectedPub),
            reason: 'Ed25519 public key for $name');
      }
    });

    test('seedKeyPair matches expected X25519 public keys', () {
      final keypairsIn = _readJson('${fixturesDir.path}/inputs/keypairs.json');
      final keypairsExp =
          _readJson('${fixturesDir.path}/inputs/keypairs.expected.json');

      for (final name in keypairsIn.keys) {
        final entry = keypairsIn[name] as Map<String, dynamic>;
        if (entry['type'] != 'x25519') continue;

        final seed = _fromHex(entry['seed_hex'] as String);
        final kp = X25519.seedKeyPair(sodium, seed);
        final expectedPub =
            keypairsExp[name]['public_key_hex'] as String;

        expect(_toHex(kp.publicKey), equals(expectedPub),
            reason: 'X25519 public key for $name');
      }
    });

    test('auth signature matches fixture', () {
      final authJson =
          _readJson('${fixturesDir.path}/auth/nonce-and-signature.json');
      final keypairsIn = _readJson('${fixturesDir.path}/inputs/keypairs.json');

      final signerName = authJson['signer'] as String;
      final seed =
          _fromHex(keypairsIn[signerName]['seed_hex'] as String);
      final kp = Ed25519.seedKeyPair(sodium, seed);

      final nonce = _fromHex(authJson['nonce_hex'] as String);
      final prefix = _fromHex(authJson['prefix_hex'] as String);
      final expectedSignedBytesHex =
          authJson['expected_signed_bytes_hex'] as String;
      final expectedSigHex = authJson['expected_sig_hex'] as String;

      final signedBytes =
          Uint8List(prefix.length + nonce.length)
            ..setRange(0, prefix.length, prefix)
            ..setRange(prefix.length, prefix.length + nonce.length, nonce);

      expect(_toHex(signedBytes), equals(expectedSignedBytesHex));

      final sig = Ed25519.signDetached(sodium, kp.secretKey, signedBytes);
      expect(_toHex(sig), equals(expectedSigHex));

      expect(
          Ed25519.verifyDetached(sodium, kp.publicKey, signedBytes, sig),
          isTrue);
    });

    test('verifyDetached rejects flipped bit', () {
      final authJson =
          _readJson('${fixturesDir.path}/auth/nonce-and-signature.json');
      final expectedSig = _fromHex(authJson['expected_sig_hex'] as String);
      final signedBytes =
          _fromHex(authJson['expected_signed_bytes_hex'] as String);
      final pubKey =
          _fromHex(authJson['signer_public_key_hex'] as String);

      final tampered = Uint8List.fromList(expectedSig);
      tampered[0] ^= 0x01;

      expect(
          Ed25519.verifyDetached(sodium, pubKey, signedBytes, tampered),
          isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // SHA-256
  // ---------------------------------------------------------------------------

  group('Sha256Vectors', () {
    test('empty string hash', () {
      final hash = Sha256.hash(Uint8List(0));
      expect(_toHex(hash),
          equals(
              'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));
    });

    test('"abc" hash', () {
      final hash = Sha256.hash(utf8.encode('abc') as Uint8List);
      expect(_toHex(hash),
          equals(
              'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
    });

    test('ciphertext hash matches fixture', () {
      final cbor = CanonicalCborMapper();
      final envelopeBytes = File(
              '${fixturesDir.path}/envelopes/basic-1-recipient.cbor')
          .readAsBytesSync();
      final envelope = cbor.readValue(envelopeBytes);

      final ciphertext = envelope['ciphertext'] as Uint8List;
      final ciphertextHash = envelope['ciphertext_hash'] as Uint8List;

      final computed = Sha256.hash(ciphertext);
      expect(computed, equals(ciphertextHash));
    });
  });

  // ---------------------------------------------------------------------------
  // UUIDv7
  // ---------------------------------------------------------------------------

  group('UuidV7Vectors', () {
    test('all fixture UUIDs match', () {
      final rows =
          jsonDecode(File('${fixturesDir.path}/inputs/uuids.expected.json')
              .readAsStringSync()) as List<dynamic>;

      for (final row in rows) {
        final name = row['name'] as String;
        final tsMs = row['ts_ms'] as int;
        final fullRand = _fromHex(row['rand_hex'] as String);
        final rand10 = Uint8List.fromList(fullRand.sublist(0, 10));
        final expectedHex = row['expected_hex'] as String;

        final uuidBytes = UuidV7.generate(tsMs, rand10);
        expect(_toHex(uuidBytes), equals(expectedHex),
            reason: 'UUIDv7 for $name');
      }
    });

    test('generated UUID has version 7 and RFC variant', () {
      final bytes = UuidV7.now(sodium);
      // Version nibble is at byte 6, high 4 bits
      final version = (bytes[6] >> 4) & 0x0F;
      expect(version, equals(7));
      // Variant bits at byte 8: must be 10xxxxxx
      final variant = (bytes[8] >> 6) & 0x03;
      expect(variant, equals(2));
    });
  });

  // ---------------------------------------------------------------------------
  // Fingerprint
  // ---------------------------------------------------------------------------

  group('FingerprintVectors', () {
    test('all fixture fingerprints match', () {
      final rows =
          jsonDecode(File('${fixturesDir.path}/fingerprints/pubkey-to-fp.json')
              .readAsStringSync()) as List<dynamic>;

      for (final row in rows) {
        final name = row['name'] as String;
        final pubKey = _fromHex(row['public_key_hex'] as String);
        final expectedRender = row['expected_fp_render'] as String;

        final actual = Fingerprint.render(pubKey);
        expect(actual, equals(expectedRender),
            reason: 'Fingerprint for $name');
      }
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

String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Map<String, dynamic> _readJson(String path) {
  return jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
}
