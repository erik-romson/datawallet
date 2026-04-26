import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/directory/directory_record.dart';
import 'package:datawallet/src/directory/directory_record_codec.dart';
import 'package:datawallet/src/directory/directory_record_verifier.dart';
import 'package:datawallet/src/directory/directory_rejection.dart';
import 'package:datawallet/src/directory/root_quorum.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';

void main() {
  late SodiumSumo sodium;
  late Directory fixturesDir;

  late PinnedRoot pinnedRoot;
  late Map<String, dynamic> keypairsExpected;
  late Map<String, dynamic> directoryMeta;
  late Map<String, dynamic> timestamps;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    fixturesDir = resolveFixturesDir();

    final codec = DirectoryRecordCodec();
    final pinnedRootBytes =
        File('${fixturesDir.path}/directory/pinned-root.cbor').readAsBytesSync();
    pinnedRoot = codec.decodePinnedRoot(pinnedRootBytes);

    keypairsExpected =
        _readJson('${fixturesDir.path}/inputs/keypairs.expected.json');
    directoryMeta =
        _readJson('${fixturesDir.path}/directory/directory_meta.json');
    timestamps = _readJson('${fixturesDir.path}/inputs/timestamps.json');
  });

  DirectoryRecordVerifier verifierAtTime(int timeMs) =>
      DirectoryRecordVerifier(sodium, nowMs: () => timeMs);

  // ---------------------------------------------------------------------------
  // PinnedRootParsing
  // ---------------------------------------------------------------------------

  group('PinnedRootParsing', () {
    test('pinned root has expected structure', () {
      expect(pinnedRoot.version, equals(1));
      expect(pinnedRoot.scheme, equals('ed25519-quorum-v1'));
      expect(pinnedRoot.threshold, equals(2));
      expect(pinnedRoot.roots, hasLength(3));
    });

    test('pinned root keys match expected', () {
      final expectedKeyNames = ['root_a', 'root_b', 'root_c'];
      for (var i = 0; i < 3; i++) {
        final root = pinnedRoot.roots[i];
        final expectedPubHex =
            keypairsExpected[expectedKeyNames[i]]['public_key_hex'] as String;
        expect(_toHex(root.publicKey), equals(expectedPubHex),
            reason: 'public key for ${expectedKeyNames[i]}');

        final expectedKeyIdHex =
            directoryMeta['key_ids'][expectedKeyNames[i]] as String;
        expect(_toHex(root.rootKeyId), equals(expectedKeyIdHex),
            reason: 'key_id for ${expectedKeyNames[i]}');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // PositiveDirectoryRecords
  // ---------------------------------------------------------------------------

  group('PositiveDirectoryRecords', () {
    test('verifier-alice-active verifies', () {
      final bytes =
          File('${fixturesDir.path}/directory/verifier-alice-active.cbor')
              .readAsBytesSync();
      final issuedAt = timestamps['t_directory_issued'] as int;
      final v = verifierAtTime(issuedAt + 1000);
      final record = v.verify(bytes, pinnedRoot);

      expect(record.version, equals(1));
      expect(record.recordType, equals('verifier'));
      expect(record.keyUse, equals('enc'));
      expect(record.status, equals('active'));
      expect(record.rootSignatures, hasLength(2));

      final expectedPubHex =
          keypairsExpected['alice_enc']['public_key_hex'] as String;
      expect(_toHex(record.publicKey), equals(expectedPubHex));
    });

    test('verifier-alice-revoked verifies', () {
      final bytes =
          File('${fixturesDir.path}/directory/verifier-alice-revoked.cbor')
              .readAsBytesSync();
      final issuedAt = timestamps['t_directory_issued'] as int;
      final v = verifierAtTime(issuedAt + 1000);
      final record = v.verify(bytes, pinnedRoot);

      expect(record.status, equals('revoked'));
      expect(record.rootSignatures, hasLength(2));
    });

    test('issuer-acme-active verifies', () {
      final bytes =
          File('${fixturesDir.path}/directory/issuer-acme-active.cbor')
              .readAsBytesSync();
      final issuedAt = timestamps['t_directory_issued'] as int;
      final v = verifierAtTime(issuedAt + 1000);
      final record = v.verify(bytes, pinnedRoot);

      expect(record.recordType, equals('issuer'));
      expect(record.keyUse, equals('sign'));
      expect(record.status, equals('active'));

      final expectedPubHex =
          keypairsExpected['acme_sign']['public_key_hex'] as String;
      expect(_toHex(record.publicKey), equals(expectedPubHex));
    });

    test('signedBytesOf from record and from bytes are consistent', () {
      final codec = DirectoryRecordCodec();
      for (final name in [
        'verifier-alice-active',
        'verifier-alice-revoked',
        'issuer-acme-active',
      ]) {
        final bytes =
            File('${fixturesDir.path}/directory/$name.cbor').readAsBytesSync();
        final record = codec.decode(bytes);
        final fromRecord = codec.signedBytesOfRecord(record);
        final fromBytes = codec.signedBytesOfEncoded(bytes);
        expect(fromRecord, equals(fromBytes),
            reason: 'signedBytesOf consistency for $name');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // NegativeDirectoryRecords
  // ---------------------------------------------------------------------------

  group('NegativeDirectoryRecords', () {
    test('one-of-two-sigs fails QuorumBelowThreshold', () {
      final bytes =
          File('${fixturesDir.path}/directory/invalid/one-of-two-sigs.cbor')
              .readAsBytesSync();
      final issuedAt = timestamps['t_directory_issued'] as int;
      final v = verifierAtTime(issuedAt + 1000);
      expect(() => v.verify(bytes, pinnedRoot),
          throwsA(isA<QuorumBelowThreshold>()));
    });

    test('tampered public key fails SignatureInvalid', () {
      final bytes =
          File('${fixturesDir.path}/directory/invalid/tampered-public-key.cbor')
              .readAsBytesSync();
      final issuedAt = timestamps['t_directory_issued'] as int;
      final v = verifierAtTime(issuedAt + 1000);
      expect(() => v.verify(bytes, pinnedRoot),
          throwsA(isA<SignatureInvalid>()));
    });

    test('expired record fails FreshnessExpired', () {
      final bytes =
          File('${fixturesDir.path}/directory/verifier-alice-active.cbor')
              .readAsBytesSync();
      final issuedAt = timestamps['t_directory_issued'] as int;
      final eightDaysLater = issuedAt + (8 * 24 * 60 * 60 * 1000);
      final v = verifierAtTime(eightDaysLater);
      expect(() => v.verify(bytes, pinnedRoot),
          throwsA(isA<FreshnessExpired>()));
    });
  });

  // ---------------------------------------------------------------------------
  // RoundTrip
  // ---------------------------------------------------------------------------

  group('RoundTrip', () {
    test('encode/decode preserves record', () {
      final codec = DirectoryRecordCodec();
      final original =
          File('${fixturesDir.path}/directory/issuer-acme-active.cbor')
              .readAsBytesSync();
      final record = codec.decode(original);
      final reEncoded = codec.encode(record);
      expect(reEncoded, equals(original));
    });
  });

  // ---------------------------------------------------------------------------
  // RootQuorumVerification
  // ---------------------------------------------------------------------------

  group('RootQuorumVerification', () {
    test('duplicate signatures from same key count once', () {
      final codec = DirectoryRecordCodec();
      final bytes =
          File('${fixturesDir.path}/directory/verifier-alice-active.cbor')
              .readAsBytesSync();
      final record = codec.decode(bytes);
      final signedBytes = codec.signedBytesOfEncoded(bytes);

      final firstSig = record.rootSignatures.first;
      final duplicatedSigs = [firstSig, firstSig];

      expect(
        () => RootQuorum.verify(
            sodium, signedBytes, duplicatedSigs, record.issuedAt, pinnedRoot),
        throwsA(isA<QuorumBelowThreshold>()),
      );
    });

    test('valid quorum with two distinct keys', () {
      final codec = DirectoryRecordCodec();
      final bytes =
          File('${fixturesDir.path}/directory/verifier-alice-active.cbor')
              .readAsBytesSync();
      final record = codec.decode(bytes);
      final signedBytes = codec.signedBytesOfEncoded(bytes);

      expect(
        () => RootQuorum.verify(sodium, signedBytes, record.rootSignatures,
            record.issuedAt, pinnedRoot),
        returnsNormally,
      );
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Map<String, dynamic> _readJson(String path) =>
    jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
