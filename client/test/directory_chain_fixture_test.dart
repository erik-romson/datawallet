import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:datawallet/src/directory/directory_record.dart';
import 'package:datawallet/src/directory/directory_record_codec.dart';
import 'package:datawallet/src/directory/directory_record_verifier.dart';
import 'package:datawallet/src/directory/directory_rejection.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sodium/sodium_sumo.dart';

void main() {
  late SodiumSumo sodium;
  late Directory fixturesDir;

  late PinnedRoot pinnedRoot;
  late Map<String, dynamic> timestamps;
  late Map<String, dynamic> intermediateMeta;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
    fixturesDir = resolveFixturesDir();

    final codec = DirectoryRecordCodec();
    final pinnedRootBytes =
        File('${fixturesDir.path}/directory/pinned-root.cbor').readAsBytesSync();
    pinnedRoot = codec.decodePinnedRoot(pinnedRootBytes);

    timestamps = _readJson('${fixturesDir.path}/inputs/timestamps.json');
    intermediateMeta = _readJson(
        '${fixturesDir.path}/directory/intermediate-record/intermediate_meta.json');
  });

  DirectoryRecordVerifier verifierAtTime(int timeMs) =>
      DirectoryRecordVerifier(sodium, nowMs: () => timeMs);

  int issuedAt() => timestamps['t_directory_issued'] as int;

  // Lookup backed by the intermediate fixture file
  ParentLookup intermediateFileLookup() {
    final intermediateBytes = File(
            '${fixturesDir.path}/directory/intermediate-record/intermediate.cbor')
        .readAsBytesSync();
    final intermediateKeyId =
        _fromHex(intermediateMeta['intermediate_key_id_hex'] as String);
    return (parentKeyId) {
      if (_bytesEqual(parentKeyId, intermediateKeyId)) return intermediateBytes;
      throw ParentNotFound('No fixture for parent_key_id=${_toHex(parentKeyId)}');
    };
  }

  // ---------------------------------------------------------------------------
  // V1 backwards compat
  // ---------------------------------------------------------------------------

  group('V1BackwardsCompat', () {
    test('v1 record decodes and re-encodes identically', () {
      final codec = DirectoryRecordCodec();
      final original =
          File('${fixturesDir.path}/directory/issuer-acme-active.cbor')
              .readAsBytesSync();
      final record = codec.decode(original);

      expect(record.parentKeyId, isNull);
      expect(record.parentSignature, isNull);
      expect(record.rootSignatures, hasLength(2));

      final reEncoded = codec.encode(record);
      expect(reEncoded, equals(original));
    });

    test('v1 record verifies with new codec', () {
      final bytes =
          File('${fixturesDir.path}/directory/issuer-acme-active.cbor')
              .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      final record = v.verify(bytes, pinnedRoot);
      expect(record.recordType, equals('issuer'));
    });
  });

  // ---------------------------------------------------------------------------
  // Valid chain
  // ---------------------------------------------------------------------------

  group('ValidChain', () {
    test('intermediate record verifies as root-signed', () {
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/intermediate.cbor')
          .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      final record = v.verify(bytes, pinnedRoot);

      expect(record.recordType, equals('intermediate'));
      expect(record.parentKeyId, isNull);
      expect(record.rootSignatures, hasLength(2));
    });

    test('issuer under intermediate verifies full chain', () {
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/issuer-under-intermediate.cbor')
          .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      final record = v.verify(bytes, pinnedRoot, intermediateFileLookup());

      expect(record.recordType, equals('issuer'));
      expect(record.parentKeyId, isNotNull);
      expect(record.parentSignature, isNotNull);
    });

    test('signedBytesOf from record and bytes are consistent', () {
      final codec = DirectoryRecordCodec();
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/issuer-under-intermediate.cbor')
          .readAsBytesSync();
      final record = codec.decode(bytes);
      final fromRecord = codec.signedBytesOfRecord(record);
      final fromBytes = codec.signedBytesOfEncoded(bytes);
      expect(fromRecord, equals(fromBytes));
    });
  });

  // ---------------------------------------------------------------------------
  // Chain rejections
  // ---------------------------------------------------------------------------

  group('ChainRejections', () {
    test('chain too deep rejected', () {
      final chainTooDeepBytes = File(
              '${fixturesDir.path}/directory/intermediate-record/chain-too-deep.cbor')
          .readAsBytesSync();
      final deepIntermediateBytes = File(
              '${fixturesDir.path}/directory/intermediate-record/deep-intermediate.cbor')
          .readAsBytesSync();
      final wrongIntermediateKeyId =
          _fromHex(intermediateMeta['wrong_intermediate_key_id_hex'] as String);

      ParentLookup lookup = (parentKeyId) {
        if (_bytesEqual(parentKeyId, wrongIntermediateKeyId)) {
          return deepIntermediateBytes;
        }
        throw ParentNotFound('Not found');
      };

      final v = verifierAtTime(issuedAt() + 1000);
      expect(() => v.verify(chainTooDeepBytes, pinnedRoot, lookup),
          throwsA(isA<ChainTooDeep>()));
    });

    test('wrong parent signature rejected', () {
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/wrong-parent-signature.cbor')
          .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      expect(() => v.verify(bytes, pinnedRoot, intermediateFileLookup()),
          throwsA(isA<ParentSignatureInvalid>()));
    });

    test('both signature containers rejected', () {
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/both-signature-containers.cbor')
          .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      expect(() => v.verify(bytes, pinnedRoot),
          throwsA(isA<SignatureContainerConflict>()));
    });

    test('no signature container rejected', () {
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/no-signature-container.cbor')
          .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      expect(() => v.verify(bytes, pinnedRoot),
          throwsA(isA<SignatureContainerMissing>()));
    });

    test('parent not found rejected for chain record', () {
      final bytes = File(
              '${fixturesDir.path}/directory/intermediate-record/issuer-under-intermediate.cbor')
          .readAsBytesSync();
      final v = verifierAtTime(issuedAt() + 1000);
      // no lookup supplied → ParentNotFound
      expect(() => v.verify(bytes, pinnedRoot),
          throwsA(isA<ParentNotFound>()));
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

Uint8List _fromHex(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
