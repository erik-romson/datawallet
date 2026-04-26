import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:datawallet/src/fixtures/fixtures_path.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory fixturesDir;
  late Map<String, dynamic> manifest;

  setUpAll(() {
    fixturesDir = resolveFixturesDir();
    final manifestFile = File('${fixturesDir.path}/manifest.json');
    expect(manifestFile.existsSync(), isTrue, reason: 'manifest.json must exist at ${manifestFile.path}');
    manifest = jsonDecode(manifestFile.readAsStringSync()) as Map<String, dynamic>;
    expect(manifest.containsKey('files'), isTrue, reason: 'manifest must have "files" key');
  });

  test('manifest has spec_version 1', () {
    expect(manifest['spec_version'], equals(1));
  });

  test('all manifest entries match sha256', () {
    final files = manifest['files'] as List<dynamic>;
    expect(files, isNotEmpty, reason: 'manifest must list at least one file');

    for (final entry in files) {
      final relPath = entry['path'] as String;
      final expectedHash = entry['sha256'] as String;

      final filePath = File('${fixturesDir.path}/$relPath');
      expect(filePath.existsSync(), isTrue, reason: 'fixture file must exist: $relPath');

      final bytes = filePath.readAsBytesSync();
      final actualHash = sha256.convert(bytes).toString();

      expect(actualHash, equals(expectedHash), reason: 'SHA-256 mismatch for $relPath');
    }
  });

  test('manifest covers minimum fixture categories', () {
    final files = manifest['files'] as List<dynamic>;

    int countByCategory(String category) =>
        files.where((e) => (e as Map<String, dynamic>)['category'] == category).length;

    expect(countByCategory('wrapped'), greaterThanOrEqualTo(4), reason: 'wrapped blobs');
    expect(countByCategory('envelope'), greaterThanOrEqualTo(4), reason: 'valid envelopes');
    expect(countByCategory('envelope-invalid'), greaterThanOrEqualTo(5), reason: 'invalid envelopes');
    expect(countByCategory('directory'), greaterThanOrEqualTo(4), reason: 'directory records');
    expect(countByCategory('directory-invalid'), greaterThanOrEqualTo(2), reason: 'invalid directory records');
    expect(countByCategory('auth'), greaterThanOrEqualTo(2), reason: 'auth vectors');
    expect(countByCategory('audit'), greaterThanOrEqualTo(2), reason: 'audit vectors');
    expect(countByCategory('fingerprint'), greaterThanOrEqualTo(1), reason: 'fingerprint vectors');
  });
}
