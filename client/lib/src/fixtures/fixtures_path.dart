import 'dart:io';

/// Resolves the path to `spec/fixtures/` for use in tests.
///
/// Resolution order:
/// 1. `FIXTURES_DIR` environment variable, if set.
/// 2. Walk up from [Directory.current] until `spec/fixtures/manifest.json` is found.
///
/// Throws [StateError] if the directory cannot be located.
Directory resolveFixturesDir() {
  final envOverride = Platform.environment['FIXTURES_DIR'];
  if (envOverride != null && envOverride.isNotEmpty) {
    final dir = Directory(envOverride);
    if (!dir.existsSync()) {
      throw StateError('FIXTURES_DIR env var points to non-existent directory: $envOverride');
    }
    return dir;
  }

  var dir = Directory.current;
  for (var i = 0; i < 8; i++) {
    final candidate = Directory('${dir.path}/spec/fixtures');
    if (candidate.existsSync() && File('${candidate.path}/manifest.json').existsSync()) {
      return candidate;
    }
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }

  throw StateError(
    'Could not find spec/fixtures/manifest.json walking up from ${Directory.current.path}. '
    'Set FIXTURES_DIR env var to the absolute path of spec/fixtures/.',
  );
}
