import 'dart:typed_data';

import 'directory_key_view.dart';

/// Resolves an issuer signing key from the directory.
///
/// Returns the [DirectoryKeyView] for ([issuerId], [issuerSigningKeyId]), or
/// `null` if no record exists.  The resolver does not check time validity —
/// that is the verifier's responsibility.
typedef IssuerKeyResolver = DirectoryKeyView? Function(
  Uint8List issuerId,
  Uint8List issuerSigningKeyId,
  int atMs,
);
