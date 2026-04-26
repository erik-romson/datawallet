import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:sodium/sodium.dart';

import '../api/directory_client.dart';
import '../api/shared_client.dart';
import '../crypto/fingerprint.dart';
import '../crypto/sealed_box.dart';
import '../crypto/secret_box.dart';
import '../directory/directory_record.dart';
import '../directory/directory_record_codec.dart';
import '../envelope/directory_key_view.dart';
import '../envelope/envelope_codec.dart';
import '../envelope/envelope_rejection.dart';
import '../envelope/envelope_verifier.dart';
import '../envelope/issuer_key_resolver.dart';
import '../state/session.dart';

/// Detail screen for a single shared entry.
///
/// Verification order (mirrors Java):
/// 1. Parse CBOR
/// 2. Version check
/// 3. Key lookup + validity
/// 4. Signature check
/// 5. Ciphertext-hash check
///
/// On failure the rejection reason is rendered; plaintext is never shown.
/// SealedBox.open is only called after all verification passes.
class SharedDetailScreen extends StatefulWidget {
  final SharedClient sharedClient;
  final DirectoryClient directoryClient;
  final Session session;
  final Sodium sodium;
  final String entryId;

  const SharedDetailScreen({
    super.key,
    required this.sharedClient,
    required this.directoryClient,
    required this.session,
    required this.sodium,
    required this.entryId,
  });

  @override
  State<SharedDetailScreen> createState() => _SharedDetailScreenState();
}

class _SharedDetailScreenState extends State<SharedDetailScreen> {
  String? _plaintext;
  String? _error;
  String? _issuerFingerprint;
  bool _loading = true;

  final _envCodec = EnvelopeCodec();
  final _dirCodec = DirectoryRecordCodec();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      // 1. Fetch raw CBOR
      final envelopeBytes = await widget.sharedClient.getShared(
        widget.session.token,
        widget.entryId,
      );

      // 2. Pre-parse to get issuer for directory lookup
      final preEnv = _envCodec.decode(envelopeBytes);

      // 3. Fetch issuer directory and build synchronous resolver
      final issuerId = _uuidString(preEnv.issuerId);
      final wrappers =
          await widget.directoryClient.getIssuerDirectory(issuerId);

      final recordsByKeyId = <String, DirectoryRecord>{};
      for (final w in wrappers) {
        try {
          final rec = _dirCodec.decode(w.signedRecord);
          recordsByKeyId[_hex(rec.keyId)] = rec;
        } catch (_) {}
      }

      IssuerKeyResolver resolver =
          (issuerId, signingKeyId, atMs) {
        final rec = recordsByKeyId[_hex(signingKeyId)];
        if (rec == null) return null;
        return DirectoryKeyView(
          issuerId: rec.subjectId,
          keyId: rec.keyId,
          publicKey: rec.publicKey,
          status: rec.status,
          validFrom: rec.validFrom,
          validUntil: rec.validUntil,
        );
      };

      // 4. Verify envelope (signature + hash) — throws EnvelopeRejection on failure
      final verifier = EnvelopeVerifier(widget.sodium, resolver);
      final envelope = verifier.verify(envelopeBytes);

      // 5. Compute issuer fingerprint from resolved key
      final signingRec = recordsByKeyId[_hex(envelope.issuerSigningKeyId)];
      if (signingRec != null) {
        _issuerFingerprint = Fingerprint.render(signingRec.publicKey);
      }

      // 6. Find our recipient wrapping by verifier_id
      final myWrapping = envelope.recipientWrappings
          .where((rw) => _bytesEqual(rw.verifierId, widget.session.verifierId))
          .firstOrNull;
      if (myWrapping == null) {
        throw _DetailError('No wrapping found for this verifier.');
      }

      // 7. Unseal the data key using the verifier's enc keypair
      final dataKey = SealedBox.open(
        widget.sodium,
        myWrapping.wrappedDataKey,
        widget.session.encPublicKey,
        widget.session.encPrivKey,
      );

      // 8. Decrypt ciphertext
      final plainBytes = SecretBoxCrypto.open(
        widget.sodium,
        envelope.ciphertext,
        envelope.ciphertextNonce,
        dataKey,
      );
      dataKey.fillRange(0, dataKey.length, 0);

      if (!mounted) return;
      setState(() {
        _plaintext = utf8.decode(plainBytes);
        _loading = false;
      });
    } on EnvelopeRejection catch (e) {
      if (!mounted) return;
      setState(() {
        _error = _rejectionMessage(e);
        _loading = false;
      });
    } on _DetailError catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Failed to load entry: $e';
        _loading = false;
      });
    }
  }

  String _rejectionMessage(EnvelopeRejection e) {
    if (e is MalformedCbor) return 'Entry data is malformed.';
    if (e is UnsupportedVersion) return 'Unsupported envelope version.';
    if (e is IssuerKeyNotActiveAt) return 'Issuer signing key not valid at entry date.';
    if (e is SignatureInvalid) return 'Issuer signature is invalid.';
    if (e is CiphertextHashMismatch) return 'Ciphertext integrity check failed.';
    return 'Verification failed: ${e.runtimeType}';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Entry')),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 40),
            const SizedBox(height: 12),
            Text(
              _error!,
              key: const Key('detail_error'),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
        ),
      );
    }
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_issuerFingerprint != null) ...[
            Text(
              'Issuer fingerprint',
              style: Theme.of(context).textTheme.labelMedium,
            ),
            Text(
              _issuerFingerprint!,
              key: const Key('issuer_fingerprint'),
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    fontFamily: 'monospace',
                    letterSpacing: 1.2,
                  ),
            ),
            const Divider(height: 24),
          ],
          Text(
            'Content',
            style: Theme.of(context).textTheme.labelMedium,
          ),
          const SizedBox(height: 8),
          SelectableText(
            _plaintext!,
            key: const Key('plaintext'),
          ),
        ],
      ),
    );
  }
}

class _DetailError implements Exception {
  final String message;
  const _DetailError(this.message);
}


String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String _uuidString(Uint8List bytes) {
  final hex = _hex(bytes);
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
