import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:sodium/sodium.dart';

import '../api/api_client.dart';
import '../api/api_exception.dart';
import '../api/directory_client.dart';
import '../api/issuer_client.dart';
import '../crypto/uuid_v7.dart';
import '../directory/directory_record_codec.dart';
import '../envelope/builder.dart';
import '../state/issuer_state.dart';

/// Compose-and-share screen for the mobile issuer.
///
/// Plaintext is held only in a [TextEditingController] and is cleared on:
///   - [dispose]
///   - [AppLifecycleState.paused], [detached], or [hidden] (via [clearPlaintext])
///   - Idle timeout (via [IssuerState.resetIdle] / [BearerProvider.invalidate])
///
/// On submit: builds a signed CBOR envelope via [EnvelopeBuilder.buildAsync]
/// and posts it via [IssuerClient.submitEntry]. Plaintext is cleared regardless
/// of outcome. Success navigates back; failure shows an inline error.
class ShareScreen extends StatefulWidget {
  final IssuerState issuerState;
  final DirectoryClient directoryClient;
  final IssuerClient issuerClient;
  final EnvelopeBuilder builder;
  final Sodium sodium;

  const ShareScreen({
    super.key,
    required this.issuerState,
    required this.directoryClient,
    required this.issuerClient,
    required this.builder,
    required this.sodium,
  });

  @override
  State<ShareScreen> createState() => ShareScreenState();
}

// Public for @visibleForTesting access from widget tests.
class ShareScreenState extends State<ShareScreen> with WidgetsBindingObserver {
  final _verifierIdCtrl = TextEditingController();
  final _descriptionCtrl = TextEditingController();
  final _plaintextCtrl = TextEditingController();

  bool _submitting = false;
  bool _verifierLookupFailed = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    clearPlaintext();
    _verifierIdCtrl.dispose();
    _descriptionCtrl.dispose();
    _plaintextCtrl.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached ||
        state == AppLifecycleState.hidden) {
      clearPlaintext();
      widget.issuerState.onBackground();
    }
  }

  /// The plaintext controller. Exposed for widget tests to verify clearing.
  @visibleForTesting
  TextEditingController get plaintextController => _plaintextCtrl;

  /// Zeros the plaintext field. Exposed for widget tests.
  @visibleForTesting
  void clearPlaintext() {
    _plaintextCtrl.clear();
  }

  Future<void> _submit() async {
    final verifierId = _verifierIdCtrl.text.trim();
    final description = _descriptionCtrl.text.trim();
    final plaintext = _plaintextCtrl.text;

    if (verifierId.isEmpty || description.isEmpty || plaintext.isEmpty) return;

    setState(() {
      _submitting = true;
      _error = null;
      _verifierLookupFailed = false;
    });

    try {
      // 1. Look up verifier enc key from directory.
      final wrappers = await widget.directoryClient.getIssuerDirectory(verifierId);
      final codec = DirectoryRecordCodec();

      RecipientDescriptor? recipient;
      for (final w in wrappers) {
        try {
          final rec = codec.decode(w.signedRecord);
          if (rec.keyUse == 'enc' && rec.status == 'active') {
            recipient = RecipientDescriptor(
              verifierId: rec.subjectId,
              verifierKeyId: rec.keyId,
              encPublicKey: rec.publicKey,
            );
            break;
          }
        } catch (_) {}
      }

      if (recipient == null) {
        if (!mounted) return;
        setState(() {
          _submitting = false;
          _verifierLookupFailed = true;
          _error = 'No active encryption key found for this verifier.';
        });
        clearPlaintext();
        return;
      }

      // 2. Resolve issuer identity from state.
      final issuerId = widget.issuerState.installUuid;
      final issuerSigningKeyId = widget.issuerState.issuerSigningKeyId;
      if (issuerId == null || issuerSigningKeyId == null) {
        throw StateError('Issuer identity not initialised');
      }

      // 3. Get bearer token.
      final signedRecord = await widget.issuerState.identity.signedRecord();
      if (signedRecord == null) throw StateError('No enrollment receipt found');

      final bearer = await widget.issuerState.bearerProvider.token(
        signedDirectoryRecord: signedRecord,
        attestationToken: 'stub',
      );

      // 4. Build signed envelope — plaintext zeroed inside buildAsync.
      final entryId = UuidV7.now(widget.sodium);
      final envelope = await widget.builder.buildAsync(
        plaintextContent: plaintext,
        entryId: entryId,
        issuerId: issuerId,
        issuerLabel: '',
        issuerSigningKeyId: issuerSigningKeyId,
        signFn: widget.issuerState.keystore.sign,
        createdAt: DateTime.now().millisecondsSinceEpoch,
        description: description,
        recipients: [recipient],
      );

      // 5. Submit to server.
      await widget.issuerClient.submitEntry(bearer, envelope.signedEnvelopeBytes);

      widget.issuerState.resetIdle();

      if (!mounted) return;
      Navigator.of(context).pop();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _error = e is ApiException ? e.message : e.toString();
      });
    } finally {
      clearPlaintext();
    }
  }

  @override
  Widget build(BuildContext context) {
    final canSubmit = !_submitting && !_verifierLookupFailed;

    return Scaffold(
      appBar: AppBar(title: const Text('Share an item')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              key: const Key('verifier_id_field'),
              controller: _verifierIdCtrl,
              decoration: const InputDecoration(
                labelText: 'Recipient verifier ID',
                hintText: 'e.g. 01941f29-7c00-...',
              ),
              onChanged: (_) {
                if (_verifierLookupFailed) {
                  setState(() {
                    _verifierLookupFailed = false;
                    _error = null;
                  });
                }
              },
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('description_field'),
              controller: _descriptionCtrl,
              decoration: const InputDecoration(
                labelText: 'Description (server-visible)',
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('plaintext_field'),
              controller: _plaintextCtrl,
              decoration: const InputDecoration(
                labelText: 'Content (encrypted)',
              ),
              maxLines: 5,
            ),
            const SizedBox(height: 24),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(
                  _error!,
                  key: const Key('share_error'),
                  style:
                      TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            _submitting
                ? const Center(child: CircularProgressIndicator())
                : ElevatedButton(
                    key: const Key('submit_button'),
                    onPressed: canSubmit ? _submit : null,
                    child: const Text('Share'),
                  ),
          ],
        ),
      ),
    );
  }
}
