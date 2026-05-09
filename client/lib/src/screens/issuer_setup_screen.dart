import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:sodium/sodium.dart';

import '../api/api_exception.dart';
import '../crypto/uuid_v7.dart';
import '../issuer/enrollment.dart';
import '../issuer/install_identity.dart';
import '../issuer/keystore.dart';
import '../state/issuer_state.dart';

/// First-launch setup screen — generates a keypair, enrolls with the
/// intermediate, and persists the receipt.
///
/// Only shown when no install identity exists. Single-use: navigates away
/// (via [IssuerState.markEnrolled]) on success. On failure, any partially
/// written key material is destroyed, leaving no orphaned wrapped key.
class IssuerSetupScreen extends StatefulWidget {
  final Keystore keystore;
  final InstallIdentity installIdentity;
  final EnrollmentClient enrollmentClient;
  final IssuerState issuerState;
  final Sodium sodium;

  const IssuerSetupScreen({
    super.key,
    required this.keystore,
    required this.installIdentity,
    required this.enrollmentClient,
    required this.issuerState,
    required this.sodium,
  });

  @override
  State<IssuerSetupScreen> createState() => _IssuerSetupScreenState();
}

class _IssuerSetupScreenState extends State<IssuerSetupScreen> {
  bool _loading = false;
  String? _error;

  Future<void> _setup() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    bool keystoreGenerated = false;
    Uint8List? installUuid;

    try {
      // 1. Generate Ed25519 keypair — wrapped key written to secure storage.
      await widget.keystore.generate();
      keystoreGenerated = true;

      final pubkey = await widget.keystore.publicKey();
      if (pubkey == null) throw StateError('Keypair generation returned null');

      // 2. Generate a UUIDv7 install identifier.
      installUuid = UuidV7.now(widget.sodium);

      // 3. Enroll with the intermediate service.
      final receipt = await widget.enrollmentClient.enroll(
        installUuid: installUuid,
        pubkey: pubkey,
        attestationToken: 'stub',
      );

      // 4. Persist enrollment receipt.
      await widget.installIdentity.save(installUuid, receipt.signedRecord);

      // 5. Transition state — triggers routing away from this screen.
      widget.issuerState.markEnrolled(
        installUuid: installUuid,
        signedRecord: receipt.signedRecord,
      );
    } catch (e) {
      // Destroy the generated keypair so no orphaned wrapped key is left.
      if (keystoreGenerated) {
        await widget.keystore.destroy();
      }
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = e is ApiException ? e.message : e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Set up issuer identity')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text(
              'Data Wallet will generate a signing key and register it with the service.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(
                  _error!,
                  key: const Key('setup_error'),
                  style:
                      TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            _loading
                ? const CircularProgressIndicator()
                : ElevatedButton(
                    key: const Key('setup_button'),
                    onPressed: _setup,
                    child: const Text('Set up'),
                  ),
          ],
        ),
      ),
    );
  }
}
