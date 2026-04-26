import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:sodium/sodium_sumo.dart';

import '../api/auth_client.dart';
import '../crypto/argon2id.dart';
import '../crypto/crypto_exception.dart';
import '../crypto/ed25519.dart';
import '../crypto/wrapped_blob.dart';
import '../crypto/x25519.dart';
import '../state/session.dart';
import '../state/wallet_state.dart';

/// Challenge-signing prefix per crypto-formats.md §4.
final Uint8List _authPrefix = Uint8List.fromList(
  [...utf8.encode('datawallet-auth-v1'), 0x00],
);

/// Verifier login screen.
///
/// Flow: validate handle → fetch LoginBlob → derive KEK (Argon2id) →
/// unwrap private keys locally → sign challenge → POST verify → set session.
/// A wrong password is rejected locally with no further server contact.
class LoginScreen extends StatefulWidget {
  final AuthClient authClient;
  final WalletState walletState;
  final SodiumSumo sodium;

  const LoginScreen({
    super.key,
    required this.authClient,
    required this.walletState,
    required this.sodium,
  });

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _handleCtrl = TextEditingController();
  final _passwordCtrl = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  bool _loading = false;
  String? _error;

  static final _handleRegex = RegExp(r'^[a-z0-9_-]{3,32}$');

  @override
  void dispose() {
    _handleCtrl.dispose();
    _passwordCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final handle = _handleCtrl.text.trim();
      final password = _passwordCtrl.text;

      // 1. Fetch login blob
      final blob = await widget.authClient.fetchLoginBlob(handle);

      // 2. Derive KEK — may block for 1-4 s at floor params
      final kek = await Future(
        () => Argon2id.deriveKek(
          widget.sodium,
          password,
          blob.kdfSalt,
          blob.kdfParams.m,
          blob.kdfParams.t,
          blob.kdfParams.p,
        ),
      );

      // 3. Unwrap private keys locally; failure == wrong password, no more HTTP
      final Uint8List encPrivKey;
      final Uint8List authPrivKey;
      try {
        encPrivKey =
            WrappedBlob.decode(blob.wrappedEncPrivKeyBlob).open(widget.sodium, kek);
        authPrivKey =
            WrappedBlob.decode(blob.wrappedAuthPrivKeyBlob).open(widget.sodium, kek);
      } on CryptoException {
        setState(() {
          _loading = false;
          _error = 'Wrong password. Please try again.';
        });
        return;
      } finally {
        kek.fillRange(0, kek.length, 0);
      }

      // Use the registered enc public key directly from the login blob; never
      // recompute via seedKeyPair (that re-hashes the scalar and yields a
      // different keypair, breaking crypto_box_seal_open against the
      // recipient blob the issuer wrapped with this very public key).
      final encPublicKey = blob.encPublicKey;

      // 4. Fetch challenge nonce
      final nonce = await widget.authClient.challenge(blob.verifierId);

      // 5. Sign: prefix || nonce
      final toSign = Uint8List(_authPrefix.length + nonce.length)
        ..setAll(0, _authPrefix)
        ..setAll(_authPrefix.length, nonce);
      final sig =
          Ed25519.signDetached(widget.sodium, authPrivKey, toSign);

      // 6. Verify → session token
      final token =
          await widget.authClient.verify(blob.verifierId, nonce, sig);

      // 7. Store session
      widget.walletState.setSession(Session(
        verifierId: blob.verifierId,
        token: token,
        authPublicKey: blob.authPublicKey,
        encPublicKey: encPublicKey,
        encPrivKey: encPrivKey,
        authPrivKey: authPrivKey,
      ));
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = e is CryptoException ? 'Wrong password. Please try again.' : e.toString();
      });
      return;
    }

    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Data Wallet — Login')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              TextFormField(
                key: const Key('handle_field'),
                controller: _handleCtrl,
                decoration: const InputDecoration(
                  labelText: 'Handle',
                  hintText: 'e.g. alice',
                ),
                validator: (v) {
                  if (v == null || !_handleRegex.hasMatch(v.trim())) {
                    return 'Handle must be 3–32 lowercase letters, digits, _ or -';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 16),
              TextFormField(
                key: const Key('password_field'),
                controller: _passwordCtrl,
                decoration: const InputDecoration(labelText: 'Password'),
                obscureText: true,
                validator: (v) =>
                    (v == null || v.isEmpty) ? 'Password required' : null,
              ),
              const SizedBox(height: 24),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: Text(
                    _error!,
                    key: const Key('login_error'),
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
              _loading
                  ? const CircularProgressIndicator()
                  : ElevatedButton(
                      key: const Key('login_button'),
                      onPressed: _submit,
                      child: const Text('Log in'),
                    ),
            ],
          ),
        ),
      ),
    );
  }
}
