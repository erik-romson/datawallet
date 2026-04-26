import 'dart:typed_data';

import 'package:datawallet/src/api/auth_client.dart';
import 'package:datawallet/src/crypto/argon2id.dart';
import 'package:datawallet/src/crypto/ed25519.dart';
import 'package:datawallet/src/crypto/secret_box.dart';
import 'package:datawallet/src/crypto/wrapped_blob.dart';
import 'package:datawallet/src/crypto/x25519.dart';
import 'package:datawallet/src/screens/login_screen.dart';
import 'package:datawallet/src/state/wallet_state.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sodium/sodium_sumo.dart';

class _MockAuthClient extends Mock implements AuthClient {}

const _testPassword = 'correct-password-42';
const _testHandle = 'alice';

void main() {
  setUpAll(() {
    // Mocktail requires a fallback value for Uint8List (used in challenge/verify).
    registerFallbackValue(Uint8List(0));
  });

  late SodiumSumo sodium;

  // Fixed test credentials — fast Argon2id params (m=65536, t=1, p=1)
  late Uint8List aliceEncPrivKey;
  late Uint8List aliceEncPubKey;
  late Uint8List aliceAuthPrivKey;
  late Uint8List aliceAuthPubKey;
  late Uint8List aliceVerifierId;
  late LoginBlob loginBlob;

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();

    aliceVerifierId = Uint8List.fromList([
      0xC8, 0xEA, 0x8C, 0x73, 0x80, 0xFC, 0xA2, 0x5E,
      0x29, 0x5D, 0xF2, 0x06, 0x74, 0x04, 0xB0, 0x36,
    ]);

    final encSeed = Uint8List.fromList(List.filled(32, 0x01));
    final authSeed = Uint8List.fromList(List.filled(32, 0x02));
    final encKp = X25519.seedKeyPair(sodium, encSeed);
    final authKp = Ed25519.seedKeyPair(sodium, authSeed);

    aliceEncPrivKey = encKp.secretKey;
    aliceEncPubKey = encKp.publicKey;
    aliceAuthPrivKey = authKp.secretKey;
    aliceAuthPubKey = authKp.publicKey;

    // Derive KEK with fast test params
    final salt = Uint8List.fromList(List.filled(16, 0xAA));
    final kek = Argon2id.deriveKek(sodium, _testPassword, salt, 65536, 1, 1);

    // Wrap enc private key
    final encNonce = Uint8List.fromList(List.filled(24, 0xF1));
    final encCt = SecretBoxCrypto.seal(sodium, aliceEncPrivKey, encNonce, kek);
    final wrappedEnc =
        WrappedBlob(nonce: encNonce, ct: encCt).encode();

    // Wrap auth private key
    final authNonce = Uint8List.fromList(List.filled(24, 0xF2));
    final authCt =
        SecretBoxCrypto.seal(sodium, aliceAuthPrivKey, authNonce, kek);
    final wrappedAuth =
        WrappedBlob(nonce: authNonce, ct: authCt).encode();

    kek.fillRange(0, kek.length, 0);

    loginBlob = LoginBlob(
      verifierId: aliceVerifierId,
      authPublicKey: aliceAuthPubKey,
      authKeyId: Uint8List.fromList(List.filled(16, 0x75)),
      encPublicKey: aliceEncPubKey,
      encKeyId: Uint8List.fromList(List.filled(16, 0x76)),
      wrappedEncPrivKeyBlob: wrappedEnc,
      wrappedAuthPrivKeyBlob: wrappedAuth,
      kdfSalt: salt,
      kdfParams: const KdfParams(
        alg: 'argon2id',
        m: 65536,
        t: 1,
        p: 1,
        version: 19,
      ),
    );
  });

  Widget _buildScreen(
    WalletState walletState,
    AuthClient authClient,
  ) {
    return MaterialApp(
      home: ListenableBuilder(
        listenable: walletState,
        builder: (context, _) {
          if (walletState.session != null) {
            return const Scaffold(body: Text('SharedListScreen'));
          }
          return LoginScreen(
            authClient: authClient,
            walletState: walletState,
            sodium: sodium,
          );
        },
      ),
    );
  }

  group('LoginScreen happy path', () {
    testWidgets('successful login sets session and navigates to shared list',
        (tester) async {
      final mock = _MockAuthClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);

      final testNonce =
          Uint8List.fromList(List.filled(32, 0xAA)); // fixed nonce

      when(() => mock.fetchLoginBlob(any()))
          .thenAnswer((_) async => loginBlob);
      when(() => mock.challenge(any())).thenAnswer((_) async => testNonce);
      when(() => mock.verify(any(), any(), any()))
          .thenAnswer((_) async => 'test-session-token');

      await tester.pumpWidget(_buildScreen(walletState, mock));
      await tester.pumpAndSettle();

      await tester.enterText(find.byKey(const Key('handle_field')), _testHandle);
      await tester.enterText(
          find.byKey(const Key('password_field')), _testPassword);

      await tester.tap(find.byKey(const Key('login_button')));
      // Let Argon2id + async ops complete
      await tester.pumpAndSettle(const Duration(seconds: 10));

      // Session set → WalletState navigates to stub screen
      expect(find.text('SharedListScreen'), findsOneWidget);
      expect(walletState.session, isNotNull);
      expect(walletState.session!.token, equals('test-session-token'));

      verify(() => mock.fetchLoginBlob(_testHandle)).called(1);
      verify(() => mock.challenge(any())).called(1);
      verify(() => mock.verify(any(), any(), any())).called(1);

      // Cancel the idle timer created by setSession before fakeAsync checks
      // pending timers at end of test.
      walletState.clearSession();
    });
  });

  group('LoginScreen wrong password', () {
    testWidgets('wrong password shows error without calling verify',
        (tester) async {
      final mock = _MockAuthClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);

      when(() => mock.fetchLoginBlob(any()))
          .thenAnswer((_) async => loginBlob);

      await tester.pumpWidget(_buildScreen(walletState, mock));
      await tester.pumpAndSettle();

      await tester.enterText(find.byKey(const Key('handle_field')), _testHandle);
      await tester.enterText(
          find.byKey(const Key('password_field')), 'wrong-password-999');

      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pumpAndSettle(const Duration(seconds: 10));

      // Error shown, no session, verify never called
      expect(find.byKey(const Key('login_error')), findsOneWidget);
      expect(walletState.session, isNull);
      expect(find.text('SharedListScreen'), findsNothing);

      verifyNever(() => mock.challenge(any()));
      verifyNever(() => mock.verify(any(), any(), any()));
    });
  });

  group('LoginScreen handle validation', () {
    testWidgets('invalid handle shows validation error without network call',
        (tester) async {
      final mock = _MockAuthClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);

      await tester.pumpWidget(_buildScreen(walletState, mock));
      await tester.pumpAndSettle();

      await tester.enterText(
          find.byKey(const Key('handle_field')), 'AB'); // too short + uppercase
      await tester.enterText(
          find.byKey(const Key('password_field')), 'password');

      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pump();

      verifyNever(() => mock.fetchLoginBlob(any()));
    });
  });
}
