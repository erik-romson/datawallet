import 'dart:typed_data';

import 'package:datawallet/src/api/api_exception.dart';
import 'package:datawallet/src/issuer/bearer.dart';
import 'package:datawallet/src/issuer/enrollment.dart';
import 'package:datawallet/src/issuer/install_identity.dart';
import 'package:datawallet/src/issuer/keystore.dart';
import 'package:datawallet/src/issuer/secure_storage.dart';
import 'package:datawallet/src/screens/issuer_setup_screen.dart';
import 'package:datawallet/src/state/issuer_state.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sodium/sodium_sumo.dart';

class _MockEnrollmentClient extends Mock implements EnrollmentClient {}

class _MockBearerProvider extends Mock implements BearerProvider {}

void main() {
  setUpAll(() {
    registerFallbackValue(Uint8List(0));
  });

  late SodiumSumo sodium;
  late InMemorySecureStorage storage;
  late Keystore keystore;
  late InstallIdentity installIdentity;
  late IssuerState issuerState;
  late _MockBearerProvider mockBearer;

  final fakeSignedRecord = Uint8List.fromList(List.filled(32, 0xAB));

  setUpAll(() async {
    sodium = await SodiumSumoInit.init();
  });

  setUp(() {
    storage = InMemorySecureStorage();
    keystore = Keystore(sodium, storage);
    installIdentity = InstallIdentity(storage);
    mockBearer = _MockBearerProvider();
    issuerState = IssuerState(
      identity: installIdentity,
      keystore: keystore,
      bearerProvider: mockBearer,
    );
  });


  Widget _buildScreen(_MockEnrollmentClient enrollmentClient) {
    return MaterialApp(
      home: ListenableBuilder(
        listenable: issuerState,
        builder: (context, _) {
          if (issuerState.enrolled == true) {
            return const Scaffold(body: Text('ShareScreen'));
          }
          return IssuerSetupScreen(
            keystore: keystore,
            installIdentity: installIdentity,
            enrollmentClient: enrollmentClient,
            issuerState: issuerState,
            sodium: sodium,
          );
        },
      ),
    );
  }

  group('IssuerSetupScreen happy path', () {
    testWidgets('keygen → enroll → receipt persisted → navigates away',
        (tester) async {
      final mockEnroll = _MockEnrollmentClient();
      when(
        () => mockEnroll.enroll(
          installUuid: any(named: 'installUuid'),
          pubkey: any(named: 'pubkey'),
          attestationToken: any(named: 'attestationToken'),
        ),
      ).thenAnswer(
        (_) async => EnrollmentReceipt(
          signedRecord: fakeSignedRecord,
          tokenUrl: 'http://intermediate/token',
        ),
      );

      await tester.pumpWidget(_buildScreen(mockEnroll));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('setup_button')), findsOneWidget);

      await tester.tap(find.byKey(const Key('setup_button')));
      await tester.pumpAndSettle();

      // State transitions to enrolled — stub screen is shown.
      expect(find.text('ShareScreen'), findsOneWidget);
      expect(issuerState.enrolled, isTrue);

      // Receipt is persisted in identity storage.
      expect(await installIdentity.isEnrolled(), isTrue);

      // Wrapped keypair is still present (not cleaned up on success).
      expect(await keystore.publicKey(), isNotNull);

      // Cancel idle timer started by markEnrolled before test ends.
      issuerState.dispose();
    });
  });

  group('IssuerSetupScreen enrollment failure', () {
    testWidgets('enrollment failure leaves no orphaned wrapped key',
        (tester) async {
      final mockEnroll = _MockEnrollmentClient();
      when(
        () => mockEnroll.enroll(
          installUuid: any(named: 'installUuid'),
          pubkey: any(named: 'pubkey'),
          attestationToken: any(named: 'attestationToken'),
        ),
      ).thenThrow(const ApiException(503, 'Service unavailable'));

      await tester.pumpWidget(_buildScreen(mockEnroll));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('setup_button')));
      await tester.pumpAndSettle();

      // Error banner shown.
      expect(find.byKey(const Key('setup_error')), findsOneWidget);

      // Not enrolled — state was never set to true, storage is clean.
      expect(issuerState.enrolled, isNot(isTrue));
      expect(await installIdentity.isEnrolled(), isFalse);

      // Wrapped key destroyed — no orphaned material remains.
      expect(await keystore.publicKey(), isNull);
      expect(
        () => keystore.sign(Uint8List(1)),
        throwsA(isA<StateError>()),
      );
    });
  });
}
