import 'dart:typed_data';

import 'package:datawallet/src/api/directory_client.dart';
import 'package:datawallet/src/api/shared_client.dart';
import 'package:datawallet/src/screens/shared_list_screen.dart'
    show SharedListScreen, SharedListScreenState;
import 'package:datawallet/src/state/session.dart';
import 'package:datawallet/src/state/wallet_state.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sodium/sodium.dart';

class _MockSharedClient extends Mock implements SharedClient {}

class _MockDirectoryClient extends Mock implements DirectoryClient {}

void main() {
  late Sodium sodium;

  setUpAll(() async {
    sodium = await SodiumInit.init();
  });

  Session _fakeSession() => Session(
        verifierId: Uint8List.fromList(List.filled(16, 0xAA)),
        token: 'test-token',
        authPublicKey: Uint8List.fromList(List.filled(32, 0xBB)),
        encPublicKey: Uint8List.fromList(List.filled(32, 0xCC)),
        encPrivKey: Uint8List.fromList(List.filled(32, 0x01)),
        authPrivKey: Uint8List.fromList(List.filled(64, 0x02)),
      );

  SharedListItem _fakeItem(String id, String label, String desc) =>
      SharedListItem(
        entryId: id,
        issuerId: '01941f29-7c00-7050-9050-505050505050',
        issuerLabel: label,
        issuerSigningKeyId: Uint8List.fromList(List.filled(16, 0xCC)),
        createdAt: '2026-01-01T00:00:00Z',
        description: desc,
      );

  Widget _buildScreen(
    SharedClient sharedClient,
    DirectoryClient directoryClient,
    WalletState walletState,
  ) {
    return MaterialApp(
      home: SharedListScreen(
        sharedClient: sharedClient,
        directoryClient: directoryClient,
        session: _fakeSession(),
        sodium: sodium,
        walletState: walletState,
      ),
    );
  }

  group('SharedListScreen', () {
    testWidgets('renders entries from first page', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);

      final items = [
        _fakeItem('entry-id-0001', 'Acme Corp', 'Loan offer #1'),
        _fakeItem('entry-id-0002', 'Beta Inc', 'Offer #2'),
      ];

      when(() => mockShared.listShared(any(), cursor: any(named: 'cursor')))
          .thenAnswer((_) async => SharedListResponse(items: items));
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => []);

      await tester.pumpWidget(_buildScreen(mockShared, mockDir, walletState));
      await tester.pumpAndSettle();

      expect(find.text('Acme Corp'), findsOneWidget);
      expect(find.text('Beta Inc'), findsOneWidget);
      expect(find.text('Loan offer #1'), findsOneWidget);
    });

    testWidgets('description carries server-visible badge', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);

      when(() => mockShared.listShared(any(), cursor: any(named: 'cursor')))
          .thenAnswer((_) async => SharedListResponse(
                items: [_fakeItem('x', 'Issuer', 'Sensitive description')],
              ));
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => []);

      await tester.pumpWidget(_buildScreen(mockShared, mockDir, walletState));
      await tester.pumpAndSettle();

      expect(find.text('server-visible'), findsOneWidget);
    });

    testWidgets('pagination: second page loaded on cursor', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);

      final page1 = SharedListResponse(
        items: [_fakeItem('e1', 'Acme', 'desc1')],
        nextCursor: 'cursor-abc',
      );
      final page2 = SharedListResponse(
        items: [_fakeItem('e2', 'Beta', 'desc2')],
      );

      when(() => mockShared.listShared(any(), cursor: null))
          .thenAnswer((_) async => page1);
      when(() => mockShared.listShared(any(), cursor: 'cursor-abc'))
          .thenAnswer((_) async => page2);
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => []);

      await tester.pumpWidget(_buildScreen(mockShared, mockDir, walletState));
      await tester.pumpAndSettle();

      // First page visible
      expect(find.text('Acme'), findsOneWidget);

      // Trigger pagination via @visibleForTesting accessor
      final state = tester.state<SharedListScreenState>(
          find.byType(SharedListScreen));
      await state.loadMoreForTest();
      await tester.pumpAndSettle();

      expect(find.text('Beta'), findsOneWidget);
    });

    testWidgets('logout clears session in WalletState', (tester) async {
      final mockShared = _MockSharedClient();
      final mockDir = _MockDirectoryClient();
      final walletState = WalletState();
      addTearDown(walletState.dispose);
      walletState.setSession(_fakeSession());

      when(() => mockShared.listShared(any(), cursor: any(named: 'cursor')))
          .thenAnswer((_) async => const SharedListResponse(items: []));
      when(() => mockDir.getIssuerDirectory(any()))
          .thenAnswer((_) async => []);

      await tester.pumpWidget(MaterialApp(
        home: ListenableBuilder(
          listenable: walletState,
          builder: (context, _) {
            final session = walletState.session;
            if (session == null) return const Text('LoggedOut');
            return SharedListScreen(
              sharedClient: mockShared,
              directoryClient: mockDir,
              session: session,
              sodium: sodium,
              walletState: walletState,
            );
          },
        ),
      ));
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.logout));
      await tester.pumpAndSettle();

      expect(walletState.session, isNull);
      expect(find.text('LoggedOut'), findsOneWidget);
    });
  });
}
