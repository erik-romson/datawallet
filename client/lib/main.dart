import 'package:flutter/material.dart';
import 'package:sodium/sodium_sumo.dart';

import 'src/api/auth_client.dart';
import 'src/api/directory_client.dart';
import 'src/api/issuer_client.dart';
import 'src/api/shared_client.dart';
import 'src/envelope/builder.dart';
import 'src/issuer/bearer.dart';
import 'src/issuer/enrollment.dart';
import 'src/issuer/install_identity.dart';
import 'src/issuer/keystore.dart';
import 'src/issuer/secure_storage.dart';
import 'src/screens/issuer_setup_screen.dart';
import 'src/screens/login_screen.dart';
import 'src/screens/share_screen.dart';
import 'src/screens/shared_list_screen.dart';
import 'src/state/issuer_state.dart';
import 'src/state/wallet_state.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final sodium = await SodiumSumoInit.init();
  runApp(DataWalletApp(sodium: sodium));
}

class DataWalletApp extends StatelessWidget {
  final SodiumSumo sodium;

  const DataWalletApp({super.key, required this.sodium});

  @override
  Widget build(BuildContext context) {
    const baseUrl = String.fromEnvironment(
      'DATAWALLET_BASE_URL',
      defaultValue: 'http://localhost:8080',
    );
    const intermediateUrl = String.fromEnvironment(
      'DATAWALLET_INTERMEDIATE_URL',
      defaultValue: 'http://localhost:8081',
    );

    final storage = FlutterSecureStorageAdapter();
    final keystore = Keystore(sodium, storage);
    final installIdentity = InstallIdentity(storage);
    final enrollmentClient = EnrollmentClient(intermediateUrl: intermediateUrl);
    final bearerProvider = BearerProvider(
      intermediateUrl: intermediateUrl,
      keystore: keystore,
    );
    final issuerClient = IssuerClient(baseUrl: baseUrl);
    final issuerState = IssuerState(
      identity: installIdentity,
      keystore: keystore,
      bearerProvider: bearerProvider,
    );

    final walletState = WalletState();
    final authClient = AuthClient(baseUrl: baseUrl);
    final sharedClient = SharedClient(baseUrl: baseUrl);
    final directoryClient = DirectoryClient(baseUrl: baseUrl);

    return MaterialApp(
      title: 'Data Wallet',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: _AppRoot(
        walletState: walletState,
        issuerState: issuerState,
        sodium: sodium,
        authClient: authClient,
        sharedClient: sharedClient,
        directoryClient: directoryClient,
        keystore: keystore,
        installIdentity: installIdentity,
        enrollmentClient: enrollmentClient,
        issuerClient: issuerClient,
      ),
    );
  }
}

class _AppRoot extends StatefulWidget {
  final WalletState walletState;
  final IssuerState issuerState;
  final SodiumSumo sodium;
  final AuthClient authClient;
  final SharedClient sharedClient;
  final DirectoryClient directoryClient;
  final Keystore keystore;
  final InstallIdentity installIdentity;
  final EnrollmentClient enrollmentClient;
  final IssuerClient issuerClient;

  const _AppRoot({
    required this.walletState,
    required this.issuerState,
    required this.sodium,
    required this.authClient,
    required this.sharedClient,
    required this.directoryClient,
    required this.keystore,
    required this.installIdentity,
    required this.enrollmentClient,
    required this.issuerClient,
  });

  @override
  State<_AppRoot> createState() => _AppRootState();
}

class _AppRootState extends State<_AppRoot> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    widget.walletState.addListener(_onStateChange);
    widget.issuerState.addListener(_onStateChange);
    widget.issuerState.init();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    widget.walletState.removeListener(_onStateChange);
    widget.issuerState.removeListener(_onStateChange);
    widget.walletState.dispose();
    widget.issuerState.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached ||
        state == AppLifecycleState.hidden) {
      widget.walletState.clearSession();
      widget.issuerState.onBackground();
    }
  }

  void _onStateChange() => setState(() {});

  @override
  Widget build(BuildContext context) {
    final enrolled = widget.issuerState.enrolled;

    // Still loading enrollment status from storage.
    if (enrolled == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    // First launch — no install identity yet.
    if (!enrolled) {
      return IssuerSetupScreen(
        keystore: widget.keystore,
        installIdentity: widget.installIdentity,
        enrollmentClient: widget.enrollmentClient,
        issuerState: widget.issuerState,
        sodium: widget.sodium,
      );
    }

    // Enrolled — show verifier list if logged in, otherwise chooser.
    final session = widget.walletState.session;
    if (session != null) {
      return SharedListScreen(
        sharedClient: widget.sharedClient,
        directoryClient: widget.directoryClient,
        session: session,
        sodium: widget.sodium,
        walletState: widget.walletState,
      );
    }

    return _ChooserScreen(
      walletState: widget.walletState,
      issuerState: widget.issuerState,
      authClient: widget.authClient,
      sharedClient: widget.sharedClient,
      directoryClient: widget.directoryClient,
      issuerClient: widget.issuerClient,
      sodium: widget.sodium,
    );
  }
}

/// Lets the user choose between verifier (view received items) and
/// issuer (share an item) mode.
class _ChooserScreen extends StatelessWidget {
  final WalletState walletState;
  final IssuerState issuerState;
  final AuthClient authClient;
  final SharedClient sharedClient;
  final DirectoryClient directoryClient;
  final IssuerClient issuerClient;
  final SodiumSumo sodium;

  const _ChooserScreen({
    required this.walletState,
    required this.issuerState,
    required this.authClient,
    required this.sharedClient,
    required this.directoryClient,
    required this.issuerClient,
    required this.sodium,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Data Wallet')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            ElevatedButton(
              key: const Key('chooser_share'),
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => ShareScreen(
                    issuerState: issuerState,
                    directoryClient: directoryClient,
                    issuerClient: issuerClient,
                    builder: EnvelopeBuilder(sodium),
                    sodium: sodium,
                  ),
                ),
              ),
              child: const Text('Share an item'),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              key: const Key('chooser_view'),
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => LoginScreen(
                    authClient: authClient,
                    walletState: walletState,
                    sodium: sodium,
                  ),
                ),
              ),
              child: const Text('View items shared with me'),
            ),
          ],
        ),
      ),
    );
  }
}
