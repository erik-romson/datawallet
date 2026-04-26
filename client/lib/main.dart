import 'package:flutter/material.dart';
import 'package:sodium/sodium_sumo.dart';

import 'src/api/auth_client.dart';
import 'src/api/directory_client.dart';
import 'src/api/shared_client.dart';
import 'src/screens/login_screen.dart';
import 'src/screens/shared_list_screen.dart';
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
        sodium: sodium,
        authClient: authClient,
        sharedClient: sharedClient,
        directoryClient: directoryClient,
      ),
    );
  }
}

class _AppRoot extends StatefulWidget {
  final WalletState walletState;
  final SodiumSumo sodium;
  final AuthClient authClient;
  final SharedClient sharedClient;
  final DirectoryClient directoryClient;

  const _AppRoot({
    required this.walletState,
    required this.sodium,
    required this.authClient,
    required this.sharedClient,
    required this.directoryClient,
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
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    widget.walletState.removeListener(_onStateChange);
    widget.walletState.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Zero key material when app goes to background.
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      widget.walletState.clearSession();
    }
  }

  void _onStateChange() => setState(() {});

  @override
  Widget build(BuildContext context) {
    final session = widget.walletState.session;
    if (session == null) {
      return LoginScreen(
        authClient: widget.authClient,
        walletState: widget.walletState,
        sodium: widget.sodium,
      );
    }
    return SharedListScreen(
      sharedClient: widget.sharedClient,
      directoryClient: widget.directoryClient,
      session: session,
      sodium: widget.sodium,
      walletState: widget.walletState,
    );
  }
}
