import 'dart:async';

import 'package:flutter/foundation.dart';

import 'session.dart';

const Duration _idleTimeout = Duration(minutes: 10);

/// Application state for the verifier wallet.
///
/// Holds the active [Session] and notifies listeners on changes.
/// Automatically zeros key material after [_idleTimeout] of inactivity
/// or when the app moves to the background.
class WalletState extends ChangeNotifier {
  Session? _session;
  Timer? _idleTimer;

  Session? get session => _session;

  /// Sets a new session and resets the idle timer.
  void setSession(Session session) {
    _session?.zero();
    _session = session;
    _resetIdleTimer();
    notifyListeners();
  }

  /// Resets the idle timer (call on user interaction).
  void resetIdle() => _resetIdleTimer();

  /// Zeros key material and clears the session.
  void clearSession() {
    _idleTimer?.cancel();
    _idleTimer = null;
    _session?.zero();
    _session = null;
    notifyListeners();
  }

  void _resetIdleTimer() {
    _idleTimer?.cancel();
    _idleTimer = Timer(_idleTimeout, clearSession);
  }

  @override
  void dispose() {
    _idleTimer?.cancel();
    _session?.zero();
    super.dispose();
  }
}
