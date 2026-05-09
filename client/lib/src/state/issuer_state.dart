import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';

import '../directory/directory_record_codec.dart';
import '../issuer/bearer.dart';
import '../issuer/install_identity.dart';
import '../issuer/keystore.dart';

const Duration _issuerIdleTimeout = Duration(minutes: 10);

/// Application state for the mobile issuer.
///
/// Holds the [BearerProvider], [InstallIdentity], and [Keystore].
/// Mirrors [WalletState] lifecycle hooks — paused/detached/hidden zeros the
/// in-memory bearer token; idle timeout invalidates it too.
class IssuerState extends ChangeNotifier {
  final InstallIdentity _identity;
  final Keystore _keystore;
  final BearerProvider _bearerProvider;
  final DirectoryRecordCodec _codec = DirectoryRecordCodec();

  bool? _enrolled; // null while loading from storage
  Uint8List? _installUuid;
  Uint8List? _issuerSigningKeyId;
  Timer? _idleTimer;

  IssuerState({
    required InstallIdentity identity,
    required Keystore keystore,
    required BearerProvider bearerProvider,
  })  : _identity = identity,
        _keystore = keystore,
        _bearerProvider = bearerProvider;

  /// Whether this install is enrolled; null until [init] completes.
  bool? get enrolled => _enrolled;

  /// 16-byte install UUID; null until enrolled.
  Uint8List? get installUuid => _installUuid;

  /// 16-byte issuer signing key ID from the enrollment receipt; null until enrolled.
  Uint8List? get issuerSigningKeyId => _issuerSigningKeyId;

  Keystore get keystore => _keystore;
  InstallIdentity get identity => _identity;
  BearerProvider get bearerProvider => _bearerProvider;

  /// Loads enrollment status and identity from storage. Must be called before use.
  Future<void> init() async {
    final enrolled = await _identity.isEnrolled();
    if (enrolled) {
      _installUuid = await _identity.installUuid();
      final rec = await _identity.signedRecord();
      if (rec != null) {
        try {
          final decoded = _codec.decode(rec);
          _issuerSigningKeyId = decoded.keyId;
        } catch (_) {}
      }
    }
    _enrolled = enrolled;
    notifyListeners();
  }

  /// Called after successful enrollment to update in-memory state.
  void markEnrolled({
    required Uint8List installUuid,
    required Uint8List signedRecord,
  }) {
    _installUuid = installUuid;
    try {
      final decoded = _codec.decode(signedRecord);
      _issuerSigningKeyId = decoded.keyId;
    } catch (_) {}
    _enrolled = true;
    _resetIdleTimer();
    notifyListeners();
  }

  /// Zeros in-memory bearer token. Call on app background transition.
  void onBackground() {
    _bearerProvider.invalidate();
  }

  /// Resets the idle timer (call on user interaction).
  void resetIdle() => _resetIdleTimer();

  void _resetIdleTimer() {
    _idleTimer?.cancel();
    _idleTimer = Timer(_issuerIdleTimeout, _onIdle);
  }

  void _onIdle() {
    _bearerProvider.invalidate();
  }

  @override
  void dispose() {
    _idleTimer?.cancel();
    super.dispose();
  }
}
