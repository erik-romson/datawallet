import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'api_exception.dart';

class KdfParams {
  final String alg;
  final int m;
  final int t;
  final int p;
  final int version;

  const KdfParams({
    required this.alg,
    required this.m,
    required this.t,
    required this.p,
    required this.version,
  });

  factory KdfParams.fromJson(Map<String, dynamic> json) => KdfParams(
        alg: json['alg'] as String,
        m: json['m'] as int,
        t: json['t'] as int,
        p: json['p'] as int,
        version: json['version'] as int,
      );
}

/// Server-side login blob returned by GET /v1/verifiers/{handle}/login-blob.
class LoginBlob {
  final Uint8List verifierId;            // 16 bytes, parsed from UUID string
  final Uint8List authPublicKey;         // 32 bytes
  final Uint8List authKeyId;             // 16 bytes
  final Uint8List encPublicKey;          // 32 bytes, X25519 — for SealedBox.open
  final Uint8List encKeyId;              // 16 bytes
  final Uint8List wrappedEncPrivKeyBlob; // canonical CBOR bytes
  final Uint8List wrappedAuthPrivKeyBlob;
  final Uint8List kdfSalt;               // 16 bytes
  final KdfParams kdfParams;

  const LoginBlob({
    required this.verifierId,
    required this.authPublicKey,
    required this.authKeyId,
    required this.encPublicKey,
    required this.encKeyId,
    required this.wrappedEncPrivKeyBlob,
    required this.wrappedAuthPrivKeyBlob,
    required this.kdfSalt,
    required this.kdfParams,
  });

  factory LoginBlob.fromJson(Map<String, dynamic> json) => LoginBlob(
        verifierId: _uuidFromString(json['verifier_id'] as String),
        authPublicKey: _fromB64url(json['auth_public_key'] as String),
        authKeyId: _fromB64url(json['auth_key_id'] as String),
        encPublicKey: _fromB64url(json['enc_public_key'] as String),
        encKeyId: _fromB64url(json['enc_key_id'] as String),
        wrappedEncPrivKeyBlob:
            _fromB64url(json['wrapped_enc_private_key_blob'] as String),
        wrappedAuthPrivKeyBlob:
            _fromB64url(json['wrapped_auth_private_key_blob'] as String),
        kdfSalt: _fromB64url(json['kdf_salt'] as String),
        kdfParams:
            KdfParams.fromJson(json['kdf_params'] as Map<String, dynamic>),
      );
}

/// Thin HTTP client for auth endpoints.
class AuthClient {
  final String baseUrl;
  final http.Client _http;

  AuthClient({required this.baseUrl, http.Client? httpClient})
      : _http = httpClient ?? http.Client();

  Future<LoginBlob> fetchLoginBlob(String handle) async {
    final resp = await _http.get(
      Uri.parse('$baseUrl/v1/verifiers/$handle/login-blob'),
    );
    if (resp.statusCode != 200) {
      throw _toException(resp);
    }
    return LoginBlob.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  /// Returns the raw 32-byte nonce.
  Future<Uint8List> challenge(Uint8List verifierId) async {
    final resp = await _http.post(
      Uri.parse('$baseUrl/v1/auth/challenge'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'verifier_id': _uuidToString(verifierId)}),
    );
    if (resp.statusCode != 200) {
      throw _toException(resp);
    }
    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    return _fromB64url(json['nonce'] as String);
  }

  /// Returns the session token string (base64url).
  Future<String> verify(
      Uint8List verifierId, Uint8List nonce, Uint8List sig) async {
    final resp = await _http.post(
      Uri.parse('$baseUrl/v1/auth/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'verifier_id': _uuidToString(verifierId),
        'nonce': _b64url(nonce),
        'signature': _b64url(sig),
      }),
    );
    if (resp.statusCode != 200) {
      throw _toException(resp);
    }
    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    return json['session_token'] as String;
  }

  Future<void> logout(String token) async {
    await _http.post(
      Uri.parse('$baseUrl/v1/auth/logout'),
      headers: {'Authorization': 'Bearer $token'},
    );
  }

  ApiException _toException(http.Response resp) {
    String? code;
    String message = 'HTTP ${resp.statusCode}';
    try {
      final json = jsonDecode(resp.body) as Map<String, dynamic>;
      final error = json['error'] as Map<String, dynamic>?;
      if (error != null) {
        code = error['code'] as String?;
        message = error['message'] as String? ?? message;
      }
    } catch (_) {}
    return ApiException(resp.statusCode, message, errorCode: code);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

String _b64url(Uint8List bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List _fromB64url(String s) {
  final padded = s.padRight((s.length + 3) & ~3, '=');
  return base64Url.decode(padded);
}

String _uuidToString(Uint8List bytes) {
  assert(bytes.length == 16);
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

Uint8List _uuidFromString(String uuid) {
  final hex = uuid.replaceAll('-', '');
  final result = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}
