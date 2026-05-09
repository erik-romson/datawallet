import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../api/api_client.dart';
import '../api/api_exception.dart';
import 'keystore.dart';

/// Mints and caches bearer tokens from the intermediate service.
///
/// Tokens are cached in memory for `exp - 30s`; never persisted to disk.
class BearerProvider {
  final String intermediateUrl;
  final Keystore _keystore;
  final http.Client _http;

  String? _cachedBearer;
  DateTime? _expiresAt;

  BearerProvider({
    required this.intermediateUrl,
    required Keystore keystore,
    http.Client? httpClient,
  })  : _keystore = keystore,
        _http = httpClient ?? http.Client();

  /// Returns a valid bearer token, refreshing if expired or absent.
  Future<String> token({
    required Uint8List signedDirectoryRecord,
    required String attestationToken,
  }) async {
    if (_cachedBearer != null &&
        _expiresAt != null &&
        DateTime.now().isBefore(_expiresAt!)) {
      return _cachedBearer!;
    }

    final popMessage = Uint8List.fromList('datawallet-token-pop'.codeUnits);
    final popSignature = await _keystore.sign(popMessage);

    final resp = await _http.post(
      Uri.parse('$intermediateUrl/token'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'signed_directory_record': b64url(signedDirectoryRecord),
        'pop_signature': b64url(popSignature),
        'attestation_token': attestationToken,
      }),
    );

    if (resp.statusCode != 200) throw toApiException(resp);

    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    final bearer = json['bearer'] as String;

    final expSeconds = _parseExp(bearer);
    if (expSeconds != null) {
      _expiresAt = DateTime.fromMillisecondsSinceEpoch(
          expSeconds * 1000,
          isUtc: true)
          .subtract(const Duration(seconds: 30));
    }
    _cachedBearer = bearer;
    return bearer;
  }

  void invalidate() {
    _cachedBearer = null;
    _expiresAt = null;
  }

  static int? _parseExp(String jwt) {
    final parts = jwt.split('.');
    if (parts.length != 3) return null;
    try {
      final payload = parts[1];
      final padded = payload.padRight((payload.length + 3) & ~3, '=');
      final decoded = base64Url.decode(padded);
      final map = jsonDecode(utf8.decode(decoded)) as Map<String, dynamic>;
      return map['exp'] as int?;
    } catch (_) {
      return null;
    }
  }
}
