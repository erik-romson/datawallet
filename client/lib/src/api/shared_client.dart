import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'api_exception.dart';

class SharedListItem {
  final String entryId;
  final String issuerId;
  final String issuerLabel;
  final Uint8List issuerSigningKeyId; // 16 bytes decoded from b64url
  final String createdAt;             // RFC3339
  final String description;

  const SharedListItem({
    required this.entryId,
    required this.issuerId,
    required this.issuerLabel,
    required this.issuerSigningKeyId,
    required this.createdAt,
    required this.description,
  });

  factory SharedListItem.fromJson(Map<String, dynamic> json) => SharedListItem(
        entryId: json['entry_id'] as String,
        issuerId: json['issuer_id'] as String,
        issuerLabel: json['issuer_label'] as String? ?? '',
        issuerSigningKeyId:
            _fromB64url(json['issuer_signing_key_id'] as String),
        createdAt: json['created_at'] as String,
        description: json['description'] as String? ?? '',
      );
}

class SharedListResponse {
  final List<SharedListItem> items;
  final String? nextCursor;

  const SharedListResponse({required this.items, this.nextCursor});
}

/// Thin HTTP client for verifier shared-entry endpoints.
class SharedClient {
  final String baseUrl;
  final http.Client _http;

  SharedClient({required this.baseUrl, http.Client? httpClient})
      : _http = httpClient ?? http.Client();

  Future<SharedListResponse> listShared(
    String token, {
    String? cursor,
    int limit = 50,
  }) async {
    final params = <String, String>{'limit': '$limit'};
    if (cursor != null) params['cursor'] = cursor;

    final resp = await _http.get(
      Uri.parse('$baseUrl/v1/shared').replace(queryParameters: params),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (resp.statusCode != 200) throw _toException(resp);

    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    final rawItems = json['items'] as List<dynamic>;
    return SharedListResponse(
      items: rawItems
          .map((e) => SharedListItem.fromJson(e as Map<String, dynamic>))
          .toList(),
      nextCursor: json['next_cursor'] as String?,
    );
  }

  /// Returns raw canonical CBOR bytes for the entry.
  Future<Uint8List> getShared(String token, String entryId) async {
    final resp = await _http.get(
      Uri.parse('$baseUrl/v1/shared/$entryId'),
      headers: {
        'Authorization': 'Bearer $token',
        'Accept': 'application/cbor',
      },
    );
    if (resp.statusCode != 200) throw _toException(resp);
    return resp.bodyBytes;
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

Uint8List _fromB64url(String s) {
  final padded = s.padRight((s.length + 3) & ~3, '=');
  return base64Url.decode(padded);
}
