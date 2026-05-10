import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'api_client.dart';

/// JSON wrapper item from GET /v1/directory/issuers/{issuer_id}.
class DirectoryRecordWrapper {
  final String keyId;         // advisory — do not trust for crypto decisions
  final String status;
  final String validFrom;     // RFC3339 — advisory
  final String validUntil;    // RFC3339 — advisory
  final String issuedAt;      // RFC3339 — advisory
  final Uint8List signedRecord; // raw canonical CBOR, authoritative

  const DirectoryRecordWrapper({
    required this.keyId,
    required this.status,
    required this.validFrom,
    required this.validUntil,
    required this.issuedAt,
    required this.signedRecord,
  });

  factory DirectoryRecordWrapper.fromJson(Map<String, dynamic> json) =>
      DirectoryRecordWrapper(
        keyId: json['key_id'] as String,
        status: json['status'] as String,
        validFrom: json['valid_from'] as String,
        validUntil: json['valid_until'] as String,
        issuedAt: json['issued_at'] as String,
        signedRecord: fromB64url(json['signed_record'] as String),
      );
}

/// Thin HTTP client for public directory endpoints.
class DirectoryClient {
  final String baseUrl;
  final http.Client _http;

  DirectoryClient({required this.baseUrl, http.Client? httpClient})
      : _http = httpClient ?? http.Client();

  Future<List<DirectoryRecordWrapper>> getIssuerDirectory(
      String issuerId) async {
    final resp = await _http.get(
      Uri.parse('$baseUrl/v1/directory/issuers/$issuerId'),
    );
    if (resp.statusCode == 404) return [];
    if (resp.statusCode != 200) throw toApiException(resp);

    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    final rawRecords = json['records'] as List<dynamic>;
    return rawRecords
        .map((e) =>
            DirectoryRecordWrapper.fromJson(e as Map<String, dynamic>))
        .toList();
  }
}
