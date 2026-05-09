import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'api_client.dart';
import 'api_exception.dart';

/// Response from POST /v1/entries.
class EntryIngestResponse {
  final String entryId;
  final int version;

  const EntryIngestResponse({required this.entryId, required this.version});
}

/// Thin HTTP client for issuer entry submission.
class IssuerClient {
  final String baseUrl;
  final http.Client _http;

  IssuerClient({required this.baseUrl, http.Client? httpClient})
      : _http = httpClient ?? http.Client();

  /// Posts a signed CBOR envelope to `POST /v1/entries`.
  ///
  /// [bearer] is the JWT from the intermediate token endpoint.
  /// [signedEnvelopeBytes] is the canonical CBOR envelope.
  Future<EntryIngestResponse> submitEntry(
    String bearer,
    Uint8List signedEnvelopeBytes,
  ) async {
    final resp = await _http.post(
      Uri.parse('$baseUrl/v1/entries'),
      headers: {
        'Authorization': 'Bearer $bearer',
        'Content-Type': 'application/cbor',
      },
      body: signedEnvelopeBytes,
    );

    if (resp.statusCode == 409) {
      final json = jsonDecode(resp.body) as Map<String, dynamic>;
      throw ApiException(409, 'Conflict',
          errorCode: json['error'] as String?);
    }
    if (resp.statusCode != 201 && resp.statusCode != 200) {
      throw toApiException(resp);
    }

    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    return EntryIngestResponse(
      entryId: json['entry_id'] as String,
      version: json['version'] as int,
    );
  }
}
