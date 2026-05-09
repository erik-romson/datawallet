import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../api/api_client.dart';
import '../api/api_exception.dart';

/// Enrollment receipt from the intermediate service.
class EnrollmentReceipt {
  final Uint8List signedRecord;
  final String tokenUrl;

  const EnrollmentReceipt({
    required this.signedRecord,
    required this.tokenUrl,
  });
}

/// Enrolls a mobile install with the intermediate service.
class EnrollmentClient {
  final String intermediateUrl;
  final http.Client _http;

  EnrollmentClient({required this.intermediateUrl, http.Client? httpClient})
      : _http = httpClient ?? http.Client();

  /// Posts enrollment request to `POST <intermediateUrl>/enroll`.
  ///
  /// Returns the signed directory record from the intermediate.
  Future<EnrollmentReceipt> enroll({
    required Uint8List installUuid,
    required Uint8List pubkey,
    required String attestationToken,
  }) async {
    final resp = await _http.post(
      Uri.parse('$intermediateUrl/enroll'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'install_uuid': uuidToString(installUuid),
        'pubkey': b64url(pubkey),
        'attestation_token': attestationToken,
      }),
    );

    if (resp.statusCode == 403) {
      final json = jsonDecode(resp.body) as Map<String, dynamic>;
      throw ApiException(403, json['rejection_code'] as String? ?? 'attestation_failed',
          errorCode: json['error'] as String?);
    }
    if (resp.statusCode != 200) throw toApiException(resp);

    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    return EnrollmentReceipt(
      signedRecord: fromB64url(json['signed_record'] as String),
      tokenUrl: json['token_url'] as String,
    );
  }
}
