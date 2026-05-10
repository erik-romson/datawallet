import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'api_exception.dart';

String b64url(Uint8List bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List fromB64url(String s) {
  final padded = s.padRight((s.length + 3) & ~3, '=');
  return base64Url.decode(padded);
}

String uuidToString(Uint8List bytes) {
  assert(bytes.length == 16);
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

Uint8List uuidFromString(String uuid) {
  final hex = uuid.replaceAll('-', '');
  final result = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

ApiException toApiException(http.Response resp) {
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
