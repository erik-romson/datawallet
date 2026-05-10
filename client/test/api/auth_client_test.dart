import 'dart:convert';
import 'dart:typed_data';

import 'package:datawallet/src/api/api_client.dart';
import 'package:datawallet/src/api/api_exception.dart';
import 'package:datawallet/src/api/auth_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  group('AuthClient.fetchLoginBlob', () {
    test('parses every binary field via base64url-no-padding', () async {
      final blob = _validLoginBlobJson();
      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          expect(req.method, 'GET');
          expect(req.url.path, '/v1/verifiers/alice/login-blob');
          return http.Response(jsonEncode(blob), 200);
        }),
      );

      final result = await client.fetchLoginBlob('alice');

      expect(result.verifierId, _uuid('00112233-4455-6677-8899-aabbccddeeff'));
      expect(result.authPublicKey.length, 32);
      expect(result.authKeyId.length, 16);
      expect(result.encPublicKey.length, 32);
      expect(result.encKeyId.length, 16);
      expect(result.kdfSalt.length, 16);
      expect(result.kdfParams.alg, 'argon2id');
      expect(result.kdfParams.m, 19456);
    });

    test('non-200 response throws ApiException with error code', () async {
      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async => http.Response(
              jsonEncode({
                'error': {'code': 'not_found', 'message': 'no such verifier'}
              }),
              404,
            )),
      );

      await expectLater(
        client.fetchLoginBlob('ghost'),
        throwsA(isA<ApiException>()
            .having((e) => e.statusCode, 'statusCode', 404)
            .having((e) => e.errorCode, 'errorCode', 'not_found')
            .having((e) => e.message, 'message', 'no such verifier')),
      );
    });

    test('non-200 with non-JSON body still throws ApiException', () async {
      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient(
            (req) async => http.Response('<html>bad gateway</html>', 502)),
      );

      await expectLater(
        client.fetchLoginBlob('alice'),
        throwsA(isA<ApiException>()
            .having((e) => e.statusCode, 'statusCode', 502)
            .having((e) => e.errorCode, 'errorCode', isNull)),
      );
    });
  });

  group('AuthClient.challenge', () {
    test('sends UUID-formatted verifier_id and decodes nonce', () async {
      final verifierId = _uuid('00112233-4455-6677-8899-aabbccddeeff');
      final nonce = Uint8List(32)..[0] = 0x42;

      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          expect(req.method, 'POST');
          expect(req.url.path, '/v1/auth/challenge');
          final body = jsonDecode(req.body) as Map<String, dynamic>;
          expect(body['verifier_id'], '00112233-4455-6677-8899-aabbccddeeff');
          return http.Response(
            jsonEncode({'nonce': base64Url.encode(nonce).replaceAll('=', '')}),
            200,
          );
        }),
      );

      final result = await client.challenge(verifierId);
      expect(result, equals(nonce));
    });
  });

  group('AuthClient.verify', () {
    test('returns session token and sends b64url-no-padding fields', () async {
      final verifierId = _uuid('00112233-4455-6677-8899-aabbccddeeff');
      final nonce = Uint8List(32)..[0] = 0x42;
      final sig = Uint8List(64)..[0] = 0x99;

      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          expect(req.url.path, '/v1/auth/verify');
          final body = jsonDecode(req.body) as Map<String, dynamic>;
          expect((body['nonce'] as String).contains('='), isFalse,
              reason: 'binary fields must use base64url-no-padding');
          expect((body['signature'] as String).contains('='), isFalse);
          return http.Response(
            jsonEncode({'session_token': 'opaque-token-bytes'}),
            200,
          );
        }),
      );

      final token = await client.verify(verifierId, nonce, sig);
      expect(token, 'opaque-token-bytes');
    });

    test('non-200 with malformed error JSON falls back to default message',
        () async {
      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient(
            (req) async => http.Response('{"unrelated": true}', 401)),
      );

      await expectLater(
        client.verify(Uint8List(16), Uint8List(32), Uint8List(64)),
        throwsA(isA<ApiException>()
            .having((e) => e.statusCode, 'statusCode', 401)
            .having((e) => e.message, 'message', 'HTTP 401')),
      );
    });
  });

  group('AuthClient.logout', () {
    test('sends bearer token in Authorization header', () async {
      var observed = false;
      final client = AuthClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          observed = true;
          expect(req.method, 'POST');
          expect(req.url.path, '/v1/auth/logout');
          expect(req.headers['Authorization'], 'Bearer abc');
          return http.Response('', 204);
        }),
      );

      await client.logout('abc');
      expect(observed, isTrue);
    });
  });
}

Map<String, dynamic> _validLoginBlobJson() => {
      'verifier_id': '00112233-4455-6677-8899-aabbccddeeff',
      'auth_public_key': b64url(Uint8List(32)),
      'auth_key_id': b64url(Uint8List(16)),
      'enc_public_key': b64url(Uint8List(32)),
      'enc_key_id': b64url(Uint8List(16)),
      'wrapped_enc_private_key_blob': b64url(Uint8List.fromList([1, 2, 3, 4])),
      'wrapped_auth_private_key_blob': b64url(Uint8List.fromList([5, 6, 7, 8])),
      'kdf_salt': b64url(Uint8List(16)),
      'kdf_params': {
        'alg': 'argon2id',
        'm': 19456,
        't': 2,
        'p': 1,
        'version': 19,
      },
    };

Uint8List _uuid(String s) {
  final hex = s.replaceAll('-', '');
  final out = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
