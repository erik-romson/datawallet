import 'dart:convert';
import 'dart:typed_data';

import 'package:datawallet/src/api/api_client.dart';
import 'package:datawallet/src/api/api_exception.dart';
import 'package:datawallet/src/api/shared_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  group('SharedClient.listShared', () {
    test('passes bearer header, parses items and next_cursor', () async {
      final keyId = Uint8List.fromList(List.generate(16, (i) => i));
      final body = {
        'items': [
          {
            'entry_id': '11111111-2222-3333-4444-555555555555',
            'issuer_id': '66666666-7777-8888-9999-aaaaaaaaaaaa',
            'issuer_label': 'Acme',
            'issuer_signing_key_id': b64url(keyId),
            'created_at': '2026-05-09T10:00:00Z',
            'description': 'Tax 2025',
          },
          {
            'entry_id': 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
            'issuer_id': '66666666-7777-8888-9999-aaaaaaaaaaaa',
            'issuer_label': 'Acme',
            'issuer_signing_key_id': b64url(keyId),
            'created_at': '2026-05-09T11:00:00Z',
            'description': 'Tax 2024',
          },
        ],
        'next_cursor': 'cursor-abc',
      };

      final client = SharedClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          expect(req.method, 'GET');
          expect(req.url.path, '/v1/shared');
          expect(req.url.queryParameters['limit'], '50');
          expect(req.headers['Authorization'], 'Bearer tok');
          return http.Response(jsonEncode(body), 200);
        }),
      );

      final result = await client.listShared('tok');
      expect(result.items.length, 2);
      expect(result.items[0].entryId, '11111111-2222-3333-4444-555555555555');
      expect(result.items[0].issuerSigningKeyId, equals(keyId));
      expect(result.nextCursor, 'cursor-abc');
    });

    test('passes cursor and custom limit when provided', () async {
      final client = SharedClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          expect(req.url.queryParameters['cursor'], 'cursor-xyz');
          expect(req.url.queryParameters['limit'], '10');
          return http.Response(
              jsonEncode({'items': [], 'next_cursor': null}), 200);
        }),
      );

      final result =
          await client.listShared('tok', cursor: 'cursor-xyz', limit: 10);
      expect(result.items, isEmpty);
      expect(result.nextCursor, isNull);
    });

    test('omits issuer_label and description when missing in JSON', () async {
      final keyId = Uint8List(16);
      final body = {
        'items': [
          {
            'entry_id': '11111111-2222-3333-4444-555555555555',
            'issuer_id': '66666666-7777-8888-9999-aaaaaaaaaaaa',
            'issuer_signing_key_id': b64url(keyId),
            'created_at': '2026-05-09T10:00:00Z',
          },
        ],
      };
      final client = SharedClient(
        baseUrl: 'https://example.test',
        httpClient:
            MockClient((req) async => http.Response(jsonEncode(body), 200)),
      );

      final result = await client.listShared('tok');
      expect(result.items.single.issuerLabel, '');
      expect(result.items.single.description, '');
      expect(result.nextCursor, isNull);
    });

    test('non-200 throws ApiException with parsed error code', () async {
      final client = SharedClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async => http.Response(
              jsonEncode({
                'error': {'code': 'unauthorized', 'message': 'token expired'}
              }),
              401,
            )),
      );

      await expectLater(
        client.listShared('tok'),
        throwsA(isA<ApiException>()
            .having((e) => e.statusCode, 'statusCode', 401)
            .having((e) => e.errorCode, 'errorCode', 'unauthorized')),
      );
    });
  });

  group('SharedClient.getShared', () {
    test('returns raw bytes and sends Accept: application/cbor', () async {
      final cbor = Uint8List.fromList([0xa1, 0x01, 0x02]);
      final client = SharedClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient((req) async {
          expect(req.url.path, '/v1/shared/some-entry-id');
          expect(req.headers['Accept'], 'application/cbor');
          expect(req.headers['Authorization'], 'Bearer tok');
          return http.Response.bytes(cbor, 200);
        }),
      );

      final result = await client.getShared('tok', 'some-entry-id');
      expect(result, equals(cbor));
    });

    test('non-200 throws ApiException', () async {
      final client = SharedClient(
        baseUrl: 'https://example.test',
        httpClient: MockClient(
            (req) async => http.Response('not found', 404)),
      );

      await expectLater(
        client.getShared('tok', 'missing'),
        throwsA(isA<ApiException>()
            .having((e) => e.statusCode, 'statusCode', 404)),
      );
    });
  });
}
