import 'dart:typed_data';

import '../crypto/canonical_cbor.dart';
import 'directory_record.dart';
import 'directory_rejection.dart';

/// Encodes and decodes [DirectoryRecord] and [PinnedRoot] to/from canonical CBOR.
class DirectoryRecordCodec {
  final CanonicalCborMapper _cbor = CanonicalCborMapper();

  /// Encodes [record] to canonical CBOR (including the appropriate signature container).
  Uint8List encode(DirectoryRecord record) {
    final map = _recordToMap(record); // includes parent_key_id when present
    if (record.parentKeyId != null) {
      map['parent_signature'] = record.parentSignature!;
    } else {
      final sigs = record.rootSignatures.map((rs) {
        return <String, Object?>{
          'root_key_id': rs.rootKeyId,
          'signature': rs.signature,
        };
      }).toList();
      map['root_signatures'] = sigs;
    }
    return _cbor.writeBytes(map);
  }

  /// Decodes [bytes] into a [DirectoryRecord].
  ///
  /// Throws [MalformedCbor] if the bytes cannot be parsed or are non-canonical.
  /// Throws [SignatureContainerConflict] or [SignatureContainerMissing] on XOR violation.
  DirectoryRecord decode(Uint8List bytes) {
    Map<String, dynamic> map;
    try {
      map = _cbor.readValue(bytes);
    } catch (e) {
      throw MalformedCbor('Failed to parse directory record CBOR', e);
    }
    return _recordFromMap(map);
  }

  /// Returns the bytes covered by signatures for [record] (strips all signature containers).
  Uint8List signedBytesOfRecord(DirectoryRecord record) {
    return _cbor.writeBytes(_recordToMap(record));
  }

  /// Parses [recordBytes], strips both signature containers, and re-encodes.
  ///
  /// This is the canonical form that signing keys sign.
  Uint8List signedBytesOfEncoded(Uint8List recordBytes) {
    Map<String, dynamic> map;
    try {
      map = _cbor.readValue(recordBytes);
    } catch (e) {
      throw MalformedCbor('Failed to parse directory record CBOR', e);
    }
    map.remove('root_signatures');
    map.remove('parent_signature');
    return _cbor.writeBytes(map);
  }

  /// Decodes a [PinnedRoot] from canonical CBOR.
  ///
  /// Throws [MalformedCbor] if the bytes cannot be parsed or are non-canonical.
  PinnedRoot decodePinnedRoot(Uint8List bytes) {
    Map<String, dynamic> map;
    try {
      map = _cbor.readValue(bytes);
    } catch (e) {
      throw MalformedCbor('Failed to parse pinned root CBOR', e);
    }

    final version = map['version'] as int;
    final scheme = map['scheme'] as String;
    final threshold = map['threshold'] as int;

    final rawRoots = map['roots'] as List<dynamic>;
    final roots = rawRoots.map((entry) {
      final rootMap = entry as Map<String, dynamic>;
      return RootEntry(
        rootKeyId: rootMap['root_key_id'] as Uint8List,
        publicKey: rootMap['public_key'] as Uint8List,
        validFrom: rootMap['valid_from'] as int,
        validUntil: rootMap['valid_until'] as int,
      );
    }).toList();

    return PinnedRoot(
        version: version, scheme: scheme, threshold: threshold, roots: roots);
  }

  Map<String, Object?> _recordToMap(DirectoryRecord rec) {
    final map = <String, Object?>{
      'version': rec.version,
      'record_type': rec.recordType,
      'subject_id': rec.subjectId,
      'key_id': rec.keyId,
      'public_key': rec.publicKey,
      'key_use': rec.keyUse,
      'status': rec.status,
      'valid_from': rec.validFrom,
      'valid_until': rec.validUntil,
      'issued_at': rec.issuedAt,
    };
    if (rec.parentKeyId != null) {
      map['parent_key_id'] = rec.parentKeyId!;
    }
    return map;
  }

  DirectoryRecord _recordFromMap(Map<String, dynamic> map) {
    final version = map['version'] as int;
    final recordType = map['record_type'] as String;
    final subjectId = map['subject_id'] as Uint8List;
    final keyId = map['key_id'] as Uint8List;
    final publicKey = map['public_key'] as Uint8List;
    final keyUse = map['key_use'] as String;
    final status = map['status'] as String;
    final validFrom = map['valid_from'] as int;
    final validUntil = map['valid_until'] as int;
    final issuedAt = map['issued_at'] as int;

    final hasRootSigs = map.containsKey('root_signatures');
    final hasParentSig = map.containsKey('parent_signature');

    if (hasRootSigs && hasParentSig) {
      throw SignatureContainerConflict(
          'Record has both root_signatures and parent_signature');
    }
    if (!hasRootSigs && !hasParentSig) {
      throw SignatureContainerMissing(
          'Record has neither root_signatures nor parent_signature');
    }

    final parentKeyId =
        map.containsKey('parent_key_id') ? map['parent_key_id'] as Uint8List : null;
    final parentSignature =
        hasParentSig ? map['parent_signature'] as Uint8List : null;

    final rootSignatures = <RootSignature>[];
    if (hasRootSigs) {
      final rawSigs = map['root_signatures'];
      if (rawSigs is List) {
        for (final entry in rawSigs) {
          final sigMap = entry as Map<String, dynamic>;
          rootSignatures.add(RootSignature(
            rootKeyId: sigMap['root_key_id'] as Uint8List,
            signature: sigMap['signature'] as Uint8List,
          ));
        }
      }
    }

    return DirectoryRecord(
      version: version,
      recordType: recordType,
      subjectId: subjectId,
      keyId: keyId,
      publicKey: publicKey,
      keyUse: keyUse,
      status: status,
      validFrom: validFrom,
      validUntil: validUntil,
      issuedAt: issuedAt,
      rootSignatures: rootSignatures,
      parentKeyId: parentKeyId,
      parentSignature: parentSignature,
    );
  }
}
