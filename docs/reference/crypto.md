# Crypto formats

The byte-layout authority is [`specs/crypto-formats.md`](../specs/crypto-formats.md);
this page is a navigation aid only.
All keys, nonces, and session tokens are produced exclusively by the libsodium CSPRNG —
`java.security.SecureRandom` and `dart:math.Random` are forbidden in these code paths
(per [`CLAUDE.md`](../../CLAUDE.md)).

## Format index

| Format | Spec section | Java codec | Flutter codec | Fixture |
|--------|-------------|-----------|--------------|---------|
| KEK derivation (Argon2id) | [§2](../specs/crypto-formats.md#2-kek-derivation) | [Argon2id.java](../../src/main/java/com/erikromson/datawallet/crypto/Argon2id.java) | [crypto/argon2id.dart](../../client/lib/src/crypto/argon2id.dart) | [`inputs/passwords.expected.json`](../../spec/fixtures/inputs/passwords.expected.json) |
| Wrapped private-key blob (`WrappedPrivateKey`) | [§3](../specs/crypto-formats.md#3-wrapped-private-key-blob-format) | [SecretBox.java#L3-L7](../../src/main/java/com/erikromson/datawallet/crypto/SecretBox.java#L3-L7) + [CanonicalCborMapper.java](../../src/main/java/com/erikromson/datawallet/crypto/CanonicalCborMapper.java) | [crypto/wrapped_blob.dart](../../client/lib/src/crypto/wrapped_blob.dart) | [`wrapped/enc_priv_alice.cbor`](../../spec/fixtures/wrapped/enc_priv_alice.cbor) |
| Auth challenge signing | [§4](../specs/crypto-formats.md#4-auth-challenge-signing) | [Ed25519.java](../../src/main/java/com/erikromson/datawallet/crypto/Ed25519.java) | [crypto/ed25519.dart](../../client/lib/src/crypto/ed25519.dart) | [`auth/nonce-and-signature.json`](../../spec/fixtures/auth/nonce-and-signature.json) |
| Shared-entry envelope (`SharedEnvelope`) | [§5](../specs/crypto-formats.md#5-shared-entry-envelope-canonical-bytes) | [EnvelopeCodec.java#L12-L14](../../src/main/java/com/erikromson/datawallet/envelope/EnvelopeCodec.java#L12-L14) | [envelope/envelope_codec.dart](../../client/lib/src/envelope/envelope_codec.dart) | [`envelopes/basic-1-recipient.cbor`](../../spec/fixtures/envelopes/basic-1-recipient.cbor) |
| Envelope signing | [§5](../specs/crypto-formats.md#5-shared-entry-envelope-canonical-bytes) | [EnvelopeSigner.java#L5-L13](../../src/main/java/com/erikromson/datawallet/envelope/EnvelopeSigner.java#L5-L13) | [envelope/envelope_signer.dart](../../client/lib/src/envelope/envelope_signer.dart) | [`envelopes/basic-1-recipient.signed`](../../spec/fixtures/envelopes/basic-1-recipient.signed) |
| Recipient wrapping (`RecipientWrapping`, `crypto_box_seal`) | [§5](../specs/crypto-formats.md#5-shared-entry-envelope-canonical-bytes) | [SealedBox.java#L3-L7](../../src/main/java/com/erikromson/datawallet/crypto/SealedBox.java#L3-L7) | [crypto/sealed_box.dart](../../client/lib/src/crypto/sealed_box.dart) | [`envelopes/three-recipients.cbor`](../../spec/fixtures/envelopes/three-recipients.cbor) |
| Directory record (`DirectoryRecord`) | [§6](../specs/crypto-formats.md#6-directory-records) | [DirectoryRecordCodec.java#L10-L14](../../src/main/java/com/erikromson/datawallet/directory/DirectoryRecordCodec.java#L10-L14) | [directory/directory_record_codec.dart](../../client/lib/src/directory/directory_record_codec.dart) | [`directory/verifier-alice-active.cbor`](../../spec/fixtures/directory/verifier-alice-active.cbor) |
| Directory record verification | [§6](../specs/crypto-formats.md#6-directory-records) | [DirectoryRecordVerifier.java#L7-L15](../../src/main/java/com/erikromson/datawallet/directory/DirectoryRecordVerifier.java#L7-L15) | [directory/directory_record_verifier.dart](../../client/lib/src/directory/directory_record_verifier.dart) | [`directory/invalid/tampered-public-key.cbor`](../../spec/fixtures/directory/invalid/tampered-public-key.cbor) |
| Root quorum / pinned root (`PinnedRoot`) | [§7](../specs/crypto-formats.md#7-root-quorum) | [RootUpdateCodec.java#L15-L20](../../src/main/java/com/erikromson/datawallet/directory/RootUpdateCodec.java#L15-L20) | [directory/root_quorum.dart](../../client/lib/src/directory/root_quorum.dart) | [`directory/pinned-root.cbor`](../../spec/fixtures/directory/pinned-root.cbor) |
| Key fingerprint (UI display) | [§8](../specs/crypto-formats.md#8-key-fingerprint-ui-display) | [Fingerprint.java#L3-L10](../../src/main/java/com/erikromson/datawallet/crypto/Fingerprint.java#L3-L10) | [crypto/fingerprint.dart](../../client/lib/src/crypto/fingerprint.dart) | [`fingerprints/pubkey-to-fp.json`](../../spec/fixtures/fingerprints/pubkey-to-fp.json) |
| UUIDv7 generation | [§10](../specs/crypto-formats.md#10-uuidv7-generation) | [UuidV7.java](../../src/main/java/com/erikromson/datawallet/crypto/UuidV7.java) | [crypto/uuid_v7.dart](../../client/lib/src/crypto/uuid_v7.dart) | [`inputs/uuids.expected.json`](../../spec/fixtures/inputs/uuids.expected.json) |
| Audit-log hash chain | [§11](../specs/crypto-formats.md#11-audit-log-hash-chain) | [Sha256.java](../../src/main/java/com/erikromson/datawallet/crypto/Sha256.java) | [crypto/sha256.dart](../../client/lib/src/crypto/sha256.dart) | [`audit/chain-genesis.json`](../../spec/fixtures/audit/chain-genesis.json) |

## Fixture generation

All `.cbor` and `.json` fixture files under `spec/fixtures/` are generated by
[`spec/tools/gen.py`](../../spec/tools/gen.py).
Both Java and Flutter stacks assert byte-for-byte equality against these fixtures in their
respective test suites.
To regenerate after a byte-format change, follow
[`how-to/regenerate-fixtures.md`](../how-to/regenerate-fixtures.md).

## See also

- [`specs/crypto-formats.md`](../specs/crypto-formats.md) — normative byte-layout specification
- [`specs/fixtures.md`](../specs/fixtures.md) — fixture catalog and cross-stack test policy
- [`explanation/envelope-lifecycle.md`](../explanation/envelope-lifecycle.md) — how formats compose in the envelope flow
- [`explanation/trust-model.md`](../explanation/trust-model.md) — root quorum and directory record trust chain
- [`reference/audiences/security-reviewer.md`](audiences/security-reviewer.md) — threat-model map
