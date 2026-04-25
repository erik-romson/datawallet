# Data Wallet — cryptographic formats (companion to `plan.md`)

This document pins every byte-level format the plan referred to in prose. Both stacks (Java + lazysodium, Dart + sodium_libs) MUST produce and verify identical bytes for every construction below. The cross-stack fixture (see `fixtures.md`) is the test of record.

All multi-byte integers are big-endian unless stated. All "canonical CBOR" means RFC 8949 §4.2.1 (Core Deterministic Encoding): definite-length maps/arrays, shortest-form integers, sorted keys by lexicographic byte order of their CBOR encoding.

## 1. Constants

| Name | Value | Purpose |
|------|-------|---------|
| `ENVELOPE_VERSION` | `1` | `version` field in shared-entry envelope |
| `WRAP_FORMAT_VERSION` | `1` | `v` field in wrapped-private-key blob |
| `DIRECTORY_RECORD_VERSION` | `1` | `version` field in directory record |
| `ARGON2ID_VERSION` | `0x13` (decimal `19`) | Argon2 v1.3, the only version libsodium ships |
| `KEK_LEN` | `32` | bytes; output of Argon2id, used as secretbox key |
| `SECRETBOX_NONCE_LEN` | `24` | libsodium `crypto_secretbox` nonce |
| `SEAL_KEY_LEN` | `32` | X25519 public/private key length |
| `ED25519_PUB_LEN` | `32` | |
| `ED25519_PRIV_LEN` | `64` | libsodium expanded form (seed ‖ public) |
| `ED25519_SIG_LEN` | `64` | |
| `KDF_SALT_LEN` | `16` | random per verifier, stable across password changes |
| `KEY_ID_LEN` | `16` | random per keypair |
| `AUTH_NONCE_LEN` | `32` | server-issued challenge |
| `SESSION_TOKEN_LEN` | `32` | server-issued session bearer |

`KDF_SALT` is 16 bytes (libsodium `crypto_pwhash_SALTBYTES`). It is regenerated only on key rotation, NOT on password change — re-deriving the KEK with a new salt would invalidate any cached wrapping by other clients.

## 2. KEK derivation

```
KEK = argon2id(
    password   = utf8_nfc(password_string),
    salt       = kdf_salt,                   // 16 bytes
    output_len = KEK_LEN,                    // 32
    m          = kdf_params.m,               // bytes (memory)
    t          = kdf_params.t,
    p          = kdf_params.p,
    version    = ARGON2ID_VERSION
)
```

- Password is normalized **NFC** before encoding to UTF-8. Both stacks MUST apply NFC; libsodium does not.
- Output is used directly as the `crypto_secretbox` key. No HKDF, no truncation, no extra label. Argon2id output is uniformly random over its length, so a separate KDF step adds no value here and creates a divergence risk between stacks.
- `kdf_params.m` is in **bytes** in the API and on disk (matches libsodium `crypto_pwhash` `memlimit`). The plan's "256 MiB" floor is `268_435_456` bytes; "64 MiB" web floor is `67_108_864` bytes.

### Server-side floor enforcement

```
if origin == web:    require m >= 67_108_864 and t >= 3 and p == 1
else (native/api):   require m >= 268_435_456 and t >= 3 and p == 1
require alg == "argon2id"
require version == 19
```

Origin is derived from the `Origin` header on registration; absent header → treat as native (mTLS) or reject (browser). Mobile/desktop native clients MUST NOT send `Origin: web`.

## 3. Wrapped private-key blob format

The blob stored as `wrapped_enc_private_key_blob` / `wrapped_auth_private_key_blob` is **canonical CBOR**:

```cddl
WrappedPrivateKey = {
    "v"     => uint,         ; WRAP_FORMAT_VERSION = 1
    "alg"   => tstr,         ; "secretbox" in v1
    "nonce" => bstr .size 24,
    "ct"    => bstr,         ; secretbox(KEK, plaintext_private_key)
}
```

CBOR map keys sorted lexicographically by their canonical byte encoding: `"v"` (1 byte), `"ct"` (2 bytes), `"alg"` (3 bytes), `"nonce"` (5 bytes) → wire order is `v, ct, alg, nonce`.

Plaintext input:
- Encryption private key: 32-byte X25519 scalar (`crypto_box_keypair` secret key).
- Auth private key: 64-byte Ed25519 expanded private key (libsodium `crypto_sign_keypair` secret key — seed ‖ public). Both stacks store the 64-byte form so signing is a single call without a re-derivation step.

The `nonce` is freshly random for every wrap (every registration, every password change, every key rotation). It is NOT derived from the salt.

Unwrap on the client:
1. Parse canonical CBOR; reject if any deterministic-encoding rule is violated.
2. Reject `v != 1` and `alg != "secretbox"`.
3. `crypto_secretbox_open(ct, nonce, KEK)` → plaintext private key. Failure here is the wrong-password path (no server round-trip).

## 4. Auth challenge signing

```
challenge_to_sign = "datawallet-auth-v1\x00" || nonce_bytes
signature         = ed25519_sign(auth_private_key, challenge_to_sign)
```

- The prefix is the **literal ASCII string `datawallet-auth-v1`** followed by a single 0x00 byte (19 bytes total).
- `nonce_bytes` is the raw 32-byte nonce returned by `POST /v1/auth/challenge` (NOT base64; clients decode it before signing).
- The server applies the same prefix when verifying; it MUST NOT verify the bare nonce. This is the domain separation that prevents the auth key from being a generic signing oracle for envelopes, directory records, or future protocol revisions.

`v1` is part of the prefix on purpose: a future v2 challenge format gets a new prefix and old keys cannot satisfy it.

## 5. Shared-entry envelope: canonical bytes

The envelope is canonical CBOR with field set defined in `plan.md §4.2`. Map key order (lexicographic over canonical byte encoding) for v1:

```
1.  "version"                 (7  bytes)
2.  "entry_id"                (8  bytes)
3.  "issuer_id"               (9  bytes)
4.  "created_at"              (10 bytes)
5.  "issuer_label"            (12 bytes)
6.  "description"             (11 bytes)   // wait — recompute order at the bottom of this section
7.  "signature"               (9  bytes)   //   …
```

> **Note for implementers**: do NOT eyeball the order. Both stacks MUST run their CBOR encoder in canonical mode and let the encoder sort. The fixture (`fixtures.md`) ships the exact byte sequence and both stacks assert against it. If your stack produces a different order, your encoder is not in canonical mode.

### Field types

```cddl
SharedEnvelope = {
    "version"                  => 1,
    "entry_id"                 => bstr .size 16,        ; UUIDv7 raw bytes
    "issuer_id"                => bstr .size 16,        ; UUID raw bytes
    "issuer_label"             => tstr,                 ; max 64 chars (NFC)
    "issuer_signing_key_id"    => bstr .size 16,
    "created_at"               => uint,                 ; ms since epoch UTC
    "description"              => tstr,                 ; max 256 NFC codepoints; "" if absent
    "ciphertext_alg"           => tstr,                 ; "xsalsa20poly1305"
    "ciphertext_nonce"         => bstr .size 24,
    "ciphertext"               => bstr,                 ; secretbox output
    "ciphertext_hash"          => bstr .size 32,        ; sha256(ciphertext) raw
    "recipient_wrappings"      => [+ RecipientWrapping],
    "signature"                => bstr .size 64         ; ed25519 over signed_bytes
}

RecipientWrapping = {
    "verifier_id"              => bstr .size 16,
    "verifier_key_id"          => bstr .size 16,
    "wrapped_data_key"         => bstr                  ; crypto_box_seal(data_key, verifier_enc_pub)
}
```

### Length units

- `issuer_label`: ≤ 64 **Unicode codepoints after NFC normalization**, encoded as UTF-8.
- `description`: ≤ 256 **codepoints after NFC**, UTF-8. Bytes-on-the-wire can therefore be up to 4×256 = 1024.

Both stacks MUST normalize before length-checking and before signing. Server validates after decoding and rejects with `422 schema_violation` on overflow.

### Signing

```
signed_bytes = canonical_cbor( envelope without "signature" key )
signature    = ed25519_sign(issuer_signing_priv, signed_bytes)
final_envelope = canonical_cbor( envelope with "signature" = signature )
```

The `signed_bytes` are computed by encoding the same map **minus** the `"signature"` key. Adding the key after signing keeps the rest of the map canonical because `"signature"` slots into the deterministic position the encoder would have chosen anyway.

Verification reverses this:
1. Parse `final_envelope` (rejecting non-canonical encodings).
2. Extract and remove `"signature"` from the parsed map.
3. Re-encode the remainder canonically → must match `signed_bytes` byte-for-byte.
4. `ed25519_verify(issuer_signing_pub, signed_bytes, signature)`.

The re-encode-and-compare step is the line of defense against a non-canonical CBOR producer that an attacker controls. A native re-serialize of `signed_bytes` from the server's already-stored opaque BYTEA is **not** required for verification — clients just hash & sign against the bytes they received, which is what the server stored verbatim.

### Data-key generation

```
data_key = randombytes_buf(32)              // libsodium crypto_secretbox_KEYBYTES
ciphertext_nonce = randombytes_buf(24)
ciphertext = crypto_secretbox(plaintext_utf8, ciphertext_nonce, data_key)
ciphertext_hash = sha256(ciphertext)        // raw 32 bytes
```

For each recipient `i`:
```
wrapped_data_key_i = crypto_box_seal(data_key, verifier_i_enc_pub)
```

`crypto_box_seal` is anonymous: it does not authenticate the issuer. Recipient authenticity comes from the envelope `signature`. The verifier client MUST NOT call `crypto_box_seal_open` until after `signature` verifies (`plan.md §7.3`, item 3 must precede item 5).

## 6. Directory records

```cddl
DirectoryRecord = {
    "version"        => 1,
    "record_type"    => "verifier" / "issuer",
    "subject_id"     => bstr .size 16,
    "key_id"         => bstr .size 16,
    "public_key"     => bstr .size 32,
    "key_use"        => "enc" / "auth" / "sign",
    "status"         => "active" / "superseded" / "revoked",
    "valid_from"     => uint,                          ; ms since epoch
    "valid_until"    => uint,                          ; ms since epoch
    "issued_at"      => uint,                          ; ms since epoch
    "root_signatures" => [+ RootSignature]
}

RootSignature = {
    "root_key_id" => bstr .size 16,
    "signature"   => bstr .size 64
}
```

`signed_bytes_directory = canonical_cbor(record without "root_signatures")`. Signed independently by ≥ M of N pinned root keys (see §7).

Freshness: clients reject `now() > issued_at + 7d`. Server republishes records at least every 3.5 days (`max_age / 2`).

Status transitions are append-only — a `revoked` record supersedes prior `active` records with the same `(record_type, subject_id, key_id)`. The server retains all records for `valid_until + 30d` for auditability. Clients always pick the freshest record matching the lookup key.

## 7. Root quorum

The pinned trust root is **a set** of N Ed25519 public keys, M of which must sign every directory record and every `root-update` record. v1 default: **N = 3, M = 2**.

```cddl
PinnedRoot = {
    "version"      => 1,
    "scheme"       => "ed25519-quorum-v1",
    "threshold"    => 2,
    "roots"        => [+ {
        "root_key_id" => bstr .size 16,
        "public_key"  => bstr .size 32,
        "valid_from"  => uint,
        "valid_until" => uint
    }]
}
```

This blob is what gets pinned in the client (compiled into native apps, served with `Subresource-Integrity` for web — see `api.md §3.4`). It is NOT signed itself; trust comes from the channel (app store / signed installer / TLS cert pinned in the SPA bundle hash).

### Verification of a directory record

```
sigs = record.root_signatures
for sig in sigs:
    root = pinned.roots.find(r => r.root_key_id == sig.root_key_id)
    require root not null
    require root.valid_from <= record.issued_at < root.valid_until
    require ed25519_verify(root.public_key, signed_bytes_directory, sig.signature)
require count(distinct sig.root_key_id for valid sigs) >= pinned.threshold
```

Duplicate signatures from the same `root_key_id` count once. An attacker forging a single root cannot reach threshold.

### Root rotation

A `RootUpdate` record:
```cddl
RootUpdate = {
    "version"           => 1,
    "old_root_key_ids"  => [* bstr .size 16],
    "new_pinned_root"   => PinnedRoot,
    "issued_at"         => uint,
    "old_root_signatures" => [+ RootSignature]   ; ≥ old.threshold of old.roots
}
```

`signed_bytes_root_update = canonical_cbor(RootUpdate without "old_root_signatures")`. Clients accept it if signed by ≥ threshold of currently-pinned roots that are still within `valid_until`. After acceptance, the pinned set is replaced for that client. App-update-shipped pins always win over chain-shipped pins of the same `valid_from`.

## 8. Key fingerprint (UI display)

```
fp_bytes  = sha256(public_key)[0:10]                    // 10 bytes = 80 bits
fp_string = base32_rfc4648(fp_bytes)                    // 16 chars, no padding
fp_render = fp_string[0:4] + "-" + fp_string[4:8] + "-" + fp_string[8:12] + "-" + fp_string[12:16]
```

Example: `JBSWY3DPEHPK3PXP`. Both stacks render identically. Use Crockford base32 only if a fixture explicitly requires it — v1 uses RFC 4648 (libsodium ships it; Java needs a small helper). Lowercase is acceptable in UI but the fixture compares uppercase.

The fingerprint is computed over the **public key bytes only**, not over the directory record envelope. This makes it stable across `valid_until` changes and lets the verifier visually confirm a key in any context (CLI, UI, audit page).

Both `verifier_id` and `issuer_id` (UUIDs) get a separate short rendering: lowercase base32 of the first 8 bytes, no dashes. Used in admin tooling, not in the user-facing UI.

## 9. Handle format

```
HANDLE_REGEX = /^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$/
```

- 2–32 chars total.
- Lowercase ASCII only — no Unicode in v1 (homograph safety, plan §2).
- May not start or end with `.`, `_`, or `-`.
- Reserved (rejected at registration): `admin`, `root`, `system`, `wallet`, `operator`, `support`, `null`, `undefined`, anything starting with `_`.
- NFC of the input MUST equal the input itself (rejects ZWJ smuggling); easier to check by validating that the input matches the regex against the raw bytes.

Server normalizes the URL path component identically — `/v1/verifiers/Alice/login-blob` → 404, not 400, so handle existence is not leaked by validation order.

## 10. UUIDv7 generation

`entry_id` is UUIDv7 (RFC 9562). v1 implementation rules for both stacks:

```
ts_ms       = current_unix_time_ms                              // 48 bits
rand_a      = randombytes_buf(2)                                // 12 bits used
rand_b      = randombytes_buf(8)                                // 62 bits used
uuid[0..6]  = ts_ms (big-endian, 48 bits → 6 bytes)
uuid[6]     = 0x70 | (rand_a[0] & 0x0F)                         // version 7
uuid[7]     = rand_a[1]
uuid[8]     = 0x80 | (rand_b[0] & 0x3F)                         // RFC variant 10
uuid[9..15] = rand_b[1..7]
```

Both stacks have a unit test against the fixture's deterministic UUIDv7 generation (which feeds in fixed `ts_ms` and fixed random bytes).

## 11. Audit-log hash chain

```
event_canonical = canonical_cbor({
    "seq":        seq,
    "ts":         ts_ms,
    "event_type": event_type,
    "actor_id":   actor_id_bytes,           ; null on system events
    "entry_id":   entry_id_bytes_or_null,
    "payload":    payload_map
})

hash_n = sha256(prev_hash || event_canonical)
```

Genesis row: `seq = 1`, `prev_hash = sha256("datawallet-audit-genesis-v1\x00")` — fixed 32-byte constant, both stacks reproduce it from the fixture.

Anchor publication (out of scope to specify the target): every 24h, the operator signs `(seq_max, hash_at_seq_max, ts)` with an offline anchor key and publishes it. v1 only requires that the operation is **possible** — the chain head is queryable via `GET /v1/admin/audit?head=true`.

## 12. Random-number generation

Both stacks MUST use the libsodium CSPRNG:
- Java: `lazysodium.randomBytesBuf(n)` (delegates to libsodium `randombytes_buf`).
- Dart native: `sodium_libs` `randombytes_buf(n)`.
- Dart web (WASM): same API; libsodium-wasm uses `crypto.getRandomValues` under the hood.

`Random.secure()` (Dart) and `SecureRandom` (Java) are forbidden in code paths that produce keys, nonces, or session tokens — use libsodium's CSPRNG so behavior matches the fixture's mock-RNG harness.

## 13. Zeroing

Sensitive buffers (`KEK`, both private keys, decrypted plaintext, `data_key`) MUST be zeroed when no longer needed:
- Java: `Arrays.fill(arr, (byte)0)` — best effort; JVM may have moved it.
- Dart: `Uint8List.fillRange(0, length, 0)` — best effort; GC may have moved it.

Document this as best-effort in operator-facing docs; do not represent it as a defense against process memory dumps. Hard guarantees would require off-heap buffers + `mlock`, which is out of scope for v1.

## 14. Stack mapping cheat sheet

| Operation | Java (`lazysodium-java`) | Dart (`sodium_libs`) |
|-----------|--------------------------|----------------------|
| Argon2id  | `PwHash.Native.cryptoPwHash(...)` | `sodium.crypto.pwhash(...)` |
| secretbox | `SecretBox.Native.cryptoSecretBoxEasy(...)` | `sodium.crypto.secretBox.easy(...)` |
| crypto_box_seal | `Box.Native.cryptoBoxSeal(...)` | `sodium.crypto.box.seal(...)` |
| Ed25519 sign / verify | `Sign.Native.cryptoSignDetached(...)` | `sodium.crypto.sign.detached(...)` |
| sha256 | `lazySodium.cryptoHashSha256(...)` | `sodium.crypto.genericHash(...)` (use `crypto_hash_sha256` if exposed; otherwise package:crypto for parity — fixture verifies parity) |
| randombytes_buf | `lazySodium.randomBytesBuf(n)` | `sodium.randombytesBuf(n)` |
| CBOR (canonical) | `jackson-dataformat-cbor` with `CBORGenerator.Feature.WRITE_TYPE_HEADER` off, custom canonical sorting `ObjectMapper` config | `package:cbor` with `CborEncoder` in `CborEncoder.canonical()` mode |
