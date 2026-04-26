# HTTP API

The wire-format authority is [`specs/api.md`](../specs/api.md); this page is a
navigation aid only — it does not restate request or response shapes.

## Endpoint index

| Method | Path | Purpose | Spec section | Controller |
|--------|------|---------|-------------|-----------|
| `POST` | `/v1/verifiers` | Register a new verifier | [§3.1](../specs/api.md#31-verifier-registration--account) | [VerifierController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java) |
| `GET` | `/v1/verifiers/{handle}/login-blob` | Retrieve login blob for a handle | [§3.1](../specs/api.md#31-verifier-registration--account) | [VerifierController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java) |
| `POST` | `/v1/verifiers/{id}/password` | Change password (re-wrap keys) | [§3.1](../specs/api.md#31-verifier-registration--account) | [VerifierRotationController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierRotationController.java) |
| `POST` | `/v1/verifiers/{id}/rotate-keys` | Rotate enc + auth keypairs | [§3.1](../specs/api.md#31-verifier-registration--account) | [VerifierRotationController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierRotationController.java) |
| `POST` | `/v1/auth/challenge` | Issue a single-use auth nonce | [§3.2](../specs/api.md#32-authentication) | [AuthController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/auth/AuthController.java) |
| `POST` | `/v1/auth/verify` | Verify challenge signature, issue session token | [§3.2](../specs/api.md#32-authentication) | [AuthController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/auth/AuthController.java) |
| `POST` | `/v1/auth/logout` | Invalidate session token | [§3.2](../specs/api.md#32-authentication) | [AuthController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/auth/AuthController.java) |
| `POST` | `/v1/entries` | Submit a new signed envelope (mTLS) | [§3.3](../specs/api.md#33-issuer-ingest--lifecycle) | [EntryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/entry/EntryController.java) |
| `PUT` | `/v1/entries/{id}` | Update an envelope with a new version (mTLS) | [§3.3](../specs/api.md#33-issuer-ingest--lifecycle) | [EntryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/entry/EntryController.java) |
| `GET` | `/v1/entries` | List the issuer's current entries (mTLS) | [§3.3](../specs/api.md#33-issuer-ingest--lifecycle) | [EntryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/entry/EntryController.java) |
| `POST` | `/v1/issuers/{id}/rotate-signing-key` | Rotate the issuer's signing key (mTLS) | [§3.3](../specs/api.md#33-issuer-ingest--lifecycle) | [IssuerKeyController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/entry/IssuerKeyController.java) |
| `GET` | `/v1/directory/verifiers/{handle}` | Fetch a verifier's signed directory record | [§3.4](../specs/api.md#34-directory) | [DirectoryQueryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/directory/DirectoryQueryController.java) |
| `GET` | `/v1/directory/issuers/{id}` | Fetch an issuer's directory records | [§3.4](../specs/api.md#34-directory) | [DirectoryQueryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/directory/DirectoryQueryController.java) |
| `GET` | `/v1/directory/root` | Fetch pinned root keys and in-flight root-update records | [§3.4](../specs/api.md#34-directory) | [DirectoryQueryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/directory/DirectoryQueryController.java) |
| `GET` | `/v1/shared` | List envelopes shared with the authenticated verifier | [§3.5](../specs/api.md#35-verifier-retrieval) | [SharedController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/shared/SharedController.java) |
| `GET` | `/v1/shared/{id}` | Fetch a single signed envelope (`application/cbor`) | [§3.5](../specs/api.md#35-verifier-retrieval) | [SharedController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/shared/SharedController.java) |
| `POST` | `/v1/admin/directory` | Publish a signed directory record (mTLS operator) | [§3.6](../specs/api.md#36-operator--admin) | [AdminDirectoryController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/admin/AdminDirectoryController.java) |
| `POST` | `/v1/admin/root-update` | Publish a signed root-update record (mTLS operator) | [§3.6](../specs/api.md#36-operator--admin) | [AdminRootUpdateController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/admin/AdminRootUpdateController.java) |
| `GET` | `/v1/admin/audit` | Query the audit log with hash-chain head (mTLS operator) | [§3.6](../specs/api.md#36-operator--admin) | [AdminAuditController.java](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/admin/AdminAuditController.java) |

## Auth and content-type notes

All authenticated endpoints use opaque 32-byte bearer tokens sent as
`Authorization: Bearer <token>` — no cookies, no CSRF surface
(per [`CLAUDE.md`](../../CLAUDE.md)).
Signed payloads (envelope upload and download, directory record publish)
use `Content-Type: application/cbor`; all other endpoints use
`application/json` with binary fields as base64url without padding.
The full auth flow is specified in [`specs/api.md §3.2`](../specs/api.md#32-authentication).

## See also

- [`specs/api.md`](../specs/api.md) — normative wire-format specification
- [`reference/crypto.md`](crypto.md) — byte-layout formats for CBOR payloads
- [`explanation/envelope-lifecycle.md`](../explanation/envelope-lifecycle.md) — upload and fetch flow
- [`explanation/trust-model.md`](../explanation/trust-model.md) — mTLS issuer and operator trust boundaries
