# CLI commands

The CLI lives under
`src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/`
and is invoked via [`bin/cli.sh`](../../bin/cli.sh).
Each command is a Picocli `@Command`-annotated Spring component active under the `cli` profile.

## Command index

| Command | Class | What it does | Used in |
|---------|-------|-------------|---------|
| `gen-root` | [GenRootCommand.java#L20-L24](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/GenRootCommand.java#L20-L24) | Generate root quorum keypairs and write a `pinned-root.cbor` blob | [`explanation/trust-model.md`](../explanation/trust-model.md) |
| `init-dev-trust` | [InitDevTrustCommand.java#L44-L48](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/InitDevTrustCommand.java#L44-L48) | Bootstrap dev trust roots, issuer key, and seed Postgres | [`bats/happy_path.bats`](../../bats/happy_path.bats) |
| `sign-directory` | [SignDirectoryRecordCommand.java#L25-L29](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/SignDirectoryRecordCommand.java#L25-L29) | Sign a directory-record JSON with one or more root keys | [`explanation/trust-model.md`](../explanation/trust-model.md) |
| `sign-root-update` | [SignRootUpdateCommand.java#L30-L34](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/SignRootUpdateCommand.java#L30-L34) | Sign a root-update record with the old root keys | [`explanation/trust-model.md`](../explanation/trust-model.md) |
| `build-envelope` | [BuildEnvelopeCommand.java#L32-L36](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/BuildEnvelopeCommand.java#L32-L36) | Encrypt plaintext for recipients and produce a signed CBOR envelope | [`tutorials/first-share.md`](../tutorials/first-share.md) |
| `upload-envelope` | [UploadEnvelopeCommand.java#L31-L35](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/UploadEnvelopeCommand.java#L31-L35) | POST a signed CBOR envelope to the wallet server | [`tutorials/first-share.md`](../tutorials/first-share.md) |
| `register-verifier` | [RegisterVerifierCommand.java#L32-L36](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/RegisterVerifierCommand.java#L32-L36) | Register a new verifier (handle + password) on the server | [`bats/happy_path.bats`](../../bats/happy_path.bats) |
| `share-with-verifier` | [ShareWithVerifierCommand.java#L35-L39](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/ShareWithVerifierCommand.java#L35-L39) | Encrypt, sign, and upload an envelope for a registered verifier | [`bats/happy_path.bats`](../../bats/happy_path.bats) |
| `verifier-fetch` | [VerifierFetchCommand.java#L38-L42](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/cli/VerifierFetchCommand.java#L38-L42) | Verifier login, list shared entries, and optionally decrypt one | [`bats/happy_path.bats`](../../bats/happy_path.bats) |

<!-- TODO: this table is hand-rolled. It should eventually be generated from Picocli annotations. -->

## See also

- [`specs/plan.md`](../specs/plan.md) — design and threat model
- [`explanation/trust-model.md`](../explanation/trust-model.md) — root → directory trust chain
- [`explanation/envelope-lifecycle.md`](../explanation/envelope-lifecycle.md) — build → sign → upload phases
- [`tutorials/first-share.md`](../tutorials/first-share.md) — end-to-end walkthrough of the happy-path commands
