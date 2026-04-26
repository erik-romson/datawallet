# Cross-stack fixture suite

This directory contains deterministic test fixtures for the Data Wallet project.
Both the Java and Dart stacks run contract tests against these files to ensure
byte-level agreement on every cryptographic construction.

## Regenerating

```sh
pip install -r spec/tools/requirements.txt
python spec/tools/gen.py
```

## Verifying (CI)

```sh
python spec/tools/gen.py --check
```

Exits 0 when committed fixtures match regenerated output, 1 on drift.

## Rules

- **Never hand-edit** files in this directory (except `inputs/*.json`).
- All generated artifacts come from `spec/tools/gen.py`.
- To change a fixture: edit `inputs/*.json`, run `gen.py`, inspect the diff, commit.
- Byte-level formats are defined in `docs/specs/crypto-formats.md`.
- Fixture design is defined in `docs/specs/fixtures.md`.

## Layout

- `inputs/` — deterministic seeds, passwords, timestamps, plaintexts
- `wrapped/` — wrapped private-key blobs (canonical CBOR)
- `envelopes/` — shared-entry envelopes (`.cbor`, `.signed`, `.json` sidecar)
- `envelopes/invalid/` — intentionally malformed envelopes for negative tests
- `directory/` — directory records and pinned root
- `directory/invalid/` — malformed directory records
- `auth/` — auth challenge signature vectors
- `audit/` — audit hash-chain vectors
- `fingerprints/` — public-key fingerprint vectors
- `manifest.json` — SHA-256 index of every artifact
