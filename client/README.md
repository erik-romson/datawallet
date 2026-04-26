# Data Wallet — Flutter verifier client

End-to-end-encrypted verifier client. Logs in with handle + password, derives the Argon2id KEK locally, unwraps the verifier's enc/auth private keys in memory, and decrypts envelopes from the server. No plaintext or private keys are ever sent to the server.

See the top-level [`README.md`](../README.md) for system-wide context.

## Quick start (web, against a local server)

Prereqs:

- Flutter stable (Dart 3.x). `flutter doctor` should be green.
- The Data Wallet server running at `http://localhost:8443` (run `bin/start.sh` from the repo root).
- Web target enabled: `flutter config --enable-web` (one-time).

From the repo root the easy path is:

```sh
bin/start-client.sh                # one-shot bootstrap + run
bin/start-client.sh --rebuild      # wipe build artifacts and re-bootstrap
```

The script does everything below. It's idempotent — second run skips the steps that are already done.

## What the script does (and what to do manually)

If you'd rather drive it by hand:

```sh
cd client

# 1. Install Dart/Flutter packages (one-time, or after pubspec changes)
flutter pub get

# 2. Download libsodium.js (sumo variant — Argon2id lives there) and patch
#    web/index.html to load it. One-time. Skip if web/sodium.js already exists.
dart run sodium:update_web --sumo

# 3. Run on Chrome on a fixed port so the server's CORS allow-list matches
flutter run -d chrome --web-port=3000 \
  --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
```

Step 2 is the gotcha: without it `SodiumSumoInit.init()` hangs forever and the page stays blank. The `sodium` package's build hooks set up native targets automatically, but **web** still needs `sodium.js` copied into `web/` and a `<script>` tag added to `index.html` — that's what `update_web` does.

`--web-port=3000` matters because the server's CORS `DATAWALLET_WEB_ORIGIN` defaults to `http://localhost:3000`. If you change one, change the other.

## Registering a verifier

There is no in-app sign-up by design. Register from the Java CLI in the repo root:

```sh
bin/cli.sh register-verifier \
  --url http://localhost:8443 \
  --handle erik \
  --password
# password is prompted interactively when --password has no inline value
```

The CLI does the same crypto the Flutter app would: generates X25519 + Ed25519 keypairs, derives the Argon2id KEK at the native floor (m = 256 MiB, t = 3, p = 1), SecretBox-wraps both private keys, and POSTs `/v1/verifiers`. KEK derivation takes ~3–5 s. After `201 Created`, log in via the browser with the same handle and password.

## Sharing an entry with a verifier

Once registered, an issuer can post an envelope. This requires running the server with the dev profile so the CLI can authenticate via header instead of mTLS:

```sh
# Stop the current server (Ctrl-C in its terminal), then:
bin/start.sh --dev

# One-time bootstrap of dev trust roots + issuer key:
bin/cli.sh init-dev-trust \
  --jdbc-url jdbc:postgresql://localhost:5432/datawallet \
  --jdbc-user wallet_app \
  --jdbc-password \
  --passphrase

# Encrypt + sign + upload an envelope to verifier 'erik':
bin/cli.sh share-with-verifier \
  --url http://localhost:8443 \
  --to erik \
  --plaintext "Approved: \$50,000 at 4.5%" \
  --description "Loan offer #42" \
  --jdbc-url jdbc:postgresql://localhost:5432/datawallet \
  --jdbc-user wallet_app \
  --jdbc-password \
  --passphrase \
  --dev
```

After upload, refresh the Flutter shared-list screen — the entry appears, tap to decrypt.

## Other targets

```sh
flutter devices                                                      # what's available
flutter run -d macos    --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
flutter run -d <ios-id> --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
```

Native targets don't need the `sodium:update_web` step — the `sodium` package's build hooks bundle the FFI library automatically.

For release builds:

```sh
flutter build web    --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
flutter build apk    --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
flutter build macos  --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
```

Web release also needs `dart run sodium:update_web --sumo` once before the build (the patched `index.html` and `web/sodium.js` are part of the artifact).

## Tests

```sh
flutter test         # 68 tests, native (FFI sodium); takes ~10 s
```

Tests don't need `update_web` — they run in the Dart VM, not the browser.

## Troubleshooting

- **Blank page, console shows only DDC bootstrap lines:** `dart run sodium:update_web --sumo` was skipped or undone by `flutter clean`. Re-run it.
- **`ApiException(404): Handle not found: <name>`:** the verifier isn't registered. Use `bin/register_verifier.dart`.
- **`ApiException(400)` with `kdf_below_floor`:** Argon2id m/t/p doesn't meet the server floor. The registration script already uses the native floor (256 MiB) — only happens if you tweak it.
- **CORS errors in the browser console:** `--web-port` and the server's `DATAWALLET_WEB_ORIGIN` don't match. Either start the client on port 3000 or restart the server with the right origin.
- **Login spinner stuck for 5+ seconds:** that's normal — Argon2id at the floor takes 1–4 s. Wait it out.

## Where things live

| Path | Purpose |
|---|---|
| `lib/main.dart` | App entry; SodiumSumoInit, routing between login and shared list |
| `lib/src/api/` | HTTP clients (`auth_client`, `shared_client`, `directory_client`) |
| `lib/src/crypto/` | Canonical CBOR + libsodium primitives (mirrors Java `crypto/`) |
| `lib/src/envelope/` | Envelope codec, signer, verifier |
| `lib/src/directory/` | Directory record codec + root quorum verification |
| `lib/src/state/` | `Session`, `WalletState` (in-memory bearer + key material, zeroed on logout/idle/background) |
| `lib/src/screens/` | `LoginScreen`, `SharedListScreen`, `SharedDetailScreen` |
| `lib/src/widgets/` | `IdentityStrip` |
| `test/` | Widget + crypto + fixture tests |
| `web/sodium.js` | libsodium WASM/JS payload (added by `dart run sodium:update_web --sumo`) |
