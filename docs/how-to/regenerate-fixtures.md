# Regenerate cross-stack fixtures

The fixtures under `spec/fixtures/` are committed test data shared
between the Java codec and the Flutter codec. They define the exact
byte sequences both stacks must produce and consume. The generator
[`spec/tools/gen.py`](../../spec/tools/gen.py) is the single source of
truth; the `.json` and `.cbor` files it produces are never hand-edited.

## When to regenerate

- A wire-format byte layout changed — in which case
  [`specs/crypto-formats.md`](../specs/crypto-formats.md) must be updated
  *first*, before touching the generator or the codecs.
- A new fixture is added (for example, a new envelope variant or a new
  auth-nonce scenario).

## Steps

1. **Update `specs/crypto-formats.md`** if the byte layout changed. The
   spec is the source of truth; the generator and both codecs follow it.
   Never update the generator first.

2. **Update `spec/tools/gen.py`** to produce the new bytes. The script
   uses `pynacl` for crypto and `cbor2` (canonical mode) for CBOR — the
   same primitives the Java and Flutter stacks wrap
   ([lines 1–29](../../spec/tools/gen.py#L1-L29)).

3. **Run the generator** and confirm only the expected files changed:

   ```sh
   # spec/tools/gen.py
   python3 spec/tools/gen.py
   ```

   The script also accepts a `--check` flag to compare against committed
   fixtures without overwriting them — useful for verifying that the
   committed files match the generator without making changes:

   ```sh
   # spec/tools/gen.py
   python3 spec/tools/gen.py --check
   ```

   After regeneration, inspect the diff with `git diff spec/fixtures/` and
   confirm only the files you expected changed. The
   [`spec/fixtures/manifest.json`](../../spec/fixtures/manifest.json)
   records expected SHA-256 hashes; the generator updates it automatically.

4. **Update both Java and Flutter codecs** to match the new byte layout.
   Neither stack should be updated before the other — divergence causes
   the cross-stack fixture suite to fail immediately. Then run both test
   suites:

   ```sh
   mvn verify
   (cd client && flutter test)
   ```

   Both must pass on the new fixtures before you commit.

5. **Commit the regenerated fixture files together with the codec
   changes** in a single commit. A commit that updates only one side
   will leave the repo in a broken state for the other stack.

## Don't

- Hand-edit a `.cbor` or `.json` file under `spec/fixtures/`. The
  generator is the source of truth; manual edits immediately desync Java
  and Flutter and will be silently overwritten on the next `gen.py` run.
- Update only one codec stack. The cross-stack fixture tests in both
  `mvn verify` and `flutter test` fail fast on any divergence — fix the
  codec, not the test assertion.

## See also

- [Add an HTTP endpoint](add-an-endpoint.md)
- [`specs/crypto-formats.md`](../specs/crypto-formats.md) — authoritative
  byte-layout spec
- [`specs/fixtures.md`](../specs/fixtures.md) — fixture catalog and
  category descriptions
- [`spec/tools/gen.py`](../../spec/tools/gen.py) — the reference generator
