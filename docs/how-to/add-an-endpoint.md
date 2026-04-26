# Add an HTTP endpoint

The pattern for a new endpoint is: controller → co-located DTOs →
integration test → spec update if the wire format changes. Follow an
existing controller as your template rather than building from scratch.

## Pick an exemplar

[`VerifierController.java`](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java)
is a good starting point. It shows the full pattern:

- `@RestController` + `@RequestMapping` at the class level
  ([lines 32–34](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java#L32-L34))
- Constructor injection of `AuditService` and a `@Value` property
  ([lines 43–49](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java#L43-L49))
- A POST handler consuming and producing `application/json`
  ([lines 51–92](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java#L51-L92))
- An `auditService.recordEvent(...)` call before returning
  ([lines 85–88](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierController.java#L85-L88))

Its integration test lives at
[`VerifierControllerIT.java`](../../src/test/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierControllerIT.java)
and shows the `@SpringBootTest` + `@Import(PostgresTestcontainer.class)` harness
([lines 25–29](../../src/test/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierControllerIT.java#L25-L29)).

## Steps

1. **Create the controller class** under `src/main/java/.../api/<area>/`.
   Name it `<Area>Controller.java`. Annotate with `@RestController` and
   `@RequestMapping("/v1/<area>")`.

2. **Co-locate DTOs** in the same `api/<area>/` package — request bodies,
   response bodies, and validation helpers all live next to the controller,
   not in a shared package. See
   [`VerifierRegistrationDto.java`](../../src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/api/verifier/VerifierRegistrationDto.java)
   as an example.

3. **Wire `AuditService` via the interface.** Inject it through the
   constructor and call `auditService.recordEvent(...)` for every
   state-changing operation. Never write to the audit table inline.
   The interface contract is the system boundary; controllers must not
   bypass it.

4. **Add an integration test** under
   `src/test/java/.../api/<area>/<Area>ControllerIT.java`. Use the
   `@SpringBootTest` + `@AutoConfigureMockMvc` + `@ActiveProfiles("test")`
   + `@Import(PostgresTestcontainer.class)` combination. Docker must be
   running — Testcontainers starts a real Postgres instance per test run.

5. **Choose the right content type.** If the request or response body is a
   signed payload, use `application/cbor`; otherwise use
   `application/json`. Binary fields in JSON go as base64url *without
   padding* (no `=` characters). See the wire-format rules in
   [`specs/api.md`](../specs/api.md).

6. **Update `specs/api.md` first** if the new endpoint changes the wire
   format. If byte layouts change, regenerate fixtures via
   `spec/tools/gen.py` before touching the codec — see
   [Regenerate cross-stack fixtures](regenerate-fixtures.md).

## Don't

- Use `java.security.SecureRandom` or any non-libsodium source for keys,
  nonces, or session tokens.
- Re-serialize a signed payload on the server. Wire bytes = DB bytes =
  signed bytes; the server stores and forwards the original bytes.
- Inline audit writes. All audit calls go through `AuditService`.
- Validate at internal boundaries. Validate only at system edges: HTTP
  handlers, CLI arg parsers, and DB reads of externally-supplied bytes.

## See also

- [First-share tutorial](../tutorials/first-share.md) — a worked end-to-end example
- [Add a Flyway migration](add-a-migration.md)
- [Regenerate cross-stack fixtures](regenerate-fixtures.md)
- [`specs/api.md`](../specs/api.md) — authoritative wire-format spec
