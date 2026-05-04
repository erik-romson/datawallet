# Terminology

Glossary of terms used throughout the Data Wallet docs and code.
Entries are alphabetical.

## Canonical CBOR directory record

A small, self-describing binary blob that **binds a name to a public
key** under the trust anchor's signature. Every issuer and every
verifier in the system has at least one. Functionally analogous to
an X.509 leaf or intermediate certificate — same job, different
byte format.

Three things make it "canonical CBOR":

1. **CBOR** ([RFC 8949][rfc8949]) is the encoding — a compact binary
   format that maps cleanly onto JSON-like data but produces shorter
   bytes and is unambiguous to parse.
2. **Canonical** means a single, deterministic byte sequence per
   logical record: map keys are sorted, integers are minimally
   encoded, no indefinite-length items, no duplicate keys. Two
   honest implementations *must* produce the same bytes for the same
   logical record. The Java side enforces this in
   [`crypto/CanonicalCborMapper.java`][ccm]; the Flutter side and
   the Python reference generator must produce byte-identical output.
3. **Directory record** is the payload schema: `record_type`
   (`"issuer"` / `"verifier"` / `"intermediate"`), `subject_id`
   (UUID), `key_id`, `pubkey`, `valid_from`, `valid_until`,
   `issued_at`, plus optional metadata. See
   [`docs/specs/crypto-formats.md`][cf] for the full byte layout.

A directory record is **the bytes that get signed**, not a wrapper
around them. The hard rule from [`CLAUDE.md`][claude] applies: wire
bytes = DB `BYTEA` bytes = signed bytes. The server never
re-serializes — it stores `signed_record` verbatim in
[`directory_records`][v1] and re-verifies the signature on every
relevant request. If the canonical encoding drifted between Java
and Flutter, signature verification would fail across stacks; the
cross-stack fixture suite under [`spec/fixtures/`][fixtures] locks
byte equality.

Records are signed either directly by a [pinned root quorum](#pinned-root-quorum)
key (current v1 behaviour) or, under the proposal in
[`docs/further-work/per-install-mobile-issuers.md`][perinstall], by
an `intermediate` whose own record is itself signed by the pinned
root quorum.

**See also:**
[`docs/specs/crypto-formats.md`][cf] § Directory record,
[`docs/specs/fixtures.md`][specfix],
[`docs/how-to/issuer-in-prod.md`](how-to/issuer-in-prod.md) § What
lands in the database.

[rfc8949]: https://www.rfc-editor.org/rfc/rfc8949
[ccm]: ../src/main/java/com/erikromson/datawallet/crypto/CanonicalCborMapper.java
[cf]: specs/crypto-formats.md
[claude]: ../CLAUDE.md
[v1]: ../src/main/resources/db/migration/V1__init.sql
[fixtures]: ../spec/fixtures/
[perinstall]: further-work/per-install-mobile-issuers.md
[specfix]: specs/fixtures.md

## Directory record

The signed binding `(subject_id, key_id) → pubkey + validity`,
stored verbatim as canonical CBOR in the `directory_records` table.
Issuers, verifiers, and (proposed) intermediates each have one or
more. The signature comes from the [pinned root quorum](#pinned-root-quorum)
or from an intermediate that the quorum has blessed.

For the full byte format and signing rules see
[Canonical CBOR directory record](#canonical-cbor-directory-record).

## HSM-backed

Shorthand for *"the private key lives in a hardware security module
(or a managed service that emulates one), and the application calls
out to that module for every signature."* The application never sees
the private key bytes.

In Data Wallet, this term appears around the **intermediate signing
service** in the per-install-mobile-issuers proposal
([`docs/further-work/per-install-mobile-issuers.md`][perinstall]).
Calling that service "HSM-backed" means three separate things, in
this order:

1. **The application is an ordinary Spring Boot service.** It runs
   in a normal process, holds normal config, exposes normal HTTP
   endpoints, talks to Postgres / the Data Wallet server / mobile
   installs. There is nothing special about its codepath until it
   needs a signature.
2. **The signing key sits in an external module.** That module is
   typically one of: a cloud KMS (AWS KMS, GCP KMS, Azure Key Vault),
   a managed cloud HSM (AWS CloudHSM, GCP Cloud HSM, Azure Dedicated
   HSM), a USB / network-attached HSM (YubiHSM 2, Thales, Utimaco),
   or — for dev only — a software keystore.
3. **The application asks the module to sign, byte-by-byte.** Via
   PKCS#11, KMIP, or the cloud provider's SDK. The module returns a
   signature; the private key never leaves it. Compromising the
   application host yields the ability to *request* signatures while
   the host is up, but **not** the ability to exfiltrate the key.

What "HSM-backed" deliberately does **not** mean:

- It does **not** mean the HSM is a separate application you have
  to write. It is hardware (or a managed service); you talk to it
  via a stable API.
- It does **not** mean the Data Wallet server is HSM-backed. Only
  the intermediate is. The Data Wallet server (this repo) does no
  signing of its own — it only verifies.
- It does **not** mean a particular vendor or FIPS level. The
  intermediate is written against PKCS#11 / cloud-SDK abstractions,
  so the choice of module is a config knob, not a code change.
  Strength spectrum (cheapest to strongest): software keystore →
  cloud KMS → managed HSM → on-prem HSM. Cloud KMS is the typical
  production sweet spot for this scale.

**Why the split matters.** The application is a relatively wide
attack surface (HTTP, JSON parsing, attestation libraries, etc.).
The HSM is a narrow attack surface (sign / verify primitives only).
Putting the key behind the narrow surface means an attacker who
breaks the wide surface still cannot walk away with the key — they
can only abuse it for as long as they hold the host. Combined with
short-lived bearer tokens and audited sign requests, this bounds
the blast radius of an intermediate compromise to "what they signed
while we hadn't noticed yet", recoverable by rotating the
intermediate via the offline root quorum.

**See also:**
[`docs/further-work/per-install-mobile-issuers.md`][perinstall] §
*Three distinct layers — do not conflate*.

## Pinned root quorum

The set of long-lived Ed25519 keypairs that act as the **trust anchor**
for the entire system. Everything else — issuer identities, verifier
identities, directory records — is ultimately trusted because it was
signed by a threshold of these keys.

The keys are **pinned**: their public bytes are written into Postgres
(`pinned_root_history`, see migration
[`V7__pinned_root_history.sql`][v7]) and the server only honours
records signed by the currently pinned set. Replacing a pinned root
key requires a `root-update` signed by the *old* quorum — there is no
way to silently swap the anchor.

The keys are a **quorum**: more than one private key is required to
sign anything. The threshold (e.g. "2 of 3") is fixed at quorum
creation time by [`gen-root`][gen-root]. No single operator can
unilaterally bless an issuer or rotate the anchor; a quorum of
operators must cooperate.

Quorum private keys live **offline**, split among the operators who
hold them. They are never on the server, never in Postgres, never on
any network-attached host. They come out only to:

- sign a new issuer directory record ([`sign-directory`][sd])
- sign a new verifier directory record (rare; usually the verifier
  registers itself and the directory entry is server-issued)
- rotate the quorum itself ([`sign-root-update`][sru])

In dev, [`init-dev-trust`][idt] generates a throwaway single-key
quorum, signs the dev issuer/verifier records with it, and seeds
Postgres in one shot. Production never runs `init-dev-trust`.

**See also:** [`docs/specs/plan.md`][plan] § Root quorum,
[`docs/explanation/trust-model.md`][tm],
[`docs/how-to/issuer-in-prod.md`](how-to/issuer-in-prod.md).

[v7]: ../src/main/resources/db/migration/V7__pinned_root_history.sql
[gen-root]: ../src/main/java/com/erikromson/datawallet/cli/GenRootCommand.java
[sd]: ../src/main/java/com/erikromson/datawallet/cli/SignDirectoryRecordCommand.java
[sru]: ../src/main/java/com/erikromson/datawallet/cli/SignRootUpdateCommand.java
[idt]: ../src/main/java/com/erikromson/datawallet/cli/InitDevTrustCommand.java
[plan]: specs/plan.md
[tm]: explanation/trust-model.md
