# Further work: why hashing a national ID does not make it private

**Status:** design rationale, not a proposal. Documents an approach
we will *not* take if verifier-initiated pull (see
[`per-install-mobile-issuers.md`](per-install-mobile-issuers.md))
ever ships.
**Audience:** anyone who, while designing a verifier→issuer lookup,
reaches for "let's just hash the fødselsnummer" as the privacy
mitigation.
**Scope:** explains why a hashed national identifier (Norwegian
fødselsnummer, US SSN, EU national IDs of similar shape) is **not**
a meaningful pseudonym, and what to use instead.

## The temptation

When verifier A wants to pull data from issuer X without first
having a relationship, the verifier needs a stable handle that
points at the same person every time. The only handles that work
without prior contact are **globally identifying** by construction:
fødselsnummer, phone number, email address (see
[`per-install-mobile-issuers.md`](per-install-mobile-issuers.md)
§ "Why this is hard").

A common reflex is: *we don't want to store fødselsnummer in
plaintext, so we'll hash it. The hash is what verifiers and the
server see; only the trusted broker holds the mapping.*

This intuition is wrong. A hash of a fødselsnummer is **not** a
pseudonym in any privacy-meaningful sense. The reason is not
subtle, but it is easy to miss when "hash" feels like a magic word
for "now it's safe".

## The entropy problem

A cryptographic hash (SHA-256, BLAKE2, etc.) is safe when its
input is **unpredictable**. It provides no protection when the
input is drawn from a small, known domain.

Fødselsnummer structure:

| Part | Range |
|---|---|
| Date of birth (DDMMYY) | ~365 × 110 ≈ 40 000 values per century |
| Individual number (3 digits, gender-coded) | ~500 per date |
| Check digits (2) | deterministic from the first 9 — zero extra entropy |

Total valid fødselsnumre currently in use in Norway: roughly
**5–6 million**. Total ever issued (including deceased and
emigrated): roughly **10–12 million**.

A modern GPU performs **billions** of SHA-256 operations per
second. Hashing every possible valid fødselsnummer takes **under
one second**. A leaked database of `hashed_fnr` columns can be
fully de-anonymized in the time it takes to make coffee.

```
$ time python -c "
import hashlib
for d in range(1, 32):
    for m in range(1, 13):
        for y in range(100):
            for i in range(1000):
                fnr = f'{d:02}{m:02}{y:02}{i:03}00'
                hashlib.sha256(fnr.encode()).hexdigest()
"
real  0m6.2s   # Python. Optimized C/GPU: <1s.
```

You have not protected the identifier — you have built a rainbow
table on the attacker's behalf.

## Why salt does not save it

### Single global salt

If there is one global salt shared across all rows (as is required
to make lookups work), then a database leak that includes the
salt — and database leaks routinely include configuration —
allows the same exhaustive search:

```
fnr → sha256(salt || fnr)
```

12 million hash operations. Still under one second. The salt is
not a defense; it is at most a per-deployment nuisance.

### Per-row salt

Per-row salt (the technique used for password hashing) breaks
lookup entirely. The whole point of the hash was that *given a
fnr*, you find the row. That requires determinism, which per-row
salt destroys.

### Slow KDF

Argon2id or scrypt with high parameters slows the attacker, but it
also slows every legitimate lookup. Tuned to 100 ms per hash:
12 million × 100 ms ≈ 14 days on one machine, hours on a GPU
cluster. Better than plain SHA-256, but still well within reach
for any motivated attacker, and now every legitimate request pays
that cost.

## Why HMAC just relocates the secret

The only construction that genuinely resists offline brute-force
on this input space is HMAC with a secret key:

```
handle = HMAC-SHA256(server_secret, fnr)
```

If `server_secret` never leaks, an attacker with the database
cannot recover `fnr` from `handle`. Brute-forcing the keyspace is
infeasible because they lack the key.

But this only relocates the problem:

1. **The secret is now the critical asset.** An attacker who
   compromises the host holding `server_secret` recovers all
   handles in the same sub-second window as before.
2. **The secret must be online.** It is needed at every lookup,
   so it lives somewhere a running process can reach it. Database
   dumps frequently include environment variables, KMS-cache
   files, or in-memory secrets captured from process snapshots.
3. **It centralizes trust.** A single component now controls the
   privacy of every record — the opposite of Data Wallet's
   "compromised server is survivable" stance.
4. **Key rotation is painful.** Rotating `server_secret` requires
   regenerating every handle in lockstep, or keeping every
   historical key online indefinitely.

HMAC over a low-entropy identifier is reasonable as a
**per-database blinding** against casual snooping. It is a weak
defense against targeted compromise.

## The deeper problem: hashing does not change the information theory

Even if the hash were uncrackable, a deterministic hash of a
national identifier still has every property that makes the
identifier itself a privacy hazard:

- **Deterministic per person.** Same person → same handle, always.
  If the same handle appears in two contexts (two verifiers, two
  databases, two time periods), they correlate. The fødselsnummer
  *role* is preserved; only its readability changes.

- **Globally unique.** Exactly one person is behind each handle.
  A leaked handle is still a pointer to a specific human being —
  just like the fnr it was derived from.

- **Not pairwise.** Every verifier asking about Kari receives the
  same handle. Two verifiers comparing notes ("do you also have
  handle Y?") can correlate their customer bases without the
  broker's involvement. Defeating this kind of correlation is
  the entire reason pairwise pseudonyms exist.

- **Externally enumerable.** Fødselsnummer is *not a secret* — it
  is an identifier. An attacker who is interested in a specific
  person typically already knows their fnr (it appears on tax
  forms, insurance documents, employer records, and is regularly
  leaked at scale). Given the fnr and the hashing scheme, the
  attacker can compute the handle themselves and ask "does this
  person exist in this system?" — turning the database into an
  oracle for membership queries.

These properties are inherited from the **input being a national
identifier**, not from the hash. No transformation that preserves
lookup-by-fnr can remove them.

## What hashing fnr is legitimately useful for

To be precise — hashing is not pointless. It is just not what
people typically reach for it to do:

- **Log hygiene.** Replacing fnr with HMAC(fnr) in application
  logs, audit trails, and DBA-visible columns reduces the chance
  that day-to-day operations expose the raw identifier. This is
  worthwhile, but it is hygiene, not privacy.
- **Indexed lookup behind an HSM boundary.** If the HMAC key
  lives in an HSM and lookup is performed via an HSM `verify`
  API ("does this fnr match the handle in this row?"), an offline
  database leak does not yield the mapping. This works, but
  promotes the HSM to a critical online dependency on every
  lookup.
- **Display obfuscation.** Replacing visible fnr with a derived
  short code in support tools and UI prevents shoulder-surfing
  and accidental disclosure. Compliance/policy value, not
  cryptographic value.

Each of these is fine in its place. None of them turn a hashed
fødselsnummer into a pseudonym suitable for cross-system identity.

## The right shape

If the requirement is "a stable, opaque per-person handle that
does not propagate the fnr to every system that needs to refer to
the person", the construction is:

1. **Random per-person UUID at enrollment.** Generate
   `person_uuid = randombytes(16)` once. Store the mapping
   `fnr ↔ person_uuid` in **one trusted broker**. Use the UUID
   everywhere else. This is not a hash of fnr — it is an
   independent identifier, with no function to invert.

2. **Pairwise per-relationship pseudonyms.**
   `pairwise_id = randombytes(16)` per (verifier, person) pair,
   recorded by the broker. Two verifiers cannot correlate even
   by colluding — they have no shared handle. Same construction
   as OIDC pairwise `sub` and Apple Sign-in's per-app
   subject identifier.

3. **The mapping table is the secret.** It lives in the broker
   only, never in the systems indexed by the UUIDs. The broker is
   protected as the keeper of the only sensitive linkage. Verifiers
   and the Data Wallet server see opaque UUIDs and can do nothing
   personally identifying with them in isolation.

This is functionally equivalent to "HMAC of fnr with a key that
never leaks", but without the false reassurance that the math
alone is doing the protective work. The mapping table is
explicitly the asset that needs guarding.

## Concrete checks if "let's hash the fnr" comes up again

When this proposal resurfaces — and it will — the questions that
expose the gap are:

1. **What is the entropy of the input?** If under ~80 bits of
   genuine unpredictability, hash-based protection is not
   meaningful against a motivated attacker.
2. **Is the secret needed at every lookup?** If yes, it is online,
   and "if the secret leaks" is a routine threat, not a remote
   one.
3. **Does the same person get the same handle across verifiers?**
   If yes, you have a global identifier, not a pseudonym.
4. **Can an attacker who knows the person's fnr verify their
   presence in the database?** If yes, the database leaks
   membership.
5. **What is the rotation story?** If rotating the scheme requires
   regenerating every handle, the answer in practice is "we
   never rotate", which means a single key compromise is forever.

If any of these answers are unsatisfactory, hashed-fnr is not the
mitigation it appears to be.

## The sharp point

Fødselsnummer has too little entropy for hashing to do meaningful
protective work. Any scheme that relies on the secrecy of a key
to make hashed-fnr safe is, in practice, a lookup table with extra
steps — and the table (or the key that defines it) is the asset
that must be protected. The honest design is to **stop treating
the identifier as something math can fix**, and instead build a
trusted broker that holds an explicit mapping from fnr to random
per-person and per-relationship UUIDs. The privacy properties then
come from how that mapping is operated, not from a hash function
applied to a known input space.

## See also

- [`per-install-mobile-issuers.md`](per-install-mobile-issuers.md)
  — verifier-initiated pull is the design where this question
  arises in the first place.
- [`../specs/plan.md`](../specs/plan.md) § Out of Scope —
  verifier-initiated pull is not in v1.
- [`../explanation/trust-model.md`](../explanation/trust-model.md)
  — the broader rationale for not concentrating trust in any
  single online component.
