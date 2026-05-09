# Intermediate bootstrap ceremony

**Audience:** operators standing up a production `datawallet-intermediate` instance.
**Goal:** generate an HSM-backed intermediate keypair inside GCP Cloud KMS, sign the
intermediate's directory record with the offline root quorum, publish it to the server,
and verify a full enroll → token → envelope round-trip.

Run this procedure once per deployment environment. Repeat it whenever you rotate
the intermediate signing key.

## Prerequisites

| Requirement | Notes |
|---|---|
| GCP project with Cloud KMS API enabled | The key ring and key are created in this step |
| Root quorum private keys available offline | Created at trust-bootstrap time by `gen-root` |
| Admin operator with mTLS access to `/v1/admin/**` on the server | Used in steps 3 and 5 |
| `datawallet-intermediate` JAR + `application.yml` staged for deployment | Built by `mvn -f intermediate/pom.xml package` |
| `gcloud` CLI authenticated | `gcloud auth application-default login` |

---

## Step 1 — Create the intermediate signing key in GCP Cloud KMS

```sh
# Create the key ring (once per region per project)
gcloud kms keyrings create datawallet-intermediate \
  --location us-central1

# Create an asymmetric Ed25519 signing key (HSM-backed)
gcloud kms keys create intermediate-signing \
  --keyring datawallet-intermediate \
  --location us-central1 \
  --purpose asymmetric-signing \
  --default-algorithm ec-sign-ed25519 \
  --protection-level hsm

# Note the full key version resource name — used in application.yml
gcloud kms keys versions list \
  --key intermediate-signing \
  --keyring datawallet-intermediate \
  --location us-central1
# Example output:
# NAME                                                                      STATE
# projects/my-proj/locations/us-central1/keyRings/datawallet-intermediate/
#   cryptoKeys/intermediate-signing/cryptoKeyVersions/1   ENABLED
```

Set `INTERMEDIATE_KMS_KEY_VERSION_NAME` in the deployment environment to the full
`cryptoKeyVersions/N` path above, and set `INTERMEDIATE_SIGNER_MODE=kms`.

```sh
# Verify the public key is reachable
gcloud kms keys versions get-public-key 1 \
  --key intermediate-signing \
  --keyring datawallet-intermediate \
  --location us-central1
```

---

## Step 2 — Export the intermediate public key

The intermediate service uses the public key embedded in its signed directory record.
Fetch it in raw-bytes form for the quorum ceremony:

```sh
# Fetch PEM-encoded SubjectPublicKeyInfo from KMS
gcloud kms keys versions get-public-key 1 \
  --key intermediate-signing \
  --keyring datawallet-intermediate \
  --location us-central1 \
  --output-file intermediate-pub.pem

# Extract the raw 32-byte Ed25519 public key (last 32 bytes of the DER)
openssl pkey -pubin -in intermediate-pub.pem -outform DER \
  | tail -c 32 \
  | xxd -p -c 32 > intermediate-pub.hex

echo "Intermediate public key (hex):"
cat intermediate-pub.hex
```

---

## Step 3 — Quorum ceremony: sign the intermediate directory record

Move `intermediate-pub.hex` to the offline quorum machine. Build a directory-record
JSON using the raw public key bytes, then sign it with the required threshold of root
private keys:

```sh
# Convert hex to base64url (no padding) for the JSON template
PUBKEY_B64URL=$(cat intermediate-pub.hex | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')

ISSUED_AT=$(date -u +%s%3N)          # UTC ms
VALID_FROM=$ISSUED_AT
VALID_UNTIL=$((ISSUED_AT + 31536000000))  # +1 year

cat > intermediate-record.json <<EOF
{
  "record_type": "intermediate",
  "subject_id": "$(uuidgen | tr '[:upper:]' '[:lower:]')",
  "public_key": "${PUBKEY_B64URL}",
  "valid_from": ${VALID_FROM},
  "valid_until": ${VALID_UNTIL},
  "issued_at": ${ISSUED_AT},
  "status": "active"
}
EOF

# Sign with the quorum CLI (requires threshold of root keys)
bin/cli.sh sign-directory \
  --root-priv root1.privkey.box \
  --root-priv root2.privkey.box \
  --pinned-root pinned-root.cbor \
  --in intermediate-record.json \
  --out intermediate-record.cbor

echo "Signed intermediate record: $(wc -c < intermediate-record.cbor) bytes"
```

Byte layout of the signed record is specified in
[`docs/specs/crypto-formats.md`](../specs/crypto-formats.md).

---

## Step 4 — Start the intermediate service with `mode=soft` to extract the key ID

Before publishing, you need the `key_id` (first 16 bytes of SHA-256 of the public key)
that `GcpKmsSignerPort` computes at startup. Start the service once with a soft key of
the same public-key material to obtain the key ID, or compute it directly:

```sh
# Compute key_id = first 16 bytes of SHA-256(public_key)
openssl pkey -pubin -in intermediate-pub.pem -outform DER \
  | tail -c 32 \
  | openssl dgst -sha256 -binary \
  | head -c 16 \
  | xxd -p
```

The `key_id` field in `intermediate-record.json` must match this value.
Update the JSON and re-sign if necessary.

---

## Step 5 — Publish the signed intermediate record to the server

Hand `intermediate-record.cbor` to an admin operator. The operator publishes it
using admin mTLS:

```sh
curl --cert admin.crt --key admin.key \
     --data-binary @intermediate-record.cbor \
     -H 'Content-Type: application/cbor' \
     https://wallet.example.com/v1/admin/directory
# Expect: 201 Created
```

---

## Step 6 — Deploy and start the intermediate service

Set the following environment variables before starting:

| Variable | Value |
|---|---|
| `INTERMEDIATE_SIGNER_MODE` | `kms` |
| `INTERMEDIATE_KMS_KEY_VERSION_NAME` | Full `cryptoKeyVersions/N` resource name from step 1 |
| `DATAWALLET_SERVER_URL` | Production server base URL |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account key JSON (or use Workload Identity) |

```sh
java -jar datawallet-intermediate.jar \
  --spring.profiles.active=mobile

# Health check
curl https://intermediate.example.com/healthz
# Expect: {"status":"UP"}
```

The service account running the intermediate needs the KMS role:
- `roles/cloudkms.signerVerifier` on the `intermediate-signing` key

---

## Step 7 — Smoke test: enroll → token → envelope

```sh
# 1. Generate a test install keypair
openssl genpkey -algorithm ed25519 -out test-install.key
openssl pkey -in test-install.key -pubout -outform DER \
  | tail -c 32 \
  | base64 -w0 | tr '+/' '-_' | tr -d '=' > test-install-pub.b64url

INSTALL_UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')

# 2. Enroll
curl -s -X POST https://intermediate.example.com/enroll \
  -H 'Content-Type: application/json' \
  -d "{
    \"install_uuid\": \"${INSTALL_UUID}\",
    \"pubkey\": \"$(cat test-install-pub.b64url)\",
    \"attestation_token\": \"stub\"
  }" | tee enroll-response.json

# 3. Produce PoP signature
SIGNED_RECORD=$(jq -r .signed_record enroll-response.json)
PoP_SIG=$(echo -n "datawallet-token-pop" \
  | openssl pkeyutl -sign -inkey test-install.key -rawin \
  | base64 -w0 | tr '+/' '-_' | tr -d '=')

# 4. Mint bearer token
curl -s -X POST https://intermediate.example.com/token \
  -H 'Content-Type: application/json' \
  -d "{
    \"signed_directory_record\": \"${SIGNED_RECORD}\",
    \"pop_signature\": \"${PoP_SIG}\",
    \"attestation_token\": \"stub\"
  }" | tee token-response.json

BEARER=$(jq -r .bearer token-response.json)
echo "Bearer token obtained: ${#BEARER} chars"

# 5. Post a test envelope via the server (requires a registered verifier)
# See docs/tutorials/first-share.md for the full envelope format.
curl -s -X POST https://wallet.example.com/v1/entries \
  -H "Authorization: Bearer ${BEARER}" \
  -H 'Content-Type: application/cbor' \
  --data-binary @test-envelope.cbor
# Expect: 201 Created
```

If step 2 returns 403 with `attestation_failed`, confirm
`datawallet.intermediate.attestation.mode=stub` is set (or deploy a real
attestation backend for production).

---

## Rotation

To rotate the intermediate signing key:

1. Create a new key version in KMS (step 1).
2. Run the quorum ceremony with the new public key (steps 2–4).
3. Publish the new record to the server (step 5) — the server keeps both records.
4. Update `INTERMEDIATE_KMS_KEY_VERSION_NAME` and redeploy the intermediate.
5. Old tokens signed by the previous key expire within 5 minutes (`exp` claim).
6. Optionally disable the old key version in KMS once all active tokens have expired.

---

## Rate limit thresholds (production baselines)

These match the defaults in `application.yml`. Tune based on observed traffic.

| Endpoint | Limit |
|---|---|
| `POST /enroll` | 5 burst, 10 req/min per IP |
| `POST /token` | 20 burst, 60 req/min per IP |

Per-install enrollment quota (1 enroll per `install_uuid` for life) is enforced
by `EnrollService` idempotency — returning the existing record on retry.
Key rotation re-enrolls by first revoking the old record via `POST /revoke`,
then calling `POST /enroll` with the new public key.

To override for a specific environment, set in the profile YAML:

```yaml
datawallet:
  intermediate:
    ratelimit:
      enroll:
        per-ip-capacity: 10
        per-ip-refill-per-minute: 20
      token:
        per-ip-capacity: 30
        per-ip-refill-per-minute: 120
```

---

## Alerting and dashboards

Alert rules are defined in Prometheus alerting-rules format at
[`deploy/alerts/intermediate-alerts.yml`](../../deploy/alerts/intermediate-alerts.yml).

### Required Prometheus scrape config

```yaml
scrape_configs:
  - job_name: datawallet-intermediate
    static_configs:
      - targets: ['intermediate.example.com:8444']
    metrics_path: /actuator/prometheus
```

### Grafana dashboard layout

Create a dashboard named **Datawallet Intermediate** with the following panels
(all queries are PromQL against the `datawallet_intermediate` job):

| Panel | Query | Threshold |
|---|---|---|
| Enroll rate | `rate(enroll_results_total[5m])` by `result` | — |
| Enroll publish failures | `rate(enroll_results_total{result="publish_failed"}[5m])` | page > 0.1/min |
| Token mint rate | `rate(token_results_total[5m])` by `result` | — |
| Attestation reject ratio | `rate(attestation_results_total{result="rejected"}[5m]) / rate(attestation_results_total[5m])` | page > 5% for 10 min |
| Deny-list age | `denylist_age_seconds` | page > `max-staleness-seconds` |
| Deny-list refresh failures | `rate(denylist_refresh_failures_total[1h])` | page > 3/hr |
| Deny-list size | `denylist_size` | — |

All metric names come from `MetricsConfig` (step 04 observability surface).
