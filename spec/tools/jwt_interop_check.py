#!/usr/bin/env python3
"""
Verifies that JWT bearer tokens minted by the Java test intermediate
conform to RFC 7519 / RFC 8037 (EdDSA).

Reads a fixture JWT from spec/fixtures/bearer/test-bearer.jwt,
verifies it against the intermediate's public key from
spec/fixtures/bearer/intermediate-pubkey.bin, and asserts
structural conformance.

If the fixture files don't exist yet (pre-integration-test), exits 0
with a message. This lets the script be wired into test-all.sh
without blocking until the IT phase produces the fixture.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    import nacl.signing
except ImportError:
    print("SKIP: pynacl not installed; install via 'pip install pynacl'")
    sys.exit(0)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "bearer"
JWT_PATH = FIXTURES_DIR / "test-bearer.jwt"
PUBKEY_PATH = FIXTURES_DIR / "intermediate-pubkey.bin"


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def main():
    if not JWT_PATH.exists() or not PUBKEY_PATH.exists():
        print(f"SKIP: bearer fixture not yet generated ({JWT_PATH})")
        sys.exit(0)

    jwt_str = JWT_PATH.read_text().strip()
    pubkey_bytes = PUBKEY_PATH.read_bytes()

    parts = jwt_str.split(".")
    assert len(parts) == 3, f"Expected 3 JWT segments, got {len(parts)}"

    header_bytes = b64url_decode(parts[0])
    payload_bytes = b64url_decode(parts[1])
    sig_bytes = b64url_decode(parts[2])

    header = json.loads(header_bytes)
    payload = json.loads(payload_bytes)

    # RFC 8037: alg must be EdDSA
    assert header.get("alg") == "EdDSA", f"Expected alg=EdDSA, got {header.get('alg')}"

    # RFC 7519: typ should be JWT when present
    if "typ" in header:
        assert header["typ"] == "JWT", f"Expected typ=JWT, got {header['typ']}"

    # Required claims
    assert "iss" in payload, "Missing iss claim"
    assert "aud" in payload, "Missing aud claim"
    assert "exp" in payload, "Missing exp claim"
    assert "iat" in payload, "Missing iat claim"
    assert isinstance(payload["iss"], str), "iss must be a string"
    assert isinstance(payload["aud"], str), "aud must be a string"
    assert isinstance(payload["exp"], int), "exp must be an integer"
    assert isinstance(payload["iat"], int), "iat must be an integer"

    # cnf.jkt (RFC 7800 confirmation claim with JWK thumbprint)
    assert "cnf" in payload, "Missing cnf claim"
    assert "jkt" in payload["cnf"], "Missing cnf.jkt"
    assert isinstance(payload["cnf"]["jkt"], str), "cnf.jkt must be a string"

    # iss prefix
    assert payload["iss"].startswith("urn:datawallet:issuer:"), \
        f"iss must start with urn:datawallet:issuer:, got {payload['iss']}"

    # Lifetime <= 5 minutes
    lifetime = payload["exp"] - payload["iat"]
    assert lifetime <= 300, f"Lifetime {lifetime}s exceeds 5 minutes"

    # Signature length (Ed25519 = 64 bytes)
    assert len(sig_bytes) == 64, f"Expected 64-byte Ed25519 signature, got {len(sig_bytes)}"

    # Verify signature via pynacl
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    verify_key = nacl.signing.VerifyKey(pubkey_bytes)
    try:
        verify_key.verify(signing_input, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        print("FAIL: Ed25519 signature verification failed")
        sys.exit(1)

    # Verify cnf.jkt matches the JWK thumbprint of the signing key from the install
    # (We can't verify the install key binding without the install pubkey fixture,
    #  so we just validate the structural conformance here)

    print(f"OK: JWT interop check passed")
    print(f"  alg={header['alg']}, iss={payload['iss']}")
    print(f"  lifetime={lifetime}s, sig_len={len(sig_bytes)}")
    sys.exit(0)


if __name__ == "__main__":
    main()
