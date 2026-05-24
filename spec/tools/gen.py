#!/usr/bin/env python3
"""
Fixture generator for Data Wallet cross-stack contract tests.

Uses only pynacl for crypto and cbor2 (canonical=True) for CBOR.
This is the third reference implementation (Python), independent of
Java and Dart stacks.

Usage:
    python spec/tools/gen.py          # regenerate all fixtures
    python spec/tools/gen.py --check  # compare against committed fixtures
"""

import os
import sys
from pathlib import Path

_VENV_DIR = Path(__file__).resolve().parent / ".venv"
_VENV_PYTHON = _VENV_DIR / "bin" / "python3"
if _VENV_PYTHON.exists() and not any(str(_VENV_DIR) in p for p in sys.path):
    os.execv(str(_VENV_PYTHON), [str(_VENV_PYTHON)] + sys.argv)

import argparse
import hashlib
import json
import struct
import tempfile
import unicodedata

import cbor2
import nacl.bindings
import nacl.signing
import nacl.public
import nacl.secret
import nacl.utils

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
AUTH_PREFIX = b"datawallet-auth-v1\x00"
AUDIT_GENESIS_SEED = b"datawallet-audit-genesis-v1\x00"


def ed25519_sign_detached(message: bytes, private_key_64: bytes) -> bytes:
    seed = private_key_64[:32]
    sk = nacl.signing.SigningKey(seed)
    signed = sk.sign(message)
    return signed.signature


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_cbor(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def load_input(name: str):
    with open(FIXTURES_DIR / "inputs" / name) as f:
        return json.load(f)


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# ── Keypair derivation ──────────────────────────────────────────────

def derive_keypairs(keypairs_input: dict) -> dict:
    result = {}
    for name, info in keypairs_input.items():
        seed = hex_to_bytes(info["seed_hex"])
        assert len(seed) == 32, f"seed for {name} must be 32 bytes"
        ktype = info["type"]
        if ktype == "ed25519":
            pub, priv = nacl.bindings.crypto_sign_seed_keypair(seed)
            result[name] = {"type": ktype, "seed": seed, "public": pub, "private": priv}
        elif ktype == "x25519":
            pub, priv = nacl.bindings.crypto_box_seed_keypair(seed)
            result[name] = {"type": ktype, "seed": seed, "public": pub, "private": priv}
        else:
            raise ValueError(f"Unknown key type: {ktype}")
    return result


def write_keypairs_expected(keys: dict, out_dir: Path):
    expected = {}
    for name, k in keys.items():
        expected[name] = {
            "type": k["type"],
            "public_key_hex": bytes_to_hex(k["public"]),
        }
    write_json(out_dir / "inputs" / "keypairs.expected.json", expected)


# ── UUIDv7 ──────────────────────────────────────────────────────────

def make_uuidv7(ts_ms: int, rand_hex: str) -> bytes:
    rand_bytes = hex_to_bytes(rand_hex)
    assert len(rand_bytes) == 12, "rand must be 12 bytes (2 rand_a + 8 rand_b + 2 spare)"
    rand_a = rand_bytes[0:2]
    rand_b = rand_bytes[2:10]
    uuid_bytes = bytearray(16)
    ts_bytes = struct.pack(">Q", ts_ms)
    uuid_bytes[0:6] = ts_bytes[2:8]
    uuid_bytes[6] = 0x70 | (rand_a[0] & 0x0F)
    uuid_bytes[7] = rand_a[1]
    uuid_bytes[8] = 0x80 | (rand_b[0] & 0x3F)
    uuid_bytes[9:16] = rand_b[1:8]
    return bytes(uuid_bytes)


# ── KEK derivation ──────────────────────────────────────────────────

def derive_kek(password: str, salt: bytes, m: int, t: int, p: int) -> bytes:
    pw_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    return nacl.bindings.crypto_pwhash_alg(
        outlen=32,
        passwd=pw_bytes,
        salt=salt,
        opslimit=t,
        memlimit=m,
        alg=nacl.bindings.crypto_pwhash_ALG_ARGON2ID13,
    )


# ── Wrapped private key blob ────────────────────────────────────────

def wrap_private_key(kek: bytes, nonce: bytes, plaintext_key: bytes) -> bytes:
    ct = nacl.bindings.crypto_secretbox(plaintext_key, nonce, kek)
    blob = {
        "v": 1,
        "alg": "secretbox",
        "nonce": nonce,
        "ct": ct,
    }
    return canonical_cbor(blob)


# ── Auth challenge ──────────────────────────────────────────────────

def sign_auth_challenge(auth_priv: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    challenge = AUTH_PREFIX + nonce
    sig_detached = ed25519_sign_detached(challenge, auth_priv)
    return challenge, sig_detached


# ── Envelope building ───────────────────────────────────────────────

def build_envelope(
    *,
    version: int,
    entry_id: bytes,
    issuer_id: bytes,
    issuer_label: str,
    issuer_signing_key_id: bytes,
    created_at: int,
    description: str,
    ciphertext_alg: str,
    ciphertext_nonce: bytes,
    ciphertext: bytes,
    ciphertext_hash: bytes,
    recipient_wrappings: list[dict],
    signing_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    envelope_map = {
        "version": version,
        "entry_id": entry_id,
        "issuer_id": issuer_id,
        "issuer_label": issuer_label,
        "issuer_signing_key_id": issuer_signing_key_id,
        "created_at": created_at,
        "description": description,
        "ciphertext_alg": ciphertext_alg,
        "ciphertext_nonce": ciphertext_nonce,
        "ciphertext": ciphertext,
        "ciphertext_hash": ciphertext_hash,
        "recipient_wrappings": recipient_wrappings,
    }
    signed_bytes = canonical_cbor(envelope_map)
    signature = ed25519_sign_detached(signed_bytes, signing_key)
    envelope_map["signature"] = signature
    final_bytes = canonical_cbor(envelope_map)
    return final_bytes, signed_bytes, signature


def encrypt_plaintext(plaintext: str, data_key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    pt_bytes = plaintext.encode("utf-8")
    ct = nacl.bindings.crypto_secretbox(pt_bytes, nonce, data_key)
    ct_hash = sha256(ct)
    return ct, ct_hash


def crypto_box_seal_deterministic(message: bytes, recipient_pub: bytes, ephemeral_seed: bytes) -> bytes:
    eph_pub, eph_priv = nacl.bindings.crypto_box_seed_keypair(ephemeral_seed)
    nonce = nacl.bindings.crypto_generichash_blake2b_salt_personal(eph_pub + recipient_pub, digest_size=24)
    ct = nacl.bindings.crypto_box_easy(message, nonce, recipient_pub, eph_priv)
    return eph_pub + ct


def wrap_data_key_for_recipient(data_key: bytes, recipient_enc_pub: bytes, ephemeral_seed: bytes) -> bytes:
    return crypto_box_seal_deterministic(data_key, recipient_enc_pub, ephemeral_seed)


# ── Directory records ───────────────────────────────────────────────

def build_directory_record(
    *,
    version: int,
    record_type: str,
    subject_id: bytes,
    key_id: bytes,
    public_key: bytes,
    key_use: str,
    status: str,
    valid_from: int,
    valid_until: int,
    issued_at: int,
    root_keys: list[dict],
    threshold: int,
) -> bytes:
    record_map = {
        "version": version,
        "record_type": record_type,
        "subject_id": subject_id,
        "key_id": key_id,
        "public_key": public_key,
        "key_use": key_use,
        "status": status,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "issued_at": issued_at,
    }
    signed_bytes = canonical_cbor(record_map)
    root_sigs = []
    for rk in root_keys[:threshold]:
        sig = ed25519_sign_detached(signed_bytes, rk["private"])
        root_sigs.append({
            "root_key_id": rk["key_id"],
            "signature": sig,
        })
    record_map["root_signatures"] = root_sigs
    return canonical_cbor(record_map)


def build_directory_record_parent_signed(
    *,
    version: int,
    record_type: str,
    subject_id: bytes,
    key_id: bytes,
    public_key: bytes,
    key_use: str,
    status: str,
    valid_from: int,
    valid_until: int,
    issued_at: int,
    parent_key_id: bytes,
    parent_private_key: bytes,
) -> bytes:
    """Builds a directory record signed by a parent intermediate key.

    signed_bytes = canonical_cbor(base_fields + parent_key_id)
    parent_signature = ed25519_sign(parent_private_key, signed_bytes)
    """
    record_map = {
        "version": version,
        "record_type": record_type,
        "subject_id": subject_id,
        "key_id": key_id,
        "public_key": public_key,
        "key_use": key_use,
        "status": status,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "issued_at": issued_at,
        "parent_key_id": parent_key_id,   # included in signed bytes
    }
    signed_bytes = canonical_cbor(record_map)
    parent_sig = ed25519_sign_detached(signed_bytes, parent_private_key)
    record_map["parent_signature"] = parent_sig
    return canonical_cbor(record_map)


def build_pinned_root(root_keys: list[dict], timestamps: dict) -> bytes:
    roots = []
    for rk in root_keys:
        roots.append({
            "root_key_id": rk["key_id"],
            "public_key": rk["public"],
            "valid_from": timestamps["t_directory_valid_from"],
            "valid_until": timestamps["t_directory_valid_until"],
        })
    pinned = {
        "version": 1,
        "scheme": "ed25519-quorum-v1",
        "threshold": 2,
        "roots": roots,
    }
    return canonical_cbor(pinned)


# ── Fingerprint ─────────────────────────────────────────────────────

def compute_fingerprint(public_key: bytes) -> str:
    import base64
    fp_bytes = sha256(public_key)[:10]
    b32 = base64encode_base32(fp_bytes)
    return f"{b32[0:4]}-{b32[4:8]}-{b32[8:12]}-{b32[12:16]}"


def base64encode_base32(data: bytes) -> str:
    import base64
    return base64.b32encode(data).decode("ascii").rstrip("=")


# ── Audit chain ─────────────────────────────────────────────────────

def audit_genesis_prev_hash() -> bytes:
    return sha256(AUDIT_GENESIS_SEED)


def audit_chain_hash(prev_hash: bytes, event_cbor: bytes) -> bytes:
    return sha256(prev_hash + event_cbor)


# ── File I/O helpers ────────────────────────────────────────────────

def write_binary(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_json(path: Path, obj, indent=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="\n") as f:
        json.dump(obj, f, indent=indent, ensure_ascii=False)
        f.write("\n")


def envelope_to_json_sidecar(envelope_map: dict) -> dict:
    result = {}
    for k, v in envelope_map.items():
        if isinstance(v, bytes):
            result[k] = bytes_to_hex(v)
        elif isinstance(v, list):
            items = []
            for item in v:
                if isinstance(item, dict):
                    items.append({ik: bytes_to_hex(iv) if isinstance(iv, bytes) else iv for ik, iv in item.items()})
                else:
                    items.append(item)
            result[k] = items
        else:
            result[k] = v
    return result


# ── Main generation ─────────────────────────────────────────────────

def generate(out_dir: Path):
    keypairs_input = load_input("keypairs.json")
    passwords_input = load_input("passwords.json")
    timestamps = load_input("timestamps.json")
    uuids_input = load_input("uuids.json")
    plaintexts = load_input("plaintexts.json")

    keys = derive_keypairs(keypairs_input)
    write_keypairs_expected(keys, out_dir)

    manifest_entries = []

    def track(rel_path: str, category: str, description: str):
        full = out_dir / rel_path
        h = sha256_hex(full.read_bytes())
        manifest_entries.append({
            "path": rel_path,
            "sha256": h,
            "category": category,
            "description": description,
        })

    # Track input files
    for inp in ["inputs/keypairs.json", "inputs/passwords.json", "inputs/handles.json",
                "inputs/timestamps.json", "inputs/uuids.json", "inputs/plaintexts.json"]:
        track(inp, "input", f"Input file: {inp}")

    # ── UUIDs ────────────────────────────────────────────────────────
    uuid_results = []
    for entry in uuids_input:
        uuid_bytes = make_uuidv7(entry["ts_ms"], entry["rand_hex"])
        uuid_results.append({
            "name": entry["name"],
            "ts_ms": entry["ts_ms"],
            "rand_hex": entry["rand_hex"],
            "expected_hex": bytes_to_hex(uuid_bytes),
        })
    # Enrich uuids input with expected values - written as a generated output
    write_json(out_dir / "inputs" / "uuids.expected.json", uuid_results)

    # Build UUID lookup
    uuid_map = {u["name"]: hex_to_bytes(u["expected_hex"]) for u in uuid_results}

    # ── KEK derivation (passwords) ──────────────────────────────────
    password_results = []
    kek_map = {}
    for pw_entry in passwords_input:
        salt = hex_to_bytes(pw_entry["kdf_salt_hex"])
        params = pw_entry["kdf_params"]
        kek = derive_kek(pw_entry["password"], salt, params["m"], params["t"], params["p"])
        kek_map[pw_entry["name"]] = kek
        password_results.append({
            "name": pw_entry["name"],
            "password": pw_entry["password"],
            "kdf_salt_hex": pw_entry["kdf_salt_hex"],
            "kdf_params": params,
            "expected_kek_hex": bytes_to_hex(kek),
        })
    write_json(out_dir / "inputs" / "passwords.expected.json", password_results)

    # ── Wrapped blobs ───────────────────────────────────────────────
    # Fixed nonces for deterministic wrapping
    wrap_nonces = {
        "enc_priv_alice": hex_to_bytes("f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"),
        "auth_priv_alice": hex_to_bytes("f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2"),
        "enc_priv_bob": hex_to_bytes("f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3"),
        "auth_priv_bob": hex_to_bytes("f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4"),
    }

    wrapped_blobs = {
        "enc_priv_alice": (kek_map["alice_native"], wrap_nonces["enc_priv_alice"], keys["alice_enc"]["private"]),
        "auth_priv_alice": (kek_map["alice_native"], wrap_nonces["auth_priv_alice"], keys["alice_auth"]["private"]),
        "enc_priv_bob": (kek_map["bob_native"], wrap_nonces["enc_priv_bob"], keys["bob_enc"]["private"]),
        "auth_priv_bob": (kek_map["bob_native"], wrap_nonces["auth_priv_bob"], keys["bob_auth"]["private"]),
    }

    wrap_meta = []
    for blob_name, (kek, nonce, priv_key) in wrapped_blobs.items():
        cbor_bytes = wrap_private_key(kek, nonce, priv_key)
        out_path = out_dir / "wrapped" / f"{blob_name}.cbor"
        write_binary(out_path, cbor_bytes)
        track(f"wrapped/{blob_name}.cbor", "wrapped", f"Wrapped private key: {blob_name}")
        wrap_meta.append({
            "name": blob_name,
            "nonce_hex": bytes_to_hex(nonce),
            "plaintext_key_len": len(priv_key),
        })
    write_json(out_dir / "wrapped" / "wrap_meta.json", wrap_meta)
    track("wrapped/wrap_meta.json", "wrapped", "Wrap metadata sidecar")

    # ── Key IDs (deterministic from public key) ─────────────────────
    # sha256(public_key)[:16] — matches DirectoryRecordSigner.computeKeyId
    def key_id_from_public_key(public_key: bytes) -> bytes:
        return sha256(public_key)[:16]

    key_ids = {name: key_id_from_public_key(k["public"]) for name, k in keys.items()}

    # Issuer ID from acme_sign uuid
    issuer_id = uuid_map["issuer_acme"]

    # Verifier IDs: use deterministic UUIDs based on key name hashes
    alice_verifier_id = sha256(b"alice-verifier-id")[:16]
    bob_verifier_id = sha256(b"bob-verifier-id")[:16]
    charlie_verifier_id = sha256(b"charlie-verifier-id")[:16]

    # ── Auth challenge ──────────────────────────────────────────────
    auth_nonce = hex_to_bytes("aa" * 32)
    challenge_bytes, auth_sig = sign_auth_challenge(keys["alice_auth"]["private"], auth_nonce)
    auth_data = {
        "nonce_hex": bytes_to_hex(auth_nonce),
        "prefix_hex": bytes_to_hex(AUTH_PREFIX),
        "expected_signed_bytes_hex": bytes_to_hex(challenge_bytes),
        "signer": "alice_auth",
        "signer_public_key_hex": bytes_to_hex(keys["alice_auth"]["public"]),
        "expected_sig_hex": bytes_to_hex(auth_sig),
    }
    write_json(out_dir / "auth" / "nonce-and-signature.json", auth_data)
    track("auth/nonce-and-signature.json", "auth", "Auth challenge signature vector")

    write_binary(out_dir / "auth" / "prefix.txt", AUTH_PREFIX)
    track("auth/prefix.txt", "auth", "Auth prefix literal bytes")

    # ── Envelopes ───────────────────────────────────────────────────

    # Fixed data keys and nonces for deterministic envelope generation
    data_key_basic = hex_to_bytes("dd" * 32)
    ct_nonce_basic = hex_to_bytes("ee" * 24)
    data_key_three = hex_to_bytes("d1" * 32)
    ct_nonce_three = hex_to_bytes("e1" * 24)
    data_key_v2 = hex_to_bytes("d2" * 32)
    ct_nonce_v2 = hex_to_bytes("e2" * 24)
    data_key_unicode = hex_to_bytes("d3" * 32)
    ct_nonce_unicode = hex_to_bytes("e3" * 24)

    # Deterministic ephemeral seeds for crypto_box_seal wrappings
    eph_seeds = {
        "basic_alice": hex_to_bytes("b1" * 32),
        "three_alice": hex_to_bytes("b2" * 32),
        "three_bob": hex_to_bytes("b3" * 32),
        "three_charlie": hex_to_bytes("b4" * 32),
        "v2_alice": hex_to_bytes("b5" * 32),
        "v2_bob": hex_to_bytes("b6" * 32),
        "unicode_alice": hex_to_bytes("b7" * 32),
    }

    # basic-1-recipient: alice only
    ct_basic, ct_hash_basic = encrypt_plaintext(plaintexts["basic"], data_key_basic, ct_nonce_basic)
    wrapped_dk_alice = wrap_data_key_for_recipient(data_key_basic, keys["alice_enc"]["public"], eph_seeds["basic_alice"])
    basic_wrappings = [{
        "verifier_id": alice_verifier_id,
        "verifier_key_id": key_ids["alice_enc"],
        "wrapped_data_key": wrapped_dk_alice,
    }]
    basic_final, basic_signed, basic_sig = build_envelope(
        version=1,
        entry_id=uuid_map["entry_basic"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_envelope_basic"],
        description="Basic test credential",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_basic,
        ciphertext=ct_basic,
        ciphertext_hash=ct_hash_basic,
        recipient_wrappings=basic_wrappings,
        signing_key=keys["acme_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "basic-1-recipient.cbor", basic_final)
    write_binary(out_dir / "envelopes" / "basic-1-recipient.signed", basic_signed)
    basic_envelope_map = cbor2.loads(basic_final)
    write_json(out_dir / "envelopes" / "basic-1-recipient.json", envelope_to_json_sidecar(basic_envelope_map))
    track("envelopes/basic-1-recipient.cbor", "envelope", "Valid envelope: single recipient (alice)")
    track("envelopes/basic-1-recipient.signed", "envelope", "Signed bytes for basic-1-recipient")
    track("envelopes/basic-1-recipient.json", "envelope", "JSON sidecar for basic-1-recipient")

    # three-recipients: alice, bob, charlie
    ct_three, ct_hash_three = encrypt_plaintext(plaintexts["three_recipients"], data_key_three, ct_nonce_three)
    three_wrappings = [
        {
            "verifier_id": alice_verifier_id,
            "verifier_key_id": key_ids["alice_enc"],
            "wrapped_data_key": wrap_data_key_for_recipient(data_key_three, keys["alice_enc"]["public"], eph_seeds["three_alice"]),
        },
        {
            "verifier_id": bob_verifier_id,
            "verifier_key_id": key_ids["bob_enc"],
            "wrapped_data_key": wrap_data_key_for_recipient(data_key_three, keys["bob_enc"]["public"], eph_seeds["three_bob"]),
        },
        {
            "verifier_id": charlie_verifier_id,
            "verifier_key_id": key_ids["charlie_enc"],
            "wrapped_data_key": wrap_data_key_for_recipient(data_key_three, keys["charlie_enc"]["public"], eph_seeds["three_charlie"]),
        },
    ]
    three_final, three_signed, _ = build_envelope(
        version=1,
        entry_id=uuid_map["entry_basic"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_envelope_basic"],
        description="Three recipients test",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_three,
        ciphertext=ct_three,
        ciphertext_hash=ct_hash_three,
        recipient_wrappings=three_wrappings,
        signing_key=keys["acme_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "three-recipients.cbor", three_final)
    write_binary(out_dir / "envelopes" / "three-recipients.signed", three_signed)
    three_envelope_map = cbor2.loads(three_final)
    write_json(out_dir / "envelopes" / "three-recipients.json", envelope_to_json_sidecar(three_envelope_map))
    track("envelopes/three-recipients.cbor", "envelope", "Valid envelope: three recipients")
    track("envelopes/three-recipients.signed", "envelope", "Signed bytes for three-recipients")
    track("envelopes/three-recipients.json", "envelope", "JSON sidecar for three-recipients")

    # allow-list-update-v2: same entry_id, new version, updated content
    ct_v2, ct_hash_v2 = encrypt_plaintext(plaintexts["v2_update"], data_key_v2, ct_nonce_v2)
    v2_wrappings = [
        {
            "verifier_id": alice_verifier_id,
            "verifier_key_id": key_ids["alice_enc"],
            "wrapped_data_key": wrap_data_key_for_recipient(data_key_v2, keys["alice_enc"]["public"], eph_seeds["v2_alice"]),
        },
        {
            "verifier_id": bob_verifier_id,
            "verifier_key_id": key_ids["bob_enc"],
            "wrapped_data_key": wrap_data_key_for_recipient(data_key_v2, keys["bob_enc"]["public"], eph_seeds["v2_bob"]),
        },
    ]
    v2_final, v2_signed, _ = build_envelope(
        version=1,
        entry_id=uuid_map["entry_v2"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_envelope_v2"],
        description="Allow-list update v2",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_v2,
        ciphertext=ct_v2,
        ciphertext_hash=ct_hash_v2,
        recipient_wrappings=v2_wrappings,
        signing_key=keys["acme_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "allow-list-update-v2.cbor", v2_final)
    write_binary(out_dir / "envelopes" / "allow-list-update-v2.signed", v2_signed)
    v2_envelope_map = cbor2.loads(v2_final)
    write_json(out_dir / "envelopes" / "allow-list-update-v2.json", envelope_to_json_sidecar(v2_envelope_map))
    track("envelopes/allow-list-update-v2.cbor", "envelope", "Valid envelope: allow-list update v2")
    track("envelopes/allow-list-update-v2.signed", "envelope", "Signed bytes for allow-list-update-v2")
    track("envelopes/allow-list-update-v2.json", "envelope", "JSON sidecar for allow-list-update-v2")

    # unicode-description
    ct_uni, ct_hash_uni = encrypt_plaintext(plaintexts["unicode"], data_key_unicode, ct_nonce_unicode)
    uni_wrappings = [{
        "verifier_id": alice_verifier_id,
        "verifier_key_id": key_ids["alice_enc"],
        "wrapped_data_key": wrap_data_key_for_recipient(data_key_unicode, keys["alice_enc"]["public"], eph_seeds["unicode_alice"]),
    }]
    unicode_desc = unicodedata.normalize("NFC", "Cr\u00e9dential avec des caract\u00e8res sp\u00e9ciaux")
    uni_final, uni_signed, _ = build_envelope(
        version=1,
        entry_id=uuid_map["entry_basic"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_envelope_basic"],
        description=unicode_desc,
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_unicode,
        ciphertext=ct_uni,
        ciphertext_hash=ct_hash_uni,
        recipient_wrappings=uni_wrappings,
        signing_key=keys["acme_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "unicode-description.cbor", uni_final)
    write_binary(out_dir / "envelopes" / "unicode-description.signed", uni_signed)
    uni_envelope_map = cbor2.loads(uni_final)
    write_json(out_dir / "envelopes" / "unicode-description.json", envelope_to_json_sidecar(uni_envelope_map))
    track("envelopes/unicode-description.cbor", "envelope", "Valid envelope: unicode description")
    track("envelopes/unicode-description.signed", "envelope", "Signed bytes for unicode-description")
    track("envelopes/unicode-description.json", "envelope", "JSON sidecar for unicode-description")

    # ── Invalid envelopes ───────────────────────────────────────────

    # tampered-ciphertext: flip a byte in ciphertext
    tampered_ct = bytearray(ct_basic)
    tampered_ct[0] ^= 0xFF
    tampered_ct = bytes(tampered_ct)
    tampered_map = dict(basic_envelope_map)
    tampered_map["ciphertext"] = tampered_ct
    write_binary(out_dir / "envelopes" / "invalid" / "tampered-ciphertext.cbor", canonical_cbor(tampered_map))
    track("envelopes/invalid/tampered-ciphertext.cbor", "envelope-invalid", "Tampered ciphertext: hash mismatch")

    # wrong-issuer-key: sign with wrong key
    wrong_final, _, _ = build_envelope(
        version=1,
        entry_id=uuid_map["entry_basic"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_envelope_basic"],
        description="Wrong issuer key",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_basic,
        ciphertext=ct_basic,
        ciphertext_hash=ct_hash_basic,
        recipient_wrappings=basic_wrappings,
        signing_key=keys["wrong_issuer"]["private"],
    )
    write_binary(out_dir / "envelopes" / "invalid" / "wrong-issuer-key.cbor", wrong_final)
    track("envelopes/invalid/wrong-issuer-key.cbor", "envelope-invalid", "Wrong issuer signing key")

    # non-canonical-cbor: manually construct non-canonical encoding
    # Use indefinite-length map encoding (0xBF ... 0xFF) which is non-canonical
    non_canonical = bytearray(basic_final)
    # Change the first byte from definite-length map to indefinite-length map
    # A canonical CBOR map starts with 0xAD (map of 13 items); non-canonical uses 0xBF (indefinite map)
    # We just flip the first byte to make it non-canonical
    if non_canonical[0] & 0xE0 == 0xA0:
        non_canonical[0] = 0xBF
        non_canonical.append(0xFF)
    write_binary(out_dir / "envelopes" / "invalid" / "non-canonical-cbor.cbor", bytes(non_canonical))
    track("envelopes/invalid/non-canonical-cbor.cbor", "envelope-invalid", "Non-canonical CBOR encoding")

    # future-version: version=2
    future_final, _, _ = build_envelope(
        version=2,
        entry_id=uuid_map["entry_basic"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_envelope_basic"],
        description="Future version",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_basic,
        ciphertext=ct_basic,
        ciphertext_hash=ct_hash_basic,
        recipient_wrappings=basic_wrappings,
        signing_key=keys["acme_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "invalid" / "future-version.cbor", future_final)
    track("envelopes/invalid/future-version.cbor", "envelope-invalid", "Future version (version=2)")

    # stale-key-id: created_at outside valid_from..valid_until
    stale_final, _, _ = build_envelope(
        version=1,
        entry_id=uuid_map["entry_basic"],
        issuer_id=issuer_id,
        issuer_label="Acme Corp",
        issuer_signing_key_id=key_ids["acme_sign"],
        created_at=timestamps["t_stale_created_at"],
        description="Stale key id",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_basic,
        ciphertext=ct_basic,
        ciphertext_hash=ct_hash_basic,
        recipient_wrappings=basic_wrappings,
        signing_key=keys["acme_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "invalid" / "stale-key-id.cbor", stale_final)
    track("envelopes/invalid/stale-key-id.cbor", "envelope-invalid", "created_at outside valid_from..valid_until")

    # ── Directory records ───────────────────────────────────────────

    root_keys_list = [
        {"key_id": key_ids["root_a"], "public": keys["root_a"]["public"], "private": keys["root_a"]["private"]},
        {"key_id": key_ids["root_b"], "public": keys["root_b"]["public"], "private": keys["root_b"]["private"]},
        {"key_id": key_ids["root_c"], "public": keys["root_c"]["public"], "private": keys["root_c"]["private"]},
    ]

    # Pinned root
    pinned_root_cbor = build_pinned_root(root_keys_list, timestamps)
    write_binary(out_dir / "directory" / "pinned-root.cbor", pinned_root_cbor)
    track("directory/pinned-root.cbor", "directory", "Pinned trust root (3 roots, threshold 2)")

    # verifier-alice-active
    alice_active = build_directory_record(
        version=1,
        record_type="verifier",
        subject_id=alice_verifier_id,
        key_id=key_ids["alice_enc"],
        public_key=keys["alice_enc"]["public"],
        key_use="enc",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        root_keys=root_keys_list,
        threshold=2,
    )
    write_binary(out_dir / "directory" / "verifier-alice-active.cbor", alice_active)
    track("directory/verifier-alice-active.cbor", "directory", "Active verifier directory record: alice enc")

    # verifier-alice-revoked
    alice_revoked = build_directory_record(
        version=1,
        record_type="verifier",
        subject_id=alice_verifier_id,
        key_id=key_ids["alice_enc"],
        public_key=keys["alice_enc"]["public"],
        key_use="enc",
        status="revoked",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        root_keys=root_keys_list,
        threshold=2,
    )
    write_binary(out_dir / "directory" / "verifier-alice-revoked.cbor", alice_revoked)
    track("directory/verifier-alice-revoked.cbor", "directory", "Revoked verifier directory record: alice enc")

    # issuer-acme-active
    acme_active = build_directory_record(
        version=1,
        record_type="issuer",
        subject_id=issuer_id,
        key_id=key_ids["acme_sign"],
        public_key=keys["acme_sign"]["public"],
        key_use="sign",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        root_keys=root_keys_list,
        threshold=2,
    )
    write_binary(out_dir / "directory" / "issuer-acme-active.cbor", acme_active)
    track("directory/issuer-acme-active.cbor", "directory", "Active issuer directory record: acme sign")

    # ── Intermediate-record chain fixtures ──────────────────────────

    intermediate_subject_id = sha256(b"intermediate-subject-id")[:16]
    mobile_install_subject_id = sha256(b"mobile-install-subject-id")[:16]

    # intermediate.cbor — root-signed intermediate record
    intermediate_cbor = build_directory_record(
        version=1,
        record_type="intermediate",
        subject_id=intermediate_subject_id,
        key_id=key_ids["intermediate_sign"],
        public_key=keys["intermediate_sign"]["public"],
        key_use="sign",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        root_keys=root_keys_list,
        threshold=2,
    )
    write_binary(out_dir / "directory" / "intermediate-record" / "intermediate.cbor", intermediate_cbor)
    track("directory/intermediate-record/intermediate.cbor", "directory",
          "Root-signed intermediate directory record")

    # issuer-under-intermediate.cbor — mobile install issuer signed by intermediate
    issuer_under_intermediate_cbor = build_directory_record_parent_signed(
        version=1,
        record_type="issuer",
        subject_id=mobile_install_subject_id,
        key_id=key_ids["mobile_install_sign"],
        public_key=keys["mobile_install_sign"]["public"],
        key_use="sign",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        parent_key_id=key_ids["intermediate_sign"],
        parent_private_key=keys["intermediate_sign"]["private"],
    )
    write_binary(out_dir / "directory" / "intermediate-record" / "issuer-under-intermediate.cbor",
                 issuer_under_intermediate_cbor)
    track("directory/intermediate-record/issuer-under-intermediate.cbor", "directory",
          "Issuer record signed by intermediate (valid chain)")

    # chain-too-deep.cbor — issuer signed by wrong_intermediate, which itself has a parent_key_id
    # (simulates depth > 2: leaf → wrong_intermediate → another level)
    # We build a "deep intermediate" record that also has parent_key_id (not root-signed)
    deep_intermediate_cbor = build_directory_record_parent_signed(
        version=1,
        record_type="intermediate",
        subject_id=sha256(b"deep-intermediate-subject-id")[:16],
        key_id=key_ids["wrong_intermediate"],
        public_key=keys["wrong_intermediate"]["public"],
        key_use="sign",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        parent_key_id=key_ids["intermediate_sign"],
        parent_private_key=keys["intermediate_sign"]["private"],
    )
    write_binary(out_dir / "directory" / "intermediate-record" / "deep-intermediate.cbor",
                 deep_intermediate_cbor)
    track("directory/intermediate-record/deep-intermediate.cbor", "directory",
          "Intermediate record that is itself parent-signed (used in chain-too-deep test)")

    chain_too_deep_cbor = build_directory_record_parent_signed(
        version=1,
        record_type="issuer",
        subject_id=mobile_install_subject_id,
        key_id=key_ids["mobile_install_sign"],
        public_key=keys["mobile_install_sign"]["public"],
        key_use="sign",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        parent_key_id=key_ids["wrong_intermediate"],
        parent_private_key=keys["wrong_intermediate"]["private"],
    )
    write_binary(out_dir / "directory" / "intermediate-record" / "chain-too-deep.cbor",
                 chain_too_deep_cbor)
    track("directory/intermediate-record/chain-too-deep.cbor", "directory",
          "Issuer chain too deep: leaf -> intermediate -> intermediate (rejected)")

    # wrong-parent-signature.cbor — issuer with mismatched parent signature (signed by wrong key)
    wrong_parent_sig_cbor = build_directory_record_parent_signed(
        version=1,
        record_type="issuer",
        subject_id=mobile_install_subject_id,
        key_id=key_ids["mobile_install_sign"],
        public_key=keys["mobile_install_sign"]["public"],
        key_use="sign",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        parent_key_id=key_ids["intermediate_sign"],
        parent_private_key=keys["wrong_intermediate"]["private"],  # wrong key!
    )
    write_binary(out_dir / "directory" / "intermediate-record" / "wrong-parent-signature.cbor",
                 wrong_parent_sig_cbor)
    track("directory/intermediate-record/wrong-parent-signature.cbor", "directory",
          "Issuer with wrong parent signature (rejected)")

    # both-signature-containers.cbor — record with both root_signatures AND parent_signature
    both_containers_map = cbor2.loads(intermediate_cbor)  # root-signed intermediate
    both_containers_map["parent_key_id"] = key_ids["intermediate_sign"]
    both_containers_map["parent_signature"] = bytes(64)   # dummy 64 bytes
    write_binary(out_dir / "directory" / "intermediate-record" / "both-signature-containers.cbor",
                 canonical_cbor(both_containers_map))
    track("directory/intermediate-record/both-signature-containers.cbor", "directory",
          "Record with both root_signatures and parent_signature (XOR violation, rejected)")

    # no-signature-container.cbor — record with neither root_signatures nor parent_signature
    no_container_map = {
        "version": 1,
        "record_type": "issuer",
        "subject_id": mobile_install_subject_id,
        "key_id": key_ids["mobile_install_sign"],
        "public_key": keys["mobile_install_sign"]["public"],
        "key_use": "sign",
        "status": "active",
        "valid_from": timestamps["t_directory_valid_from"],
        "valid_until": timestamps["t_directory_valid_until"],
        "issued_at": timestamps["t_directory_issued"],
    }
    write_binary(out_dir / "directory" / "intermediate-record" / "no-signature-container.cbor",
                 canonical_cbor(no_container_map))
    track("directory/intermediate-record/no-signature-container.cbor", "directory",
          "Record with no signature container (rejected)")

    # Intermediate-record metadata sidecar
    intermediate_meta = {
        "intermediate_key_id_hex": bytes_to_hex(key_ids["intermediate_sign"]),
        "intermediate_public_key_hex": bytes_to_hex(keys["intermediate_sign"]["public"]),
        "intermediate_subject_id_hex": bytes_to_hex(intermediate_subject_id),
        "mobile_install_key_id_hex": bytes_to_hex(key_ids["mobile_install_sign"]),
        "mobile_install_subject_id_hex": bytes_to_hex(mobile_install_subject_id),
        "wrong_intermediate_key_id_hex": bytes_to_hex(key_ids["wrong_intermediate"]),
    }
    write_json(out_dir / "directory" / "intermediate-record" / "intermediate_meta.json",
               intermediate_meta)
    track("directory/intermediate-record/intermediate_meta.json", "directory",
          "Intermediate-record chain fixture metadata")

    # ── Invalid directory records ───────────────────────────────────

    # one-of-two-sigs: only 1 root signature (below threshold of 2)
    one_sig_record = build_directory_record(
        version=1,
        record_type="verifier",
        subject_id=alice_verifier_id,
        key_id=key_ids["alice_enc"],
        public_key=keys["alice_enc"]["public"],
        key_use="enc",
        status="active",
        valid_from=timestamps["t_directory_valid_from"],
        valid_until=timestamps["t_directory_valid_until"],
        issued_at=timestamps["t_directory_issued"],
        root_keys=root_keys_list[:1],
        threshold=1,
    )
    write_binary(out_dir / "directory" / "invalid" / "one-of-two-sigs.cbor", one_sig_record)
    track("directory/invalid/one-of-two-sigs.cbor", "directory-invalid", "Below threshold: only 1 of 2 required signatures")

    # tampered-public-key: valid sigs but public_key changed after signing
    tampered_dir = cbor2.loads(alice_active)
    tampered_pk = bytearray(tampered_dir["public_key"])
    tampered_pk[0] ^= 0xFF
    tampered_dir["public_key"] = bytes(tampered_pk)
    write_binary(out_dir / "directory" / "invalid" / "tampered-public-key.cbor", canonical_cbor(tampered_dir))
    track("directory/invalid/tampered-public-key.cbor", "directory-invalid", "Tampered public key in directory record")

    # ── Audit chain ─────────────────────────────────────────────────

    genesis_prev = audit_genesis_prev_hash()
    genesis_data = {
        "seed_string": "datawallet-audit-genesis-v1\\x00",
        "expected_prev_hash_hex": bytes_to_hex(genesis_prev),
    }
    write_json(out_dir / "audit" / "chain-genesis.json", genesis_data)
    track("audit/chain-genesis.json", "audit", "Audit chain genesis prev_hash")

    events = [
        {
            "seq": 1,
            "ts": timestamps["t_register"],
            "event_type": "verifier_registered",
            "actor_id": alice_verifier_id,
            "entry_id": None,
            "payload": {"handle": "alice"},
        },
        {
            "seq": 2,
            "ts": timestamps["t_envelope_basic"],
            "event_type": "entry_created",
            "actor_id": issuer_id,
            "entry_id": uuid_map["entry_basic"],
            "payload": {"version": 1},
        },
        {
            "seq": 3,
            "ts": timestamps["t_envelope_v2"],
            "event_type": "entry_updated",
            "actor_id": issuer_id,
            "entry_id": uuid_map["entry_v2"],
            "payload": {"version": 2},
        },
    ]

    prev_hash = genesis_prev
    chain_hashes = []
    chain_events_out = []
    for evt in events:
        cbor_map = {
            "seq": evt["seq"],
            "ts": evt["ts"],
            "event_type": evt["event_type"],
            "actor_id": evt["actor_id"],
            "entry_id": evt["entry_id"],
            "payload": evt["payload"],
        }
        event_cbor = canonical_cbor(cbor_map)
        current_hash = audit_chain_hash(prev_hash, event_cbor)
        chain_hashes.append(bytes_to_hex(current_hash))
        chain_events_out.append({
            "seq": evt["seq"],
            "ts": evt["ts"],
            "event_type": evt["event_type"],
            "actor_id_hex": bytes_to_hex(evt["actor_id"]) if evt["actor_id"] else None,
            "entry_id_hex": bytes_to_hex(evt["entry_id"]) if evt["entry_id"] else None,
            "payload": evt["payload"],
            "event_cbor_hex": bytes_to_hex(event_cbor),
        })
        prev_hash = current_hash

    chain_3 = {
        "events": chain_events_out,
        "expected_hashes_hex": chain_hashes,
    }
    write_json(out_dir / "audit" / "chain-3-events.json", chain_3)
    track("audit/chain-3-events.json", "audit", "Audit chain: 3 events with expected hashes")

    # ── Fingerprints ────────────────────────────────────────────────

    fp_vectors = []
    for name in ["alice_enc", "alice_auth", "bob_enc", "acme_sign", "root_a"]:
        pub = keys[name]["public"]
        fp = compute_fingerprint(pub)
        fp_vectors.append({
            "name": name,
            "public_key_hex": bytes_to_hex(pub),
            "expected_fp_render": fp,
        })
    write_json(out_dir / "fingerprints" / "pubkey-to-fp.json", fp_vectors)
    track("fingerprints/pubkey-to-fp.json", "fingerprint", "Public key to fingerprint vectors")

    # ── Track generated sidecar files ───────────────────────────────
    track("inputs/keypairs.expected.json", "input", "Expected derived public keys")
    track("inputs/passwords.expected.json", "input", "Expected KEK derivation results")
    track("inputs/uuids.expected.json", "input", "Expected UUIDv7 results")

    # ── Envelope metadata for contract tests ────────────────────────
    envelope_meta = {
        "basic-1-recipient": {
            "data_key_hex": bytes_to_hex(data_key_basic),
            "ciphertext_nonce_hex": bytes_to_hex(ct_nonce_basic),
            "plaintext_key": "basic",
            "issuer_signing_key": "acme_sign",
            "recipients": ["alice_enc"],
        },
        "three-recipients": {
            "data_key_hex": bytes_to_hex(data_key_three),
            "ciphertext_nonce_hex": bytes_to_hex(ct_nonce_three),
            "plaintext_key": "three_recipients",
            "issuer_signing_key": "acme_sign",
            "recipients": ["alice_enc", "bob_enc", "charlie_enc"],
        },
        "allow-list-update-v2": {
            "data_key_hex": bytes_to_hex(data_key_v2),
            "ciphertext_nonce_hex": bytes_to_hex(ct_nonce_v2),
            "plaintext_key": "v2_update",
            "issuer_signing_key": "acme_sign",
            "recipients": ["alice_enc", "bob_enc"],
        },
        "unicode-description": {
            "data_key_hex": bytes_to_hex(data_key_unicode),
            "ciphertext_nonce_hex": bytes_to_hex(ct_nonce_unicode),
            "plaintext_key": "unicode",
            "issuer_signing_key": "acme_sign",
            "recipients": ["alice_enc"],
        },
    }
    write_json(out_dir / "envelopes" / "envelope_meta.json", envelope_meta)
    track("envelopes/envelope_meta.json", "envelope", "Envelope generation metadata")

    # ── Mobile-built envelopes ─────────────────────────────────────

    data_key_mobile = hex_to_bytes("d4" * 32)
    ct_nonce_mobile = hex_to_bytes("e4" * 24)
    eph_seed_mobile_alice = hex_to_bytes("b8" * 32)

    ct_mobile, ct_hash_mobile = encrypt_plaintext(plaintexts["mobile"], data_key_mobile, ct_nonce_mobile)
    wrapped_dk_mobile_alice = wrap_data_key_for_recipient(
        data_key_mobile, keys["alice_enc"]["public"], eph_seed_mobile_alice)
    mobile_wrappings = [{
        "verifier_id": alice_verifier_id,
        "verifier_key_id": key_ids["alice_enc"],
        "wrapped_data_key": wrapped_dk_mobile_alice,
    }]

    mobile_final, mobile_signed, mobile_sig = build_envelope(
        version=1,
        entry_id=uuid_map["entry_mobile"],
        issuer_id=mobile_install_subject_id,
        issuer_label="Mobile Install",
        issuer_signing_key_id=key_ids["mobile_install_sign"],
        created_at=timestamps["t_envelope_v2"],
        description="Mobile-issued credential",
        ciphertext_alg="xsalsa20poly1305",
        ciphertext_nonce=ct_nonce_mobile,
        ciphertext=ct_mobile,
        ciphertext_hash=ct_hash_mobile,
        recipient_wrappings=mobile_wrappings,
        signing_key=keys["mobile_install_sign"]["private"],
    )
    write_binary(out_dir / "envelopes" / "mobile-built" / "single-recipient.cbor", mobile_final)
    write_binary(out_dir / "envelopes" / "mobile-built" / "single-recipient.signed", mobile_signed)
    mobile_envelope_map = cbor2.loads(mobile_final)
    write_json(out_dir / "envelopes" / "mobile-built" / "single-recipient.json",
               envelope_to_json_sidecar(mobile_envelope_map))
    track("envelopes/mobile-built/single-recipient.cbor", "envelope",
          "Mobile-built envelope: single recipient (alice)")
    track("envelopes/mobile-built/single-recipient.signed", "envelope",
          "Signed bytes for mobile-built single-recipient")
    track("envelopes/mobile-built/single-recipient.json", "envelope",
          "JSON sidecar for mobile-built single-recipient")

    mobile_meta = {
        "single-recipient": {
            "data_key_hex": bytes_to_hex(data_key_mobile),
            "ciphertext_nonce_hex": bytes_to_hex(ct_nonce_mobile),
            "plaintext_key": "mobile",
            "issuer_signing_key": "mobile_install_sign",
            "issuer_id_hex": bytes_to_hex(mobile_install_subject_id),
            "recipients": ["alice_enc"],
        },
    }
    write_json(out_dir / "envelopes" / "mobile-built" / "mobile_meta.json", mobile_meta)
    track("envelopes/mobile-built/mobile_meta.json", "envelope",
          "Mobile-built envelope generation metadata")

    # server-side-verified: expected unwrap output for the mobile envelope
    verified_meta = {
        "single-recipient": {
            "expected_plaintext": plaintexts["mobile"],
            "data_key_hex": bytes_to_hex(data_key_mobile),
            "issuer_signing_key": "mobile_install_sign",
            "issuer_id_hex": bytes_to_hex(mobile_install_subject_id),
        },
    }
    write_json(out_dir / "envelopes" / "server-side-verified" / "single-recipient.json",
               verified_meta)
    track("envelopes/server-side-verified/single-recipient.json", "envelope",
          "Server-side verified: expected unwrap for mobile single-recipient")

    # Directory record metadata
    dir_meta = {
        "pinned_root": {
            "threshold": 2,
            "root_keys": ["root_a", "root_b", "root_c"],
        },
        "verifier_ids": {
            "alice": bytes_to_hex(alice_verifier_id),
            "bob": bytes_to_hex(bob_verifier_id),
            "charlie": bytes_to_hex(charlie_verifier_id),
        },
        "issuer_id_hex": bytes_to_hex(issuer_id),
        "key_ids": {name: bytes_to_hex(kid) for name, kid in key_ids.items()},
        "acme_signing_key_valid_from": timestamps["t_directory_valid_from"],
        "acme_signing_key_valid_until": timestamps["t_directory_valid_until"],
    }
    write_json(out_dir / "directory" / "directory_meta.json", dir_meta)
    track("directory/directory_meta.json", "directory", "Directory generation metadata")

    # ── Write manifest ──────────────────────────────────────────────
    manifest = {
        "spec_version": 1,
        "generated_by": "spec/tools/gen.py",
        "files": sorted(manifest_entries, key=lambda e: e["path"]),
    }
    write_json(out_dir / "manifest.json", manifest)

    print(f"Generated {len(manifest_entries)} fixture files in {out_dir}")
    return manifest


def check_mode(committed_dir: Path):
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp) / "fixtures"
        # Copy inputs to temp dir so gen can read them
        import shutil
        shutil.copytree(committed_dir / "inputs", tmp_dir / "inputs")

        # Temporarily point FIXTURES_DIR to tmp for generation
        global FIXTURES_DIR
        old_dir = FIXTURES_DIR
        FIXTURES_DIR = tmp_dir
        generate(tmp_dir)
        FIXTURES_DIR = old_dir

        # Compare all generated files
        mismatches = []
        manifest_path = tmp_dir / "manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)

        for entry in manifest["files"]:
            rel = entry["path"]
            committed_file = committed_dir / rel
            generated_file = tmp_dir / rel
            if not committed_file.exists():
                mismatches.append(f"MISSING: {rel}")
                continue
            if committed_file.read_bytes() != generated_file.read_bytes():
                mismatches.append(f"CHANGED: {rel}")

        # Also check manifest itself
        committed_manifest = committed_dir / "manifest.json"
        if committed_manifest.exists():
            if committed_manifest.read_bytes() != manifest_path.read_bytes():
                mismatches.append("CHANGED: manifest.json")
        else:
            mismatches.append("MISSING: manifest.json")

        if mismatches:
            print("Fixture drift detected:", file=sys.stderr)
            for m in mismatches:
                print(f"  {m}", file=sys.stderr)
            sys.exit(1)
        else:
            print("All fixtures match committed files.")
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Generate Data Wallet cross-stack fixtures")
    parser.add_argument("--check", action="store_true", help="Verify committed fixtures match regenerated output")
    args = parser.parse_args()

    if args.check:
        check_mode(FIXTURES_DIR)
    else:
        generate(FIXTURES_DIR)


if __name__ == "__main__":
    main()
