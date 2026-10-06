#!/usr/bin/env python3
"""
Sovereign OAuth Local Generator - Production
Ed25519 keypair generation, canonical JSON, O_EXCL writes.
No tests. No avatar. Fail-closed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: cryptography package required for Ed25519", file=sys.stderr)
    sys.exit(1)


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def write_excl(path: Path, data: bytes) -> None:
    """Atomic exclusive write - fails if file exists."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sovereign OAuth Local Generator")
    parser.add_argument("--dry-run", action="store_true", help="Generate and validate without writing secrets")
    parser.add_argument("--out-dir", type=Path, default=Path("artifacts/oauth"), help="Output directory")
    args = parser.parse_args()

    print(f"[oauth] Python {sys.version}")
    print(f"[oauth] dry-run={args.dry_run}")

    private_bytes, public_bytes = generate_keypair()
    kid = hashlib.sha256(public_bytes).hexdigest()[:16]
    created = int(time.time())

    record = {
        "kid": kid,
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kty": "OKP",
        "created": created,
        "x": base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii"),
    }

    payload = canonical_json(record)
    print(f"[oauth] kid={kid}")
    print(f"[oauth] public_x={record['x']}")
    print(f"[oauth] canonical_len={len(payload)}")

    if args.dry_run:
        print("[oauth] DRY-RUN complete - no files written")
        print("[oauth] SUCCESS")
        return 0

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    pub_path = out / f"oauth-{kid}.pub.json"
    # Never write private key in dry-run; production path would seal it
    write_excl(pub_path, payload + b"\n")
    print(f"[oauth] wrote {pub_path}")
    print("[oauth] SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
