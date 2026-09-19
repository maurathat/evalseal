"""Ed25519 over the canonical receipt bytes.

An unsigned receipt is editable by anyone who can edit the prompt, which makes
it a log entry rather than evidence. Twenty lines closes that.

The signature covers the canonical bytes of the receipt payload under the
receipt's own declared profile, so "what was signed" is reproducible by a
verifier who has only the payload and the profile name -- no re-serialization
ambiguity, which is the usual way signed-JSON schemes break.

Key handling here is demo-grade on purpose: a keypair on disk, generated on
first use. In a real deployment the signing key belongs to whoever has
authority to approve a release, in an HSM or a KMS, and the receipt should
carry a certificate chain rather than a bare public key. That gap is worth
naming out loud rather than papering over.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize

__all__ = ["load_or_create_key", "sign_payload", "verify_payload", "public_key_hex"]


def load_or_create_key(path: str | Path) -> Ed25519PrivateKey:
    p = Path(path)
    if p.exists():
        return serialization.load_pem_private_key(p.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    p.chmod(0o600)
    return key


def public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def signing_bytes(payload: dict[str, Any], profile: str) -> bytes:
    """Exactly the bytes that get signed, so a verifier can reproduce them."""
    return canonicalize(payload, profile)


def sign_payload(payload: dict[str, Any], key: Ed25519PrivateKey, profile: str = "strict") -> str:
    return key.sign(signing_bytes(payload, profile)).hex()


def verify_payload(
    payload: dict[str, Any], signature_hex: str, public_key_hex_str: str, profile: str = "strict"
) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex_str))
    try:
        pub.verify(bytes.fromhex(signature_hex), signing_bytes(payload, profile))
        return True
    except (InvalidSignature, ValueError):
        return False
