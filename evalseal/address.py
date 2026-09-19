"""Addresses: sha256 over canonical bytes, tagged with the profile that made them.

An address here looks like::

    es1:strict:sha256:3f1c...

The profile name is *inside* the address. Two addresses computed under
different equivalence relations are not comparable, and putting the relation in
the string makes accidental comparison impossible rather than merely
discouraged.

Scope note, stated deliberately: the ``es1`` scheme is local to EvalSeal. It
claims no byte compatibility with UOR-ADDR, with SCITT's canonical payload
binding, with OCI descriptors, or with any other addressing scheme, and none of
those should be inferred from a shared use of sha256. The contribution here is
not the digest construction; it is binding an evaluation result to a
configuration identity computed under a declared relation.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import Profile, canonical_text, canonicalize

__all__ = ["SCHEME", "addr_of", "addr_of_text", "addr_of_bytes", "short"]

SCHEME = "es1"


def addr_of_bytes(data: bytes, profile: str | Profile = "strict") -> str:
    name = profile if isinstance(profile, str) else profile.name
    return f"{SCHEME}:{name}:sha256:{hashlib.sha256(data).hexdigest()}"


def addr_of(obj: Any, profile: str | Profile = "strict") -> str:
    """Address of a JSON-representable object under ``profile``."""
    return addr_of_bytes(canonicalize(obj, profile), profile)


def addr_of_text(text: str, profile: str | Profile = "strict") -> str:
    """Address of a free-text artifact under ``profile``."""
    return addr_of_bytes(canonical_text(text, profile), profile)


def raw_byte_addr(data: bytes) -> str:
    """Digest of the literal bytes, with no canonicalization at all.

    This is the baseline EvalSeal measures itself against, so it gets a name
    and a distinct tag rather than being an untagged sha256 floating around.
    """
    return f"{SCHEME}:bytes:sha256:{hashlib.sha256(data).hexdigest()}"


def short(addr: str, n: int = 8) -> str:
    """``es1:strict:sha256:3f1c9a...`` -> ``3f1c9a02``, for terminal output."""
    return addr.rsplit(":", 1)[-1][:n]
