"""Minimal compact-JWS helpers for EdDSA (Ed25519) only.

Deliberately small: one algorithm, compact serialization only, strict JSON
parsing that rejects duplicate member names (AAE -02 section 5, step 4, JOSE
profile for the challenge response).
"""
from __future__ import annotations

import base64
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class JoseError(ValueError):
    """Raised for any malformed JOSE input."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        raise JoseError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise JoseError(f"duplicate member name {k!r}")
        out[k] = v
    return out


def strict_json(data: bytes):
    """Parse UTF-8 JSON, rejecting duplicate member names at any depth."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JoseError("not UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates)
    except JoseError:
        raise
    except ValueError as exc:
        raise JoseError("not JSON") from exc


def split_compact(jws: str, max_bytes: int) -> tuple[str, str, str]:
    """Bound the size first, then split into three base64url segments."""
    if not isinstance(jws, str):
        raise JoseError("JWS is not a string")
    if len(jws) > max_bytes:
        raise JoseError("JWS exceeds size bound")
    parts = jws.split(".")
    if len(parts) != 3 or not all(_B64URL.match(p) for p in parts):
        raise JoseError("not a compact JWS with three parts")
    if parts[1] == "":
        raise JoseError("detached payload")
    return parts[0], parts[1], parts[2]


def sign_compact(header: dict, payload: dict, key: Ed25519PrivateKey) -> str:
    """Produce an EdDSA compact JWS. Used by the demo and tests only."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = key.sign(f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{b64url_encode(sig)}"
