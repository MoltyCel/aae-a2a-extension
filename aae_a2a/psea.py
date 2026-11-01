"""psea_payload_hash against request_digest: the one comparison a PSEA proof
needs from this profile.

A PSEA proof carries psea_payload_hash: the SHA-256 over the RFC 8785 (JCS)
form of the action payload the approver signed, written in standard Base64
with padding (RFC 4648 section 4). The PSEA specification is explicit that
this field does not share the encoding of ueid and psea_user_hash, which are
base64url without padding, and that the two are not interchangeable:
"a deliberate per-claim encoding split that implementers MUST observe
exactly" (draft-yossif-psea-03, the normative Base64 encoding split under
Figure 1; the pattern itself is stated there and in section 3.5, and the
reference implementation is conformance/src/psea.py payload_hash).

This profile carries the same kind of hash of the request part it decided on
in request_digest: "sha256:" followed by lowercase hex (spec section 8.5,
digest.request_digest).

Both name 32 bytes of the same hash function, in two encodings that never
agree on a character. Whether a PSEA proof speaks about the very request this
profile decided on is therefore one question, and it is decided on the
decoded octets: decode both, compare the bytes. A string comparison would
answer "different" for a proof that is in fact about the same request.
"""
from __future__ import annotations

import base64
import binascii
import re

from .digest import PREFIX

#: Standard Base64 with padding over 32 bytes, the form psea_payload_hash
#: takes. The last character before "=" cannot be arbitrary: 32 bytes leave
#: two bits unused, so only a sixth of the alphabet can appear there. The
#: PSEA specification states this pattern.
PAYLOAD_HASH = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")

#: "sha256:" and 64 lowercase hex characters, the form request_digest takes.
REQUEST_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

DIGEST_SIZE = 32


class PseaHashError(ValueError):
    """A hash was not in the encoding its field prescribes."""


def decode_payload_hash(value: str) -> bytes:
    """The 32 octets behind a psea_payload_hash.

    Rejects base64url, missing padding and any length other than 32 bytes:
    each of those is a different field or a different hash function, not a
    variant of this one.
    """
    if not isinstance(value, str) or not PAYLOAD_HASH.match(value):
        raise PseaHashError(
            "psea_payload_hash must be standard Base64 with padding over 32 "
            "bytes (RFC 4648 section 4), not base64url"
        )
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - pattern catches these
        raise PseaHashError(f"psea_payload_hash is not Base64: {exc}") from exc
    if len(raw) != DIGEST_SIZE:
        raise PseaHashError(f"psea_payload_hash is {len(raw)} bytes, {DIGEST_SIZE} expected")
    return raw


def decode_request_digest(value: str) -> bytes:
    """The 32 octets behind a request_digest, prefix removed."""
    if not isinstance(value, str) or not REQUEST_DIGEST.match(value):
        raise PseaHashError(f'request_digest must be "{PREFIX}" and 64 lowercase hex characters')
    return bytes.fromhex(value[len(PREFIX):])


def covers_same_request(psea_payload_hash: str, request_digest: str) -> bool:
    """True when the PSEA proof is about the request this profile decided on.

    The comparison is over the decoded octets, so it holds across the two
    encodings. Either argument in the wrong encoding raises PseaHashError
    rather than returning False: that is a malformed proof, not a proof about
    another request.
    """
    return decode_payload_hash(psea_payload_hash) == decode_request_digest(request_digest)


def payload_hash(raw: bytes) -> str:
    """A 32-byte hash in the encoding psea_payload_hash prescribes.

    For building examples and for showing the encoding a mismatch should have
    used. It does not hash anything: the input is the digest itself.
    """
    if len(raw) != DIGEST_SIZE:
        raise PseaHashError(f"a digest is {DIGEST_SIZE} bytes, got {len(raw)}")
    return base64.b64encode(raw).decode("ascii")
