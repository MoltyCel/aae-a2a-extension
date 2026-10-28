"""request_digest: the binding between a verification result and the request it
decided on (spec section 8.5).

The input is the request part {"skill", "transaction"} as the server froze it:
after the number mapping of section 6.4, before the skill runs. The output is
"sha256:" followed by the SHA-256 of its RFC 8785 (JCS) serialization in
lowercase hex, the same form as enforce.core_digest. There is no domain tag and
no nonce in the input, so anyone holding the request part can recompute it with
a JCS library and SHA-256 alone.

The digest identifies content, not an execution. Two tasks with byte-identical
request parts carry the same request_digest; the task id tells them apart.
"""
from __future__ import annotations

import hashlib

import jcs

PREFIX = "sha256:"


def request_bytes(part: dict) -> bytes:
    """The JCS serialization that request_digest hashes."""
    if not isinstance(part, dict) or set(part) != {"skill", "transaction"}:
        raise ValueError('request part must be exactly {"skill", "transaction"}')
    return jcs.canonicalize(part)


def request_digest(part: dict) -> str:
    return PREFIX + hashlib.sha256(request_bytes(part)).hexdigest()
