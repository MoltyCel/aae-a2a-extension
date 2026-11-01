"""A PSEA proof over the same request as the profile's request_digest, and one
over a different request.

The example and the counter-example are built here, not taken from anywhere:
hash a request part with this profile's own request_digest, then write the same
32 bytes in the encoding psea_payload_hash prescribes. A PSEA proof whose
approver signed that request part carries exactly that string.
"""
from __future__ import annotations

import base64

import pytest

from aae_a2a.digest import request_digest
from aae_a2a.psea import (
    PseaHashError,
    covers_same_request,
    decode_payload_hash,
    decode_request_digest,
    payload_hash,
)

#: The request part of XR-01, the accepted order, taken from
#: tests/vectors/crossrun/cases.json.
ORDER = {
    "skill": "place-order",
    "transaction": {
        "amount": 120,
        "currency": "EUR",
        "items": [{"sku": "PAPER-A4", "qty": 20}],
    },
}

#: The counter-example: another request. Same shape, one value changed, so the
#: digests share nothing.
OTHER_ORDER = {
    "skill": "place-order",
    "transaction": {
        "amount": 121,
        "currency": "EUR",
        "items": [{"sku": "PAPER-A4", "qty": 20}],
    },
}


def psea_proof_over(part: dict) -> str:
    """The psea_payload_hash an approver would carry for this request part."""
    return payload_hash(decode_request_digest(request_digest(part)))


def test_example_same_request_matches():
    digest = request_digest(ORDER)
    proof = psea_proof_over(ORDER)
    assert covers_same_request(proof, digest) is True
    # The two encodings of those same 32 bytes have no character in common at
    # the end and differ in alphabet: the match cannot come from a string
    # comparison.
    assert proof != digest
    assert decode_payload_hash(proof) == decode_request_digest(digest)
    assert len(decode_payload_hash(proof)) == 32


def test_counter_example_other_request_differs():
    digest = request_digest(ORDER)
    proof = psea_proof_over(OTHER_ORDER)
    assert covers_same_request(proof, digest) is False
    mine, theirs = decode_payload_hash(proof), decode_request_digest(digest)
    assert mine != theirs
    # Not a near miss: one changed value in the request part leaves almost no
    # byte of the digest where it was.
    assert sum(a == b for a, b in zip(mine, theirs)) < 4


def test_the_two_encodings_are_not_interchangeable():
    """base64url of the same digest is not psea_payload_hash and is rejected.

    The specification calls the split deliberate and a token that mixes them
    non-conformant. A proof in the wrong encoding is malformed; it is not a
    proof about another request, so it raises instead of comparing false.
    """
    raw = decode_request_digest(request_digest(ORDER))
    standard = payload_hash(raw)
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert urlsafe != standard
    with pytest.raises(PseaHashError):
        decode_payload_hash(urlsafe)
    with pytest.raises(PseaHashError):
        covers_same_request(urlsafe, request_digest(ORDER))


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not base64 at all",
        # The 32-byte form without its padding.
        payload_hash(bytes(32)).rstrip("="),
        # 31 bytes: a different hash function, right alphabet.
        base64.b64encode(bytes(31)).decode("ascii"),
        # 33 bytes.
        base64.b64encode(bytes(33)).decode("ascii"),
        # Right length, but the final sextet carries bits a 32-byte digest
        # never sets, so the encoding is non-canonical.
        payload_hash(bytes(32))[:42] + "B=",
    ],
)
def test_payload_hash_rejects_other_forms(value):
    with pytest.raises(PseaHashError):
        decode_payload_hash(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        request_digest(ORDER).upper(),
        request_digest(ORDER)[len("sha256:"):],
        "sha512:" + request_digest(ORDER)[len("sha256:"):],
        request_digest(ORDER) + "00",
    ],
)
def test_request_digest_rejects_other_forms(value):
    with pytest.raises(PseaHashError):
        decode_request_digest(value)


def test_payload_hash_takes_a_digest_not_a_message():
    with pytest.raises(PseaHashError):
        payload_hash(b"too short")
