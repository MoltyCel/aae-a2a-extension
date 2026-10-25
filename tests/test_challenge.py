"""Unit tests for the AAE -02 section 5 step 4 challenge-response profile."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from aae_a2a.challenge import ChallengeError, SubjectBinding, utc_now
from aae_a2a.jose import b64url_encode, sign_compact
from aae_a2a.testkeys import demo_key, demo_resolver, did_of, kid_of

AUD = "http://supplier.example/a2a/jsonrpc"
AAE_ID = "urn:uuid:00000000-0000-4000-8000-000000000001"


def _setup():
    sb = SubjectBinding(demo_resolver(), master_key=b"k" * 32)
    now = utc_now()
    nonce = sb.mint(AUD, AAE_ID, now)
    return sb, now, nonce


def _payload(n, now, **over):
    p = {"nonce": n, "aud": AUD, "iat": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "aae_id": AAE_ID}
    p.update(over)
    return p


def _check(sb, resp, now, nonce):
    sb.verify_response(resp, subject_did=did_of("buyer"), aae_id=AAE_ID, aud=AUD,
                       expected_nonce=nonce, now=now)


def _raw(header_json: str, payload_json: str, signer="buyer") -> str:
    h = b64url_encode(header_json.encode())
    p = b64url_encode(payload_json.encode())
    sig = demo_key(signer).sign(f"{h}.{p}".encode())
    return f"{h}.{p}.{b64url_encode(sig)}"


def test_valid_then_replay():
    sb, now, nonce = _setup()
    resp = sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, _payload(nonce, now), demo_key("buyer"))
    _check(sb, resp, now, nonce)
    with pytest.raises(ChallengeError, match="nonce_replayed"):
        _check(sb, resp, now, nonce)


@pytest.mark.parametrize("header,payload_over,reason", [
    ({"alg": "ES256"}, {}, "challenge_response_alg_not_eddsa"),
    ({"crit": ["exp"]}, {}, "challenge_response_crit_present"),
    ({"cty": "aae+json"}, {}, "challenge_response_is_envelope"),
    ({"kid": did_of("buyer")}, {}, "challenge_kid_invalid"),
    ({"kid": did_of("other-agent") + "#key-1"}, {}, "subject_mismatch"),
    ({}, {"aud": "http://elsewhere.example/a2a"}, "audience_mismatch"),
    ({}, {"aae_id": "urn:uuid:other"}, "aae_id_mismatch"),
    ({}, {"extra": 1}, "challenge_payload_members"),
    ({}, {"nonce": "abc"}, "nonce_malformed"),
])
def test_rejections(header, payload_over, reason):
    sb, now, nonce = _setup()
    hdr = {"alg": "EdDSA", "kid": kid_of("buyer"), **header}
    resp = sign_compact(hdr, _payload(nonce, now, **payload_over), demo_key("buyer"))
    with pytest.raises(ChallengeError, match=reason):
        _check(sb, resp, now, nonce)


def test_tampered_nonce_expiry_not_authentic():
    sb, now, nonce = _setup()
    rnd, exp, tag = nonce.split(".")
    longer = f"{rnd}.{int(exp) + 3600}.{tag}"
    resp = sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, _payload(longer, now), demo_key("buyer"))
    with pytest.raises(ChallengeError, match="nonce_not_authentic"):
        _check(sb, resp, now, None)


def test_expired_nonce():
    sb, now, nonce = _setup()
    later = now + timedelta(seconds=sb.lifetime_s + 5)
    resp = sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, _payload(nonce, later), demo_key("buyer"))
    with pytest.raises(ChallengeError, match="nonce_expired"):
        _check(sb, resp, later, nonce)


def test_iat_in_future():
    sb, now, nonce = _setup()
    p = _payload(nonce, now + timedelta(minutes=10))
    resp = sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, p, demo_key("buyer"))
    with pytest.raises(ChallengeError, match="iat_in_future"):
        _check(sb, resp, now, nonce)


def test_duplicate_member_in_payload():
    sb, now, nonce = _setup()
    p = _payload(nonce, now)
    body = json.dumps(p)[:-1] + ', "nonce": "x"}'
    resp = _raw(json.dumps({"alg": "EdDSA", "kid": kid_of("buyer")}), body)
    with pytest.raises(ChallengeError, match="duplicate member"):
        _check(sb, resp, now, nonce)


def test_duplicate_member_in_header():
    sb, now, nonce = _setup()
    hdr = '{"alg":"EdDSA","kid":"%s","kid":"%s"}' % (kid_of("buyer"), kid_of("other-agent"))
    resp = _raw(hdr, json.dumps(_payload(nonce, now)))
    with pytest.raises(ChallengeError, match="duplicate member"):
        _check(sb, resp, now, nonce)


def test_key_not_under_authentication():
    # did:example:issuer has only assertionMethod; it cannot answer a challenge.
    sb = SubjectBinding(demo_resolver(), master_key=b"k" * 32)
    now = utc_now()
    nonce = sb.mint(AUD, AAE_ID, now)
    resp = sign_compact({"alg": "EdDSA", "kid": kid_of("issuer")}, _payload(nonce, now), demo_key("issuer"))
    with pytest.raises(ChallengeError, match="vm_not_authorized_authentication"):
        sb.verify_response(resp, subject_did=did_of("issuer"), aae_id=AAE_ID, aud=AUD,
                           expected_nonce=nonce, now=now)
