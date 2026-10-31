"""Deterministic TEST-ONLY keys, DID documents and AAE issuance for the demo.

Every private key here is derived from a public label with SHA-256, so anyone
can recompute it. These keys are not secrets and MUST NOT be used for anything
but this demo and its tests. The DIDs use the did:example method.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import AAE_CTY
from .didres import LocalDidResolver
from .jose import b64url_encode, sign_compact

_SEED_LABEL = "aae-a2a-extension/testkey/v1/"


def demo_key(name: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256((_SEED_LABEL + name).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def did_of(name: str) -> str:
    return f"did:example:{name}"


def kid_of(name: str) -> str:
    return f"{did_of(name)}#key-1"


def did_document(name: str, relationships: tuple[str, ...]) -> dict:
    pub = demo_key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did, kid = did_of(name), kid_of(name)
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": kid, "type": "JsonWebKey", "controller": did,
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(pub)},
        }],
    }
    for rel in relationships:
        doc[rel] = [kid]
    return doc


# issuer: the principal's trust registry; buyer/supplier: agents. "buyer-sub" is a
# sub-agent for the delegation case; "mallory" has a key but no DID document.
PARTIES = {
    "issuer": ("assertionMethod",),
    "buyer": ("authentication", "assertionMethod"),
    "buyer-sub": ("authentication",),
    "supplier": ("authentication",),
    "other-agent": ("authentication",),
}


def demo_resolver() -> LocalDidResolver:
    return LocalDidResolver([did_document(n, rels) for n, rels in PARTIES.items()])


def _z(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_vc(*, subject: str, issuer: str, mandate: dict, constraints: dict,
            not_before: datetime, not_after: datetime, single_use: bool = False,
            vc_id: str | None = None, extra_validity: dict | None = None) -> dict:
    validity = {"not_before": _z(not_before), "not_after": _z(not_after), "single_use": single_use}
    validity.update(extra_validity or {})
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://moltrust.ch/contexts/aae/v1"],
        "type": ["VerifiableCredential", "AgentAuthorizationEnvelope"],
        "id": vc_id or f"urn:uuid:{uuid.uuid4()}",
        "issuer": issuer,
        "validFrom": _z(not_before),
        "credentialSubject": {
            "id": subject,
            "aae": {"mandate": mandate, "constraints": constraints, "validity": validity},
        },
    }


def sign_aae(vc: dict, signer: str, *, cty: str = AAE_CTY, kid: str | None = None) -> str:
    header = {"alg": "EdDSA", "cty": cty, "kid": kid or kid_of(signer)}
    return sign_compact(header, vc, demo_key(signer))


def buyer_mandate() -> dict:
    return {
        "actions": ["read", "pay"],
        "purpose": "Purchase office supplies on behalf of the principal",
        "scope": "procurement",
        "principal_did": "did:example:principal-acme",
    }


# The principal of buyer_mandate(). It has no DID document: under -02 6.4 the
# key that checks its ratification comes from the mandate, never from elsewhere.
PRINCIPAL_DID = "did:example:principal-acme"


def public_key_hex(name: str) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return demo_key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def held_mandate(action: dict) -> dict:
    """buyer_mandate() with a hold grant for `action` and its principal's key:
    an order inside the grant is PENDING until the principal ratifies it."""
    from . import enforce
    return {**buyer_mandate(),
            "principal": {"did": PRINCIPAL_DID, "public_key": public_key_hex("principal")},
            "grants": [{"action_binding": enforce.action_binding(action),
                        "type_fields": sorted(action, key=lambda k: k != "verb"),
                        "disposition": "hold",
                        "constraints": [{"type": "range", "field": "amount", "lo": 0, "hi": 300},
                                        {"type": "exact", "field": "currency", "value": "EUR"}]}]}


def ratification_proof(prior_core_digest: str, decision: str, mandate: dict, *,
                       signer: str = "principal", authority: str = PRINCIPAL_DID) -> dict:
    """The authority proof of -02 6.4, signed with a test key."""
    from . import enforce
    sig = demo_key(signer).sign(enforce.statement_bytes(prior_core_digest, decision, authority))
    return {"mandate": mandate, "authority": authority, "signature": sig.hex()}


def buyer_constraints(domains: list[str]) -> dict:
    return {
        "max_transaction_value": {"value": 500, "currency": "EUR", "required": True},
        "allowed_domains": {"value": domains, "required": True},
    }


def issue_buyer_aae(now: datetime, domains: list[str], *, lifetime=timedelta(hours=1),
                    subject: str | None = None, **kw) -> str:
    vc = make_vc(subject=subject or did_of("buyer"), issuer=did_of("issuer"),
                 mandate=kw.pop("mandate", buyer_mandate()),
                 constraints=kw.pop("constraints", buyer_constraints(domains)),
                 not_before=kw.pop("not_before", now - timedelta(minutes=5)),
                 not_after=kw.pop("not_after", now + lifetime), **kw)
    return sign_aae(vc, "issuer")


def issue_supplier_aae(now: datetime) -> str:
    """The supplier's own AAE, published in its Agent Card (informative)."""
    vc = make_vc(subject=did_of("supplier"), issuer=did_of("issuer"),
                 mandate={"actions": ["write"], "purpose": "Accept purchase orders and issue confirmations",
                          "principal_did": "did:example:principal-supplier-co"},
                 constraints={}, not_before=now - timedelta(minutes=5), not_after=now + timedelta(days=1))
    return sign_aae(vc, "issuer")
