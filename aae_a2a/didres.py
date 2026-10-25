"""Local DID resolution.

AAE -02 section 5.2 defers DID methods that require outbound resolution: a
relying party that cannot resolve a DID locally rejects. This resolver only
answers from a fixed set of DID documents it was configured with.
"""
from __future__ import annotations

import glob
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .jose import JoseError, b64url_decode


class ResolutionError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class LocalDidResolver:
    def __init__(self, documents: list[dict] | None = None):
        self._docs: dict[str, dict] = {}
        for doc in documents or []:
            self.add(doc)

    @classmethod
    def from_directory(cls, path: str) -> "LocalDidResolver":
        docs = []
        for p in sorted(glob.glob(os.path.join(path, "*.json"))):
            with open(p, encoding="utf-8") as fh:
                docs.append(json.load(fh))
        return cls(docs)

    def add(self, doc: dict) -> None:
        self._docs[doc["id"]] = doc

    def resolve_key(self, kid: str, relationship: str) -> Ed25519PublicKey:
        """Dereference a DID URL to an Ed25519 key authorized for `relationship`
        ("assertionMethod" or "authentication")."""
        if not isinstance(kid, str) or "#" not in kid:
            raise ResolutionError("kid_not_did_url")
        did, fragment = kid.split("#", 1)
        if not did or not fragment:
            raise ResolutionError("kid_not_did_url")
        doc = self._docs.get(did)
        if doc is None:
            raise ResolutionError("did_unresolvable")
        vm = next((m for m in doc.get("verificationMethod", []) if m.get("id") == kid), None)
        if vm is None:
            raise ResolutionError("verification_method_absent")
        if kid not in doc.get(relationship, []):
            raise ResolutionError(f"vm_not_authorized_{relationship}")
        jwk = vm.get("publicKeyJwk") or {}
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
            raise ResolutionError("key_not_ed25519")
        try:
            raw = b64url_decode(jwk["x"])
        except JoseError as exc:
            raise ResolutionError("key_not_ed25519") from exc
        if len(raw) != 32:
            raise ResolutionError("key_not_ed25519")
        return Ed25519PublicKey.from_public_bytes(raw)
