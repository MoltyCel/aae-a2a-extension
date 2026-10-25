"""Subject binding (AAE -02 section 5, step 4): nonce minting and the
challenge-response check, plus the used-nonce store.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature

from .constants import AAE_CTY, MAX_CHALLENGE_RESPONSE_BYTES
from .didres import LocalDidResolver, ResolutionError
from .jose import JoseError, b64url_decode, b64url_encode, split_compact, strict_json

_NONCE_RE = re.compile(r"^([0-9a-f]{32,})\.([0-9]{1,12})\.([A-Za-z0-9_-]{43})$")
_RFC3339_UTC_OFFSET = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")

# Key-derivation label: the nonce key is domain-separated from every other
# authenticator the relying party issues (AAE -02 section 5, step 4).
_KEY_LABEL = b"aae-a2a-extension/v1/subject-binding-nonce"


class ChallengeError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class UsedNonceStore:
    """Single-use barrier keyed by SHA-256 of the nonce.

    insert() is the atomic check-and-record: an insert that finds the key is
    the rejection. Records are kept until the nonce's own expiry.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}

    def insert(self, nonce: str, expiry: int, now: int) -> bool:
        key = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if key in self._seen:
                return False
            self._seen[key] = expiry
            return True


class SubjectBinding:
    def __init__(self, resolver: LocalDidResolver, master_key: bytes | None = None,
                 lifetime_s: int = 300, skew_s: int = 60):
        master = master_key if master_key is not None else os.urandom(32)
        self._key = hmac.new(master, _KEY_LABEL, hashlib.sha256).digest()
        self._resolver = resolver
        self.lifetime_s = lifetime_s
        self.skew_s = skew_s
        self.used = UsedNonceStore()

    def _auth(self, rnd: str, expiry: str, aud: str, aae_id: str) -> str:
        msg = f"{rnd}.{expiry}.{aud}.{aae_id}".encode("utf-8")
        return b64url_encode(hmac.new(self._key, msg, hashlib.sha256).digest())

    def mint(self, aud: str, aae_id: str, now: datetime) -> str:
        """nonce = <random> "." <expiry> "." <authenticator> (AAE -02 section 5, step 4)."""
        rnd = os.urandom(16).hex()
        expiry = str(int(now.timestamp()) + self.lifetime_s)
        return f"{rnd}.{expiry}.{self._auth(rnd, expiry, aud, aae_id)}"

    def verify_response(self, response: str, *, subject_did: str, aae_id: str, aud: str,
                        expected_nonce: str | None, now: datetime) -> None:
        """Run conditions (a)-(f) of AAE -02 section 5, step 4. Raises ChallengeError."""
        # JOSE profile: bound the size before decoding anything.
        try:
            h_b64, p_b64, s_b64 = split_compact(response, MAX_CHALLENGE_RESPONSE_BYTES)
            header = strict_json(b64url_decode(h_b64))
        except JoseError as exc:
            raise ChallengeError(f"challenge_response_malformed: {exc}") from exc
        if not isinstance(header, dict):
            raise ChallengeError("challenge_response_malformed: header not an object")
        if "crit" in header:
            raise ChallengeError("challenge_response_crit_present")
        if header.get("b64") is False:
            raise ChallengeError("challenge_response_unencoded_payload")
        if header.get("alg") != "EdDSA":  # explicit allowlist, not taken from the token
            raise ChallengeError("challenge_response_alg_not_eddsa")
        if header.get("cty") == AAE_CTY or header.get("cty") == "application/" + AAE_CTY:
            raise ChallengeError("challenge_response_is_envelope")

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid.isascii():
            raise ChallengeError("challenge_kid_invalid")
        if "/" in kid or "\\" in kid or ".." in kid:
            raise ChallengeError("challenge_kid_invalid")
        did, sep, fragment = kid.partition("#")
        if not sep or not did or not fragment:
            raise ChallengeError("challenge_kid_invalid")
        # Exact octet comparison, no normalization (AAE -02 section 5, step 4).
        if did != subject_did:
            raise ChallengeError("subject_mismatch")

        # (a) + (b): key controlled by credentialSubject.id, under `authentication`.
        try:
            pub = self._resolver.resolve_key(kid, "authentication")
        except ResolutionError as exc:
            raise ChallengeError(f"subject_key_unresolved: {exc.reason}") from exc
        try:
            pub.verify(b64url_decode(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
        except (InvalidSignature, JoseError) as exc:
            raise ChallengeError("challenge_signature_invalid") from exc

        try:
            payload = strict_json(b64url_decode(p_b64))
        except JoseError as exc:
            raise ChallengeError(f"challenge_response_malformed: {exc}") from exc
        if not isinstance(payload, dict) or set(payload) != {"nonce", "aud", "iat", "aae_id"}:
            raise ChallengeError("challenge_payload_members")

        # (c) provenance: form, then authenticator (constant time), then expiry.
        nonce = payload["nonce"]
        m = _NONCE_RE.match(nonce) if isinstance(nonce, str) else None
        if m is None:
            raise ChallengeError("nonce_malformed")
        rnd, expiry, tag = m.groups()
        if not hmac.compare_digest(tag, self._auth(rnd, expiry, aud, aae_id)):
            raise ChallengeError("nonce_not_authentic")
        now_s = int(now.timestamp())
        if int(expiry) < now_s:
            raise ChallengeError("nonce_expired")
        # Profile rule: the nonce must be the one issued for this task.
        if expected_nonce is not None and not hmac.compare_digest(nonce, expected_nonce):
            raise ChallengeError("nonce_not_issued_for_task")
        # (d) audience, (e) envelope.
        if payload["aud"] != aud:
            raise ChallengeError("audience_mismatch")
        if payload["aae_id"] != aae_id:
            raise ChallengeError("aae_id_mismatch")
        # (f) iat: RFC 3339 with offset, two-sided window.
        iat_s = payload["iat"]
        if not isinstance(iat_s, str) or not _RFC3339_UTC_OFFSET.match(iat_s):
            raise ChallengeError("iat_malformed")
        iat = datetime.fromisoformat(iat_s.replace("Z", "+00:00"))
        if iat > now + timedelta(seconds=self.skew_s):
            raise ChallengeError("iat_in_future")
        if iat < now - timedelta(seconds=self.lifetime_s + self.skew_s):
            raise ChallengeError("iat_too_old")
        # (c) single use: the record is created as part of accepting the response.
        if not self.used.insert(nonce, int(expiry), now_s):
            raise ChallengeError("nonce_replayed")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
