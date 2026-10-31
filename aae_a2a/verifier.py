# Portions derived from examples/python-verify.py in MoltyCel/aae-conformance-vectors
# (commit 2f117799c604f258e67d5c13d69fea63881bdae0),
# Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust), Apache License 2.0.
# Modified: DID resolution, subject binding, single-use state, revocation and
# rate-limit state are injected instead of read from a vector context; strict
# JOSE parsing; ancestors are indexed by id and walked by delegator_aae_id
# (AAE -02 section 5, step 9); grant evaluation and grant attenuation added.
"""The AAE verification algorithm of draft-kroehl-agentic-trust-aae-02, section 5.

`AaeVerifier.verify` runs steps 1-9 in order and raises `Reject(step, reason)`
at the first failing step. Step numbers in results are the -02 section 5 step
numbers; step 0 marks a check defined by the A2A profile rather than by -02.
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from cryptography.exceptions import InvalidSignature

from . import enforce
from .constants import AAE_CTY, MAX_ANCESTORS, MAX_JWS_BYTES
from .didres import LocalDidResolver, ResolutionError
from .jose import JoseError, b64url_decode, b64url_encode, split_compact, strict_json

RECOGNIZED_CONSTRAINTS = {"max_transaction_value", "allowed_domains", "rate_limit"}
NUMERIC_UPPER_BOUND = {"max_transaction_value"}
CURRENCY_VALUED = {"max_transaction_value"}
ALLOWLIST_CONSTRAINTS = {"allowed_domains"}
DISPOSITION_ORDER = {"allow": 0, "hold": 1, "forbid": 2}
MAX_CHAIN_HOPS = 8

STEP_NAMES = {
    0: "profile",
    1: "signature",
    2: "payload_schema",
    3: "temporal_validity",
    4: "subject_binding",
    5: "single_use",
    6: "action",
    7: "constraints",
    8: "revocation",
    9: "delegation_chain",
}

_UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


class Reject(Exception):
    def __init__(self, step: int, reason: str, detail: str | None = None,
                 enforce_result: dict | None = None):
        super().__init__(reason)
        self.step = step
        self.reason = reason
        self.detail = detail
        self.enforce_result = enforce_result


@dataclass
class Accepted:
    vc: dict
    root_vc: dict
    last_step: int
    enforce_result: dict | None = None
    steps: list[int] = field(default_factory=list)


# --- helpers -----------------------------------------------------------------

def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def parse_duration(s) -> timedelta | None:
    m = _DURATION.match(s) if isinstance(s, str) and s not in ("P", "PT") else None
    if m is None:
        return None
    d, h, mi, se = (int(x) if x else 0 for x in m.groups())
    return timedelta(days=d, hours=h, minutes=mi, seconds=se)


def jws_hash(jws: str) -> str:
    """delegator_aae_hash construction of AAE -02 section 3."""
    return "sha-256:" + b64url_encode(hashlib.sha256(jws.encode("ascii")).digest())


def _is_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


# --- state ---------------------------------------------------------------------

class SingleUseStore:
    """Atomic check-and-record keyed by the VC id (AAE -02 section 5, step 5).

    reserve() is the atomic check; a reservation becomes the record when the
    presentation is accepted, and is released if a later step rejects it.
    """

    def __init__(self, consumed: list[str] | None = None):
        self._lock = threading.Lock()
        self._ids: set[str] = set(consumed or [])

    def reserve(self, vc_id: str) -> bool:
        with self._lock:
            if vc_id in self._ids:
                return False
            self._ids.add(vc_id)
            return True

    def release(self, vc_id: str) -> None:
        with self._lock:
            self._ids.discard(vc_id)


class RateLimitStore:
    """Counts accepted actions per VC id for rate_limit (AAE -02 section 2.3)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._events: dict[str, deque] = {}

    def count(self, vc_id: str, window: timedelta, now: datetime) -> int:
        with self._lock:
            q = self._events.get(vc_id, deque())
            return sum(1 for t in q if t > now - window)

    def record(self, vc_id: str, now: datetime) -> None:
        with self._lock:
            self._events.setdefault(vc_id, deque(maxlen=10_000)).append(now)


# Revocation lookup: returns {"http_status": int, "revoked": bool, "unparseable": bool}
# or None when the status cannot be determined (which fails closed).
RevocationLookup = Callable[[dict], "dict | None"]


def no_revocation_egress(_vc: dict) -> None:
    """Default: this verifier has no constrained egress path, so it cannot
    determine revocation status and fails closed (AAE -02 section 5.2)."""
    return None


# --- verifier ------------------------------------------------------------------

class AaeVerifier:
    def __init__(self, resolver: LocalDidResolver, *,
                 accepted_issuers: list[str] | None = None,
                 revocation: RevocationLookup = no_revocation_egress,
                 single_use: SingleUseStore | None = None,
                 rate_limits: RateLimitStore | None = None):
        self.resolver = resolver
        self.accepted_issuers = accepted_issuers
        self.revocation = revocation
        self.single_use = single_use or SingleUseStore()
        self.rate_limits = rate_limits or RateLimitStore()

    # step 1 -----------------------------------------------------------------
    def verify_signature(self, jws: str, step: int = 1) -> tuple[dict, dict, str]:
        try:
            h_b64, p_b64, s_b64 = split_compact(jws, MAX_JWS_BYTES)
            header = strict_json(b64url_decode(h_b64))
        except JoseError as exc:
            raise Reject(step, "malformed_jws", str(exc)) from exc
        if not isinstance(header, dict):
            raise Reject(step, "malformed_header")
        if header.get("alg") != "EdDSA":
            raise Reject(step, "alg_not_eddsa")
        if "crit" in header:
            raise Reject(step, "crit_not_supported")
        kid = header.get("kid")
        try:
            pub = self.resolver.resolve_key(kid, "assertionMethod")
        except ResolutionError as exc:
            raise Reject(step, exc.reason) from exc
        try:
            pub.verify(b64url_decode(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
        except (InvalidSignature, JoseError) as exc:
            raise Reject(step, "invalid_signature") from exc
        try:
            payload = strict_json(b64url_decode(p_b64))
        except JoseError as exc:
            # The payload is parsed in step 2 by the draft; a payload that is not
            # JSON fails there.
            raise Reject(2 if step == 1 else step, "payload_not_json", str(exc)) from exc
        if not isinstance(payload, dict):
            # Before signing authority, which reads issuer from it (spec 7.2).
            raise Reject(2 if step == 1 else step, "payload_not_object")
        return header, payload, kid.split("#", 1)[0]

    @staticmethod
    def check_signing_authority(vc: dict, signing_did: str, step: int = 1) -> None:
        mandate = ((vc.get("credentialSubject") or {}).get("aae") or {}).get("mandate")
        deleg = mandate.get("delegation") if isinstance(mandate, dict) else None
        issuer = vc.get("issuer") if isinstance(vc, dict) else None
        if deleg is None:
            if signing_did != issuer:
                raise Reject(step, "signing_authority_mismatch")
        else:
            delegator = deleg.get("delegator_did") if isinstance(deleg, dict) else None
            # Case (a) only; case (b) is rejected by this revision (-02 section 5.2).
            if not (signing_did == delegator and issuer == delegator):
                raise Reject(step, "signing_authority_mismatch")

    # step 2 -----------------------------------------------------------------
    @staticmethod
    def check_schema(header: dict, vc, step: int = 2) -> None:
        if header.get("cty") != AAE_CTY:
            raise Reject(step, "cty_not_aae_json")
        if not isinstance(vc, dict):
            raise Reject(step, "payload_not_object")
        if "proof" in vc:
            raise Reject(step, "embedded_proof_present")
        if not isinstance(vc.get("id"), str) or not isinstance(vc.get("issuer"), str):
            raise Reject(step, "missing_id_or_issuer")
        cs = vc.get("credentialSubject")
        if not isinstance(cs, dict) or not isinstance(cs.get("id"), str):
            raise Reject(step, "missing_credentialSubject")
        aae = cs.get("aae")
        if not isinstance(aae, dict) or not all(k in aae for k in ("mandate", "constraints", "validity")):
            raise Reject(step, "missing_aae_blocks")
        mandate, constraints, validity = aae["mandate"], aae["constraints"], aae["validity"]
        if not isinstance(mandate, dict) or not isinstance(mandate.get("actions"), list) \
                or not all(isinstance(a, str) for a in mandate["actions"]):
            raise Reject(step, "mandate_actions_invalid")
        if not isinstance(constraints, dict):
            raise Reject(step, "constraints_not_object")
        if not isinstance(validity, dict):
            raise Reject(step, "validity_not_object")
        for k in ("not_before", "not_after"):
            if not isinstance(validity.get(k), str) or not _UTC_Z.match(validity[k]):
                raise Reject(step, f"validity_{k}_invalid")
        vf = vc.get("validFrom")
        if vf is not None and (not isinstance(vf, str) or not _UTC_Z.match(vf)):
            raise Reject(step, "validFrom_invalid")
        if "single_use" in validity and not isinstance(validity["single_use"], bool):
            raise Reject(step, "single_use_not_boolean")

    # step 3 -----------------------------------------------------------------
    @staticmethod
    def check_temporal(vc: dict, now: datetime, step: int = 3) -> None:
        validity = vc["credentialSubject"]["aae"]["validity"]
        lower = parse_time(validity["not_before"])
        if vc.get("validFrom"):
            lower = max(lower, parse_time(vc["validFrom"]))
        if now < lower:
            raise Reject(step, "not_yet_valid_not_before")
        if now > parse_time(validity["not_after"]):
            raise Reject(step, "expired_not_after")

    # step 7 -----------------------------------------------------------------
    @staticmethod
    def check_constraint_value_shapes(constraints: dict, step: int) -> None:
        for ctype, c in constraints.items():
            if not isinstance(c, dict):
                if ctype in RECOGNIZED_CONSTRAINTS:
                    raise Reject(step, "constraint_unevaluable", ctype)
                raise Reject(step, "unrecognized_required_constraint", ctype)

    @classmethod
    def check_constraints(cls, aae: dict, action_ctx: dict, step: int = 7) -> None:
        constraints = aae.get("constraints", {})
        cls.check_constraint_value_shapes(constraints, step)
        for ctype, c in constraints.items():
            required = c.get("required", True) is not False
            if ctype not in RECOGNIZED_CONSTRAINTS:
                if required:
                    raise Reject(step, "unrecognized_required_constraint", ctype)
                continue
            if ctype == "max_transaction_value":
                amount = action_ctx.get("amount")
                if not _is_number(amount) or not _is_number(c.get("value")) \
                        or not isinstance(c.get("currency"), str):
                    if required:
                        raise Reject(step, "constraint_unevaluable", ctype)
                    continue
                if action_ctx.get("currency") != c["currency"]:
                    raise Reject(step, "currency_mismatch",
                                 f"request {action_ctx.get('currency')!r}, constraint {c['currency']!r}")
                if amount > c["value"]:
                    raise Reject(step, "max_transaction_value_exceeded",
                                 f"amount {amount} {c['currency']} > cap {c['value']} {c['currency']}")
            elif ctype == "allowed_domains":
                domain = action_ctx.get("domain")
                allow = c.get("value")
                if not isinstance(domain, str) or not isinstance(allow, list):
                    if required:
                        raise Reject(step, "constraint_unevaluable", ctype)
                    continue
                if domain.lower() not in {d.lower() for d in allow if isinstance(d, str)}:
                    raise Reject(step, "domain_not_in_allowlist", domain)
            elif ctype == "rate_limit":
                count = action_ctx.get("rate_count")
                if not isinstance(count, int) or not isinstance(c.get("value"), int):
                    if required:
                        raise Reject(step, "constraint_unevaluable", ctype)
                    continue
                if count >= c["value"]:
                    raise Reject(step, "rate_limit_exceeded")

    # step 8 -----------------------------------------------------------------
    def check_revocation(self, vc: dict, step: int, revoked_reason: str = "revoked") -> None:
        validity = vc["credentialSubject"]["aae"]["validity"]
        if "revocation_check" not in validity:
            return
        resp = self.revocation(vc)
        if resp is None:
            raise Reject(step, "revocation_status_indeterminate")
        if resp.get("http_status", 200) >= 500 or resp.get("unparseable"):
            raise Reject(step, "revocation_status_indeterminate")
        if resp.get("revoked") is True:
            raise Reject(step, revoked_reason)

    # step 9 -----------------------------------------------------------------
    @staticmethod
    def _effective_depth(vc: dict) -> int:
        deleg = vc["credentialSubject"]["aae"]["mandate"].get("delegation")
        return deleg["depth"] if deleg else 0

    @staticmethod
    def _effective_max_depth(vc: dict):
        mandate = vc["credentialSubject"]["aae"]["mandate"]
        deleg = mandate.get("delegation")
        if deleg:
            return deleg.get("max_depth")
        policy = mandate.get("delegation_policy")
        return policy.get("max_depth") if isinstance(policy, dict) else None

    @staticmethod
    def _constraint_implies(child_c, parent_c) -> bool:
        if not isinstance(child_c, dict) or not isinstance(parent_c, dict):
            return False
        if child_c.get("type") != parent_c.get("type") or child_c.get("field") != parent_c.get("field"):
            return False
        t = parent_c.get("type")
        if t == "exact":
            return child_c.get("value") == parent_c.get("value")
        if t == "enum":
            cv, pv = child_c.get("values"), parent_c.get("values")
            return isinstance(cv, list) and isinstance(pv, list) and set(cv) <= set(pv)
        if t == "range":
            lo, hi, plo, phi = (child_c.get("lo"), child_c.get("hi"),
                                parent_c.get("lo"), parent_c.get("hi"))
            return all(enforce.is_int(x) for x in (lo, hi, plo, phi)) and lo >= plo and hi <= phi
        return False

    @classmethod
    def check_grant_attenuation(cls, child_m: dict, parent_m: dict, step: int) -> None:
        cg, pg = child_m.get("grants"), parent_m.get("grants")
        if cg is None and pg is None:
            return
        if pg is not None and cg is None:
            raise Reject(step, "delegated_grants_dropped")
        if not isinstance(cg, list) or not isinstance(pg, list):
            raise Reject(step, "delegated_grant_not_covered")
        for g in cg:
            covered = False
            for p in pg:
                if not (isinstance(g, dict) and isinstance(p, dict)):
                    continue
                if g.get("action_binding") != p.get("action_binding"):
                    continue
                if DISPOSITION_ORDER.get(g.get("disposition"), -1) < DISPOSITION_ORDER.get(p.get("disposition"), 9):
                    continue
                pcs, ccs = p.get("constraints") or [], g.get("constraints") or []
                if all(any(cls._constraint_implies(cc, pc) for cc in ccs) for pc in pcs):
                    covered = True
                    break
            if not covered:
                raise Reject(step, "delegated_grant_not_covered")

    @classmethod
    def check_link(cls, child_vc: dict, parent_vc: dict, step: int = 9) -> None:
        """AAE -02 section 3 narrowing rules for one delegation link."""
        child = child_vc["credentialSubject"]["aae"]
        parent = parent_vc["credentialSubject"]["aae"]
        deleg = child["mandate"]["delegation"]
        if parent_vc["credentialSubject"]["id"] != deleg.get("delegator_did"):
            raise Reject(step, "delegator_did_mismatch")
        if parent["mandate"].get("delegation") is None:
            policy = parent["mandate"].get("delegation_policy")
            md = policy.get("max_depth") if isinstance(policy, dict) else None
            if not (isinstance(md, int) and not isinstance(md, bool) and md >= 0):
                raise Reject(step, "delegation_policy_missing")
        if not set(child["mandate"].get("actions", [])) <= set(parent["mandate"].get("actions", [])):
            raise Reject(step, "delegated_actions_not_subset")
        p_depth, p_max = cls._effective_depth(parent_vc), cls._effective_max_depth(parent_vc)
        if deleg.get("depth") != p_depth + 1:
            raise Reject(step, "delegation_depth_inconsistent")
        if not isinstance(deleg.get("max_depth"), int) or (p_max is not None and deleg["max_depth"] > p_max):
            raise Reject(step, "delegation_max_depth_exceeds_parent")
        if deleg["depth"] > deleg["max_depth"]:
            raise Reject(step, "delegation_depth_exceeded")
        pc, cc = parent.get("constraints", {}), child.get("constraints", {})
        for ctype, p in pc.items():
            if p.get("required", True) is not False:
                c = cc.get(ctype)
                if c is None:
                    raise Reject(step, "required_parent_constraint_dropped", ctype)
                if c.get("required", True) is False:
                    raise Reject(step, "required_parent_constraint_downgraded", ctype)
        for ctype, c in cc.items():
            p = pc.get(ctype)
            if p is None:
                continue
            if ctype not in RECOGNIZED_CONSTRAINTS:
                if c != p:
                    raise Reject(step, "unrecognized_constraint_differs", ctype)
                continue
            if ctype in CURRENCY_VALUED and c.get("currency") != p.get("currency"):
                raise Reject(step, "delegation_currency_mismatch")
            if ctype in NUMERIC_UPPER_BOUND and not (
                    _is_number(c.get("value")) and _is_number(p.get("value")) and c["value"] <= p["value"]):
                raise Reject(step, "delegated_constraint_relaxed", ctype)
            if ctype in ALLOWLIST_CONSTRAINTS and not set(c.get("value", [])) <= set(p.get("value", [])):
                raise Reject(step, "delegated_allowlist_not_subset")
            if ctype == "rate_limit" and (c.get("window") != p.get("window")
                                          or not isinstance(c.get("value"), int)
                                          or not isinstance(p.get("value"), int)
                                          or c["value"] > p["value"]):
                raise Reject(step, "delegated_rate_limit_not_narrower")
        cv, pv = child["validity"], parent["validity"]
        if parse_time(cv["not_before"]) < parse_time(pv["not_before"]) or \
                parse_time(cv["not_after"]) > parse_time(pv["not_after"]):
            raise Reject(step, "delegated_validity_widened")
        cls.check_grant_attenuation(child["mandate"], parent["mandate"], step)

    def verify_delegation(self, presented_vc: dict, ancestor_jws: list, now: datetime,
                          step: int = 9) -> dict:
        """Returns the root AAE of the chain."""
        if not isinstance(ancestor_jws, list) or len(ancestor_jws) > MAX_ANCESTORS:
            raise Reject(step, "ancestors_unbounded")
        by_id: dict[str, tuple[str, dict]] = {}
        for jws in ancestor_jws:
            if not isinstance(jws, str):
                raise Reject(step, "ancestor_not_jws")
            header, vc, signing_did = self.verify_signature(jws, step=step)
            self.check_schema(header, vc, step=step)
            self.check_constraint_value_shapes(vc["credentialSubject"]["aae"]["constraints"], step)
            self.check_signing_authority(vc, signing_did, step=step)
            self.check_temporal(vc, now, step=step)
            self.check_revocation(vc, step=step, revoked_reason="ancestor_revoked")
            if vc["id"] in by_id:
                raise Reject(step, "ancestor_id_duplicated", vc["id"])
            by_id[vc["id"]] = (jws, vc)

        deleg = presented_vc["credentialSubject"]["aae"]["mandate"]["delegation"]
        if not isinstance(deleg, dict) or not isinstance(deleg.get("depth"), int) \
                or not isinstance(deleg.get("max_depth"), int):
            raise Reject(step, "delegation_malformed")
        if deleg["depth"] > deleg["max_depth"]:
            raise Reject(step, "delegation_depth_exceeded")

        visited = {presented_vc["id"]}
        child = presented_vc
        limit = min(MAX_CHAIN_HOPS, deleg["max_depth"])
        hops = 0
        while True:
            d = child["credentialSubject"]["aae"]["mandate"].get("delegation")
            if d is None:
                return child  # reached the root AAE
            if not isinstance(d, dict):
                raise Reject(step, "delegation_malformed")
            parent_id = d.get("delegator_aae_id")
            if parent_id in visited:
                raise Reject(step, "delegation_cycle_detected")
            if parent_id not in by_id:
                # Retrieval by delegator_aae_uri is deferred (-02 section 5.2).
                raise Reject(step, "parent_aae_not_supplied", str(parent_id))
            hops += 1
            pjws, parent = by_id[parent_id]
            pmax = self._effective_max_depth(parent)
            if isinstance(pmax, int):
                limit = min(limit, pmax)
            if hops > max(limit, 0) or hops > MAX_CHAIN_HOPS:
                raise Reject(step, "delegation_recursion_limit")
            h = d.get("delegator_aae_hash")
            if h is not None and h != jws_hash(pjws):
                raise Reject(step, "delegator_aae_hash_mismatch")
            self.check_link(child, parent, step=step)
            visited.add(parent_id)
            child = parent

    # profile check -------------------------------------------------------------
    def check_issuer_accepted(self, root_vc: dict) -> None:
        if self.accepted_issuers is not None and root_vc.get("issuer") not in self.accepted_issuers:
            raise Reject(0, "issuer_not_accepted", root_vc.get("issuer"))

    # entry points -------------------------------------------------------------
    def precheck(self, jws: str, now: datetime) -> dict:
        """Steps 1-3 only, used before a subject-binding challenge is issued."""
        header, vc, signing_did = self.verify_signature(jws, step=1)
        self.check_signing_authority(vc, signing_did, step=1)
        self.check_schema(header, vc, step=2)
        self.check_temporal(vc, now, step=3)
        if vc["credentialSubject"]["aae"]["mandate"].get("delegation") is None:
            self.check_issuer_accepted(vc)
        return vc

    def verify(self, jws: str, *, now: datetime, action: str, action_ctx: dict,
               subject_binding: Callable[[dict], None],
               ancestor_jws: list | None = None,
               transaction: dict | None = None) -> Accepted:
        """Run AAE -02 section 5 steps 1-9.

        subject_binding(vc) performs step 4 and raises Reject(4, ...) on failure.
        transaction is the section 2.2.3 transaction, evaluated when the mandate
        carries grants.
        """
        # Step 1 - signature and signing authority
        header, vc, signing_did = self.verify_signature(jws, step=1)
        self.check_signing_authority(vc, signing_did, step=1)
        # Step 2 - payload, schema, cty
        self.check_schema(header, vc, step=2)
        aae = vc["credentialSubject"]["aae"]
        # Step 3 - temporal validity
        self.check_temporal(vc, now, step=3)
        # Step 4 - subject binding
        subject_binding(vc)
        # Step 5 - single use (reserve; released if a later step rejects)
        reserved = False
        if aae["validity"].get("single_use") is True:
            if not self.single_use.reserve(vc["id"]):
                raise Reject(5, "single_use_already_consumed")
            reserved = True
        try:
            # Step 6 - action check, and grant evaluation where grants are present
            enforce_result = None
            if action not in aae["mandate"]["actions"]:
                raise Reject(6, "action_not_in_mandate", action)
            if "grants" in aae["mandate"]:
                tx = transaction if isinstance(transaction, dict) else None
                act = tx.get("action") if tx else None
                if not isinstance(act, dict) or act.get("verb") != action:
                    raise Reject(6, "grant_action_verb_mismatch",
                                 "transaction.action.verb must equal the mapped mandate action")
                enforce_result = enforce.enforce_check(aae["mandate"], tx)
                if enforce_result["verdict"] != enforce.PERMIT:
                    raise Reject(6, "grant_" + enforce_result["verdict"].lower(),
                                 enforce_result["reason"], enforce_result)
            # Step 7 - constraints
            ctx = dict(action_ctx)
            rl = aae["constraints"].get("rate_limit")
            if isinstance(rl, dict) and "rate_count" not in ctx:
                window = parse_duration(rl.get("window"))
                if window is not None:
                    ctx["rate_count"] = self.rate_limits.count(vc["id"], window, now)
            self.check_constraints(aae, ctx, step=7)
            steps = [1, 2, 3, 4, 5, 6, 7]
            # Step 8 - revocation (conditional)
            if "revocation_check" in aae["validity"]:
                self.check_revocation(vc, step=8)
                steps.append(8)
            # Step 9 - delegation chain (conditional)
            root = vc
            if aae["mandate"].get("delegation") is not None:
                root = self.verify_delegation(vc, ancestor_jws or [], now, step=9)
                steps.append(9)
            self.check_issuer_accepted(root)
        except Reject:
            if reserved:
                self.single_use.release(vc["id"])
            raise
        if isinstance(rl, dict):
            self.rate_limits.record(vc["id"], now)
        return Accepted(vc=vc, root_vc=root, last_step=steps[-1],
                        enforce_result=enforce_result, steps=steps)
