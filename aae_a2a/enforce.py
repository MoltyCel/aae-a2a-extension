# Derived from examples/enforce-verify.py in MoltyCel/aae-conformance-vectors
# (commit 2f117799c604f258e67d5c13d69fea63881bdae0),
# Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust), Apache License 2.0.
# Modified: the grant-evaluation kernel (enforce_check) and the ratification
# kernel (ratify, -02 6.3/6.4); the vector harness is not included; the exact and
# action_binding comparisons and the authority DID comparison use
# hmac.compare_digest (constant time, -02 2.2.3/2.5.1/6.4), and an authority given
# as a DID URL with a path, query or fragment is not matched (-02 6.4).
"""Grant evaluation and ratification kernels of AAE -02 sections 2.2.1-2.2.3,
2.5, 6.1, 6.3 and 6.4.

Stateless and clock-free by construction (AAE -02 section 2.5.3).
"""
from __future__ import annotations

import hashlib
import hmac

import jcs

PERMIT, DENY, PENDING = "PERMIT", "DENY", "PENDING"
PASS, FAIL = "PASS", "FAIL"

TAG_ACTION = b"aae:enforce-action:v1\x00"
TAG_MANDATE = b"aae:enforce-mandate:v1\x00"
TAG_TRANSACTION = b"aae:enforce-transaction:v1\x00"
TAG_CORE = b"aae:enforce-core:v1\x00"
TAG_RATIFY_STATEMENT = b"aae:enforce-ratify-statement:v1\x00"
TAG_RATIFY_CORE = b"aae:enforce-ratify-core:v1\x00"

ENFORCE_VERSION = "3.0"
RATIFY_VERSION = "3.0"
APPROVED, DISAPPROVED = "APPROVED", "DISAPPROVED"
RATIFIED, REJECTED = "RATIFIED", "REJECTED"
MAX_RATIFICATION_AUTHORITIES = 64

DISPOSITIONS = ("allow", "hold", "forbid")
CONSTRAINT_TYPES = ("exact", "enum", "range")
TYPE_FIELD_VERB = "verb"

MAX_GRANTS = 256
MAX_CONSTRAINTS_PER_GRANT = 64
MAX_ENUM_MEMBERS = 512
MAX_TYPE_FIELDS = 32
MAX_FIELD_DEPTH = 8
MAX_ABS_INT = 10 ** 15

DIGESTED_PRED_FIELDS = ("predicate", "field", "value", "bound", "result")


def digest(tag: bytes, obj) -> str | None:
    try:
        payload = jcs.canonicalize(obj)
    except Exception:
        return None
    return "sha256:" + hashlib.sha256(tag + payload).hexdigest()


def pred(predicate, field, result, reason, value=None, bound=None) -> dict:
    return {"predicate": predicate, "field": field, "value": value,
            "bound": bound, "result": result, "reason": reason}


def trace_for_core(trace) -> list:
    return [{k: e[k] for k in DIGESTED_PRED_FIELDS} for e in trace]


def resolve_field(transaction, path):
    if not isinstance(path, str) or not path:
        return False, None
    segments = path.split(".")
    if len(segments) > MAX_FIELD_DEPTH or any(s == "" for s in segments):
        return False, None
    cur = transaction
    for seg in segments:
        if not isinstance(cur, dict) or seg not in cur:
            return False, None
        cur = cur[seg]
    return True, cur


def is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and abs(x) <= MAX_ABS_INT


def eval_exact(c, transaction):
    field, expected = c.get("field"), c.get("value")
    found, actual = resolve_field(transaction, field)
    if not isinstance(expected, str):
        return pred("exact", field, FAIL, "constraint value is not a string", None, expected)
    if not found:
        return pred("exact", field, FAIL, "field not present in transaction", None, expected)
    if not isinstance(actual, str):
        return pred("exact", field, FAIL, "transaction value is not a string", actual, expected)
    if hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8")):
        return pred("exact", field, PASS, "exact match", actual, expected)
    return pred("exact", field, FAIL, "value does not match exactly", actual, expected)


def eval_enum(c, transaction):
    field, members = c.get("field"), c.get("values")
    found, actual = resolve_field(transaction, field)
    if not isinstance(members, list) or not members:
        return pred("enum", field, FAIL, "constraint values is not a non-empty array", None, members)
    if len(members) > MAX_ENUM_MEMBERS:
        return pred("enum", field, FAIL, "constraint values exceeds member cap", None, len(members))
    if not found:
        return pred("enum", field, FAIL, "field not present in transaction", None, members)
    if not isinstance(actual, str):
        return pred("enum", field, FAIL, "transaction value is not a string", actual, members)
    hits = sum(1 for m in members if actual == m)  # every member compared, no short circuit
    if hits:
        return pred("enum", field, PASS, "value in enumeration", actual, members)
    return pred("enum", field, FAIL, "value not in enumeration", actual, members)


def eval_range(c, transaction):
    field, lo, hi = c.get("field"), c.get("lo"), c.get("hi")
    bound = {"lo": lo, "hi": hi}
    found, actual = resolve_field(transaction, field)
    if not is_int(lo) or not is_int(hi):
        return pred("range", field, FAIL, "constraint bounds are not bounded integers", None, bound)
    if lo > hi:
        return pred("range", field, FAIL, "constraint bounds inverted (lo > hi)", None, bound)
    if not found:
        return pred("range", field, FAIL, "field not present in transaction", None, bound)
    if not is_int(actual):
        return pred("range", field, FAIL, "transaction value is not a bounded integer", actual, bound)
    if lo <= actual <= hi:
        return pred("range", field, PASS, "within range", actual, bound)
    return pred("range", field, FAIL, "outside range", actual, bound)


def eval_constraint(c, transaction):
    if not isinstance(c, dict):
        return pred("unknown", None, FAIL, "constraint is not an object")
    ctype = c.get("type")
    if ctype not in CONSTRAINT_TYPES:
        return pred(str(ctype), c.get("field"), FAIL, "unknown constraint type -> deny by default")
    return {"exact": eval_exact, "enum": eval_enum, "range": eval_range}[ctype](c, transaction)


def type_fields_ok(tf) -> bool:
    if not isinstance(tf, list) or not tf or len(tf) > MAX_TYPE_FIELDS:
        return False
    if any(not isinstance(n, str) or not n for n in tf):
        return False
    if len(set(tf)) != len(tf):
        return False
    return TYPE_FIELD_VERB in tf


def grant_shape_ok(g) -> bool:
    if not isinstance(g, dict):
        return False
    ab = g.get("action_binding")
    if not isinstance(ab, str) or len(ab) != 71 or not ab.startswith("sha256:"):
        return False
    if any(ch not in "0123456789abcdef" for ch in ab[7:]):
        return False
    if g.get("disposition") not in DISPOSITIONS:
        return False
    if not type_fields_ok(g.get("type_fields")):
        return False
    cs = g.get("constraints")
    return isinstance(cs, list) and len(cs) <= MAX_CONSTRAINTS_PER_GRANT


def mandate_problem(mandate):
    if not isinstance(mandate, dict):
        return "mandate missing or not an object"
    grants = mandate.get("grants")
    if not isinstance(grants, list) or not grants:
        return "mandate.grants missing or empty"
    if len(grants) > MAX_GRANTS:
        return "mandate.grants exceeds cap"
    for i, g in enumerate(grants):
        if not grant_shape_ok(g):
            return (f"mandate.grants[{i}] malformed "
                    f"(action_binding/disposition/type_fields/constraints)")
    return None


def type_shape_problem(action, type_fields):
    if not isinstance(action, dict):
        return "action is not an object"
    have, want = set(action.keys()), set(type_fields)
    missing, extra = sorted(want - have), sorted(have - want)
    if missing and extra:
        return (f"action fields do not match type_fields "
                f"(missing {missing}, outside the type {extra})")
    if missing:
        return f"action is missing type_fields {missing}"
    if extra:
        return f"action carries fields outside type_fields {extra}"
    return None


def enforce_check(mandate, transaction, prev_core_digest=None) -> dict:
    """AAE -02 section 2.2.3 grant evaluation with the section 2.5.3 core."""
    trace, grant_index = [], None
    problem = mandate_problem(mandate)
    tx_ok = isinstance(transaction, dict)
    act_digest = digest(TAG_ACTION, transaction.get("action")) if tx_ok else None

    if problem is not None:
        verdict, reason = DENY, problem
        trace.append(pred("mandate_present", None, FAIL, problem))
    elif not tx_ok:
        verdict, reason = DENY, "transaction missing or not an object"
        trace.append(pred("transaction_present", None, FAIL, reason))
    elif act_digest is None:
        verdict, reason = DENY, "transaction.action missing or not canonicalizable"
        trace.append(pred("action_binding", "action", FAIL, reason))
    else:
        trace.append(pred("mandate_present", None, PASS, "mandate structurally valid"))
        grants = mandate["grants"]
        action = transaction.get("action")

        typed, first_problem = [], None
        for i, g in enumerate(grants):
            p = type_shape_problem(action, g["type_fields"])
            if p is None:
                typed.append(i)
            elif first_problem is None:
                first_problem = (i, p)

        if not typed:
            i, p = first_problem
            verdict, reason = DENY, f"grant[{i}]: {p}"
            trace.append(pred("type_fields", "action", FAIL, reason,
                              sorted(action.keys()) if isinstance(action, dict) else None,
                              list(grants[i]["type_fields"])))
        else:
            trace.append(pred("type_fields", "action", PASS,
                              f"action carries exactly the type_fields of grant(s) {typed}",
                              sorted(action.keys()), list(grants[typed[0]]["type_fields"])))
            matched = [i for i in typed
                       if hmac.compare_digest(grants[i]["action_binding"], act_digest)]

            if not matched:
                verdict, reason = DENY, "unaddressed action: no grant binds this action digest"
                trace.append(pred("action_binding", "action", FAIL, reason, act_digest, None))
            else:
                trace.append(pred("action_binding", "action", PASS,
                                  f"bound by grant(s) {matched}", act_digest, act_digest))
                forbidden = [i for i in matched if grants[i]["disposition"] == "forbid"]
                if forbidden:
                    grant_index = forbidden[0]
                    verdict = DENY
                    reason = f"grant[{grant_index}] disposition=forbid"
                    trace.append(pred("disposition", None, FAIL, reason, "forbid", None))
                else:
                    verdict, reason = DENY, "no matching grant satisfied its constraints"
                    for i in matched:
                        preds = [eval_constraint(c, transaction) for c in grants[i]["constraints"]]
                        trace.extend(preds)
                        if all(p["result"] == PASS for p in preds):
                            grant_index = i
                            disp = grants[i]["disposition"]
                            verdict = PERMIT if disp == "allow" else PENDING
                            reason = (f"grant[{i}] matched, all constraints hold, "
                                      f"disposition={disp}")
                            trace.append(pred("disposition", None, PASS, reason, disp, None))
                            break

    core = {
        "enforce_version": ENFORCE_VERSION,
        "mandate_digest": digest(TAG_MANDATE, mandate),
        "transaction_digest": digest(TAG_TRANSACTION, transaction),
        "action_digest": act_digest,
        "verdict": verdict,
        "grant_index": grant_index,
        "trace": trace_for_core(trace),
        "prev_core_digest": prev_core_digest if isinstance(prev_core_digest, str) else None,
    }
    return {"verdict": verdict, "reason": reason, "grant_index": grant_index,
            "trace": trace, "core": core, "core_digest": digest(TAG_CORE, core)}


def action_binding(action) -> str | None:
    """AAE -02 section 2.2.2 action_binding for an action object."""
    return digest(TAG_ACTION, action)


# --- ratification (AAE -02 sections 6.3 and 6.4) ------------------------------------------

class RatifyError(Exception):
    """A caller error of -02 section 6.4: the question does not line up, so no
    ratification record is produced."""


def statement_bytes(prior_core_digest: str, decision: str, authority_did: str) -> bytes:
    """What an authority signs (-02 section 6.3)."""
    return TAG_RATIFY_STATEMENT + jcs.canonicalize({
        "ratify_version": RATIFY_VERSION, "ratifies": prior_core_digest,
        "decision": decision, "authority": authority_did})


def mandate_authorities(mandate) -> list[tuple[str, str, str]]:
    """(did, public_key hex, role label) for the two sources of -02 section 6.4:
    mandate.principal, then each ratification_authorities entry carrying both a
    did and a public_key, up to the first 64. The role is reported, never read."""
    if not isinstance(mandate, dict):
        return []
    out = []
    principal = mandate.get("principal")
    if isinstance(principal, dict):
        did, key = principal.get("did"), principal.get("public_key")
        if isinstance(did, str) and isinstance(key, str):
            out.append((did, key, "principal"))
    entries = mandate.get("ratification_authorities")
    for entry in (entries if isinstance(entries, list) else [])[:MAX_RATIFICATION_AUTHORITIES]:
        if not isinstance(entry, dict):
            continue
        did, key = entry.get("did"), entry.get("public_key")
        if isinstance(did, str) and isinstance(key, str):
            role = entry.get("role")
            out.append((did, key, role if isinstance(role, str) else "named_authority"))
    return out


def _same_did(a: str, b) -> bool:
    if not isinstance(b, str) or any(ch in b for ch in "/?#"):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _ed25519_verify(public_key_hex, signature_hex, message: bytes) -> bool:
    """Every decoding failure is a failed signature predicate (-02 section 6.4)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(public_key_hex, str) or not isinstance(signature_hex, str):
        return False
    try:
        raw, sig = bytes.fromhex(public_key_hex), bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(raw) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except Exception:
        return False


def ratify(prior_record, decision, authority_proof, prev_core_digest=None) -> dict:
    """The ratification record of -02 section 6.3 over prior_record {core,
    core_digest}. Raises RatifyError for a caller error (-02 section 6.4)."""
    if decision not in (APPROVED, DISAPPROVED):
        raise RatifyError(f"decision must be APPROVED or DISAPPROVED, got {decision!r}")
    if not isinstance(prior_record, dict):
        raise RatifyError("prior_record missing or not an object")
    core, claimed = prior_record.get("core"), prior_record.get("core_digest")
    if not isinstance(core, dict) or not isinstance(claimed, str):
        raise RatifyError("prior_record.core or core_digest missing")
    if digest(TAG_CORE, core) != claimed:
        raise RatifyError("prior_record.core_digest does not match its own core")
    if not isinstance(core.get("mandate_digest"), str):
        raise RatifyError("prior_record carries no mandate_digest")
    prior_verdict = core.get("verdict")
    if prior_verdict == PERMIT:
        raise RatifyError("a PERMIT is not ratifiable — there is no status to change")
    if prior_verdict not in (DENY, PENDING):
        raise RatifyError(f"prior verdict {prior_verdict!r} is not ratifiable")
    if prev_core_digest is not None and prev_core_digest != claimed:
        raise RatifyError("prev_core_digest must equal the core_digest of the record being "
                          f"ratified (ratifies {claimed}, got {prev_core_digest!r})")

    trace = [pred("prior_ratifiable", None, PASS,
                  f"prior verdict {prior_verdict} may be ratified", prior_verdict, None)]
    authority_did, status, reason = None, REJECTED, "authority not established"
    if not isinstance(authority_proof, dict):
        trace.append(pred("authority_proof", None, FAIL,
                          "authority_proof missing or not an object"))
        reason = "authority_proof missing or not an object"
    else:
        mandate = authority_proof.get("mandate")
        claimed_authority = authority_proof.get("authority")
        supplied = digest(TAG_MANDATE, mandate) if mandate is not None else None
        bound = supplied == core["mandate_digest"]
        trace.append(pred("mandate_binding", "mandate", PASS if bound else FAIL,
                          "supplied mandate is the one the prior record refers to" if bound
                          else "supplied mandate does not match prior_record.mandate_digest",
                          supplied, core["mandate_digest"]))
        if not bound:
            reason = "supplied mandate does not match the prior record"
        else:
            allowed = mandate_authorities(mandate)
            match = next((a for a in allowed if _same_did(a[0], claimed_authority)), None)
            trace.append(pred("authority_in_mandate", "authority", PASS if match else FAIL,
                              f"authority derives from mandate as {match[2]}" if match
                              else "authority is not the issuing principal and not a role "
                                   "named in the mandate",
                              claimed_authority, [d for d, _k, _r in allowed]))
            if not match:
                reason = "authority does not derive from the mandate"
            else:
                did, key_hex, role = match
                ok = _ed25519_verify(key_hex, authority_proof.get("signature"),
                                     statement_bytes(claimed, decision, did))
                trace.append(pred("authority_signature", "signature", PASS if ok else FAIL,
                                  "signature verifies against the mandate-held key" if ok
                                  else "signature does not verify against the "
                                       "mandate-held key"))
                if ok:
                    authority_did, status = did, RATIFIED
                    reason = f"ratified by {role} {did}: prior {prior_verdict} -> {decision}"
                else:
                    reason = "authority signature does not verify"
    rcore = {
        "ratify_version": RATIFY_VERSION,
        "ratifies": claimed,
        "prior_verdict": prior_verdict,
        "decision": decision,
        "status": status,
        "authority": authority_did,
        "mandate_digest": core["mandate_digest"],
        "trace": trace_for_core(trace),
        "prev_core_digest": prev_core_digest if isinstance(prev_core_digest, str) else claimed,
    }
    return {"status": status, "decision": decision, "ratifies": claimed,
            "authority": authority_did, "reason": reason, "trace": trace,
            "core": rcore, "core_digest": digest(TAG_RATIFY_CORE, rcore)}
