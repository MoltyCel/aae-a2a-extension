# Derived from examples/enforce-verify.py in MoltyCel/aae-conformance-vectors
# (commit 2f117799c604f258e67d5c13d69fea63881bdae0),
# Copyright (c) 2026 CryptoKRI GmbH, Zurich (MolTrust), Apache License 2.0.
# Modified: reduced to the grant-evaluation kernel (enforce_check); the
# ratification part and the vector harness are not included; the exact and
# action_binding comparisons use hmac.compare_digest (constant time, -02 2.2.3/2.5.1).
"""Grant evaluation kernel of AAE -02 sections 2.2.1-2.2.3, 2.5 and 6.1.

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

ENFORCE_VERSION = "3.0"

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
