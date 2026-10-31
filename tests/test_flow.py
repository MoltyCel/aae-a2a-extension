"""End-to-end tests over the A2A JSON-RPC binding (in-process ASGI transport)."""
from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from a2a.types import TaskState
from a2a.utils.errors import ExtensionSupportRequiredError, InvalidParamsError

from aae_a2a import enforce
from aae_a2a.buyer import task_result
from aae_a2a.challenge import utc_now
from aae_a2a.constants import EXTENSION_URI
from aae_a2a.jose import sign_compact
from aae_a2a.testkeys import (buyer_constraints, buyer_mandate, demo_key, did_of,
                              issue_buyer_aae, kid_of, make_vc, sign_aae)

from .conftest import BASE_URL, DOMAINS, run

ORDER_OK = {"amount": 120, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}
ORDER_BIG = {"amount": 900, "currency": "EUR"}


def rejected_at(task, step: int, reason: str | None = None) -> dict:
    assert task.status.state == TaskState.TASK_STATE_REJECTED
    res = task_result(task)
    assert res["verdict"] == "REJECT"
    assert int(res["step"]) == step, res
    if reason is not None:
        assert res["reason_code"] == reason, res
    return res


async def _order(env, aae, tx=ORDER_OK, name="buyer", **kw):
    buyer = await env.discovered(name)
    return await buyer.request("place-order", tx, aae=aae, **kw)


# --- the three demo cases -----------------------------------------------------------

def test_within_mandate_completes(env):
    task = run(_order(env, issue_buyer_aae(utc_now(), DOMAINS)))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    res = task_result(task)
    assert res["verdict"] == "ACCEPT"
    assert [int(s) for s in res["steps_passed"]] == [1, 2, 3, 4, 5, 6, 7]
    assert res["subject"] == did_of("buyer") and res["action"] == "pay"
    assert len(task.artifacts) == 1


def test_over_cap_rejected_at_step_7(env):
    task = run(_order(env, issue_buyer_aae(utc_now(), DOMAINS), tx=ORDER_BIG))
    rejected_at(task, 7, "max_transaction_value_exceeded")
    assert not task.artifacts


def test_extension_not_activated(env):
    with pytest.raises(ExtensionSupportRequiredError) as ei:
        run(_order(env, issue_buyer_aae(utc_now(), DOMAINS), activate=False))
    assert ei.value.data["extension"] == EXTENSION_URI


def test_missing_aae(env):
    with pytest.raises(InvalidParamsError) as ei:
        run(_order(env, None))
    assert ei.value.data["reason_code"] == "aae_missing"


def test_forged_aae_rejected_at_step_1(env):
    now = utc_now()
    vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"), mandate=buyer_mandate(),
                 constraints=buyer_constraints(DOMAINS), not_before=now - timedelta(minutes=1),
                 not_after=now + timedelta(hours=1))
    forged = sign_compact({"alg": "EdDSA", "cty": "aae+json", "kid": kid_of("issuer")}, vc,
                          demo_key("mallory"))
    rejected_at(run(_order(env, forged)), 1, "invalid_signature")


# --- further negative cases ------------------------------------------------------------

def test_expired_aae_rejected_at_step_3(env):
    now = utc_now()
    aae = issue_buyer_aae(now, DOMAINS, not_before=now - timedelta(hours=2),
                          not_after=now - timedelta(hours=1))
    rejected_at(run(_order(env, aae)), 3, "expired_not_after")


def test_wrong_cty_rejected_at_step_2(env):
    now = utc_now()
    vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"), mandate=buyer_mandate(),
                 constraints=buyer_constraints(DOMAINS), not_before=now - timedelta(minutes=1),
                 not_after=now + timedelta(hours=1))
    rejected_at(run(_order(env, sign_aae(vc, "issuer", cty="vc+jwt"))), 2, "cty_not_aae_json")


def test_subject_mismatch_rejected_at_step_4(env):
    # The AAE names another agent; the buyer can only prove control of its own DID.
    aae = issue_buyer_aae(utc_now(), DOMAINS, subject=did_of("other-agent"))
    rejected_at(run(_order(env, aae)), 4, "subject_mismatch")


def test_challenge_signed_with_wrong_key_rejected_at_step_4(env):
    aae = issue_buyer_aae(utc_now(), DOMAINS)

    def respond(challenge, _aae_id):
        payload = {**challenge, "iat": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")}
        return sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, payload, demo_key("mallory"))

    rejected_at(run(_order(env, aae, respond=respond)), 4, "challenge_signature_invalid")


def test_challenge_response_from_other_task_rejected(env):
    aae = issue_buyer_aae(utc_now(), DOMAINS)
    captured = {}

    async def scenario():
        buyer = await env.discovered()

        def capture(challenge, aae_id):
            captured["r"] = buyer.answer_challenge(challenge, aae_id)
            return captured["r"]

        first = await buyer.request("place-order", ORDER_OK, aae=aae, respond=capture)
        assert first.status.state == TaskState.TASK_STATE_COMPLETED
        return await buyer.request("place-order", ORDER_OK, aae=aae,
                                   respond=lambda _c, _i: captured["r"])

    rejected_at(run(scenario()), 4, "nonce_not_issued_for_task")


def test_action_not_in_mandate_rejected_at_step_6(env):
    mandate = {**buyer_mandate(), "actions": ["read"]}
    aae = issue_buyer_aae(utc_now(), DOMAINS, mandate=mandate)
    rejected_at(run(_order(env, aae)), 6, "action_not_in_mandate")


def test_single_use_replay_rejected_at_step_5(env):
    aae = issue_buyer_aae(utc_now(), DOMAINS, single_use=True)

    async def scenario():
        first = await _order(env, aae)
        assert first.status.state == TaskState.TASK_STATE_COMPLETED
        return await _order(env, aae)

    rejected_at(run(scenario()), 5, "single_use_already_consumed")


def test_single_use_not_consumed_by_rejected_presentation(env):
    aae = issue_buyer_aae(utc_now(), DOMAINS, single_use=True)

    async def scenario():
        rejected_at(await _order(env, aae, tx=ORDER_BIG), 7)
        return await _order(env, aae)

    assert run(scenario()).status.state == TaskState.TASK_STATE_COMPLETED


def test_domain_not_allowed_rejected_at_step_7(env):
    aae = issue_buyer_aae(utc_now(), ["other-supplier.example"])
    rejected_at(run(_order(env, aae)), 7, "domain_not_in_allowlist")


def test_revocation_check_fails_closed_at_step_8(env):
    aae = issue_buyer_aae(utc_now(), DOMAINS, extra_validity={
        "revocation_check": "https://registry.example/aae/revocation/{id}"})
    rejected_at(run(_order(env, aae)), 8, "revocation_status_indeterminate")


def test_issuer_not_accepted(env):
    now = utc_now()
    vc = make_vc(subject=did_of("buyer"), issuer=did_of("buyer"), mandate=buyer_mandate(),
                 constraints=buyer_constraints(DOMAINS), not_before=now - timedelta(minutes=1),
                 not_after=now + timedelta(hours=1))
    rejected_at(run(_order(env, sign_aae(vc, "buyer"))), 0, "issuer_not_accepted")


def test_unknown_skill_rejected(env):
    async def scenario():
        buyer = await env.discovered()
        return await buyer.request("refund", ORDER_OK, aae=issue_buyer_aae(utc_now(), DOMAINS))

    rejected_at(run(scenario()), 0, "skill_not_gated")


def test_response_echoes_activated_extension(env):
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app),
                                     base_url=BASE_URL) as c:
            r = await c.post("/a2a/jsonrpc", headers={"A2A-Extensions": EXTENSION_URI},
                             json={"jsonrpc": "2.0", "id": 1, "method": "GetTask",
                                   "params": {"id": "does-not-exist"}})
            return r

    r = run(scenario())
    assert r.headers.get("A2A-Extensions") == EXTENSION_URI


# --- delegation chain (step 9) -----------------------------------------------------------

def _chain(now, parent_policy=1):
    root_vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"),
                      mandate={**buyer_mandate(), "delegation_policy": {"max_depth": parent_policy}},
                      constraints=buyer_constraints(DOMAINS),
                      not_before=now - timedelta(minutes=5), not_after=now + timedelta(hours=2))
    root = sign_aae(root_vc, "issuer")
    child_vc = make_vc(subject=did_of("buyer-sub"), issuer=did_of("buyer"),
                       mandate={"actions": ["pay"], "purpose": "Re-order paper",
                                "delegation": {"delegator_did": did_of("buyer"),
                                               "delegator_aae_id": root_vc["id"],
                                               "depth": 1, "max_depth": 1}},
                       constraints={"max_transaction_value": {"value": 200, "currency": "EUR"},
                                    "allowed_domains": {"value": DOMAINS}},
                       not_before=now - timedelta(minutes=1), not_after=now + timedelta(hours=1))
    return root, sign_aae(child_vc, "buyer")


def test_delegated_aae_accepted_with_ancestors(env):
    root, child = _chain(utc_now())
    task = run(_order(env, child, name="buyer-sub", ancestor_jws=[root]))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    res = task_result(task)
    assert [int(s) for s in res["steps_passed"]][-1] == 9
    assert res["issuer"] == did_of("issuer")


def test_delegated_aae_without_parent_rejected_at_step_9(env):
    _root, child = _chain(utc_now())
    rejected_at(run(_order(env, child, name="buyer-sub")), 9, "parent_aae_not_supplied")


def test_delegated_aae_parent_without_policy_rejected_at_step_9(env):
    root, child = _chain(utc_now(), parent_policy=None)
    rejected_at(run(_order(env, child, name="buyer-sub", ancestor_jws=[root])), 9)


# --- grants (AAE -02 section 2.2) ---------------------------------------------------------

def _grant_aae(now):
    action = {"verb": "pay", "category": "office-supplies"}
    mandate = {**buyer_mandate(), "grants": [{
        "action_binding": enforce.action_binding(action),
        "type_fields": ["verb", "category"],
        "disposition": "allow",
        "constraints": [{"type": "range", "field": "amount", "lo": 0, "hi": 300},
                        {"type": "exact", "field": "currency", "value": "EUR"}],
    }]}
    return issue_buyer_aae(now, DOMAINS, mandate=mandate), action


def test_grant_permit(env):
    aae, action = _grant_aae(utc_now())
    task = run(_order(env, aae, tx={**ORDER_OK, "action": action}))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    res = task_result(task)
    assert res["enforce"]["verdict"] == "PERMIT"
    assert res["enforce"]["core_digest"].startswith("sha256:")


def test_grant_deny_rejected_at_step_6(env):
    aae, action = _grant_aae(utc_now())
    res = rejected_at(run(_order(env, aae, tx={"amount": 400, "currency": "EUR", "action": action})),
                      6, "grant_deny")
    assert res["enforce"]["verdict"] == "DENY"


def test_grant_present_but_no_action_rejected(env):
    aae, _action = _grant_aae(utc_now())
    rejected_at(run(_order(env, aae)), 6, "grant_action_verb_mismatch")


# --- reading order of steps 1 and 2 (spec 7.2) --------------------------------------

def _signed_payload(body: bytes) -> str:
    from aae_a2a.crossrun import sign_raw
    return sign_raw({"alg": "EdDSA", "cty": "aae+json", "kid": kid_of("issuer")}, body,
                    demo_key("issuer"))


def test_payload_not_json_rejected_at_step_2(env):
    rejected_at(run(_order(env, _signed_payload(b'{"issuer": '))), 2, "payload_not_json")


def test_payload_json_but_not_object_rejected_at_step_2(env):
    """Before signing authority, which reads issuer from the payload."""
    rejected_at(run(_order(env, _signed_payload(b'["did:example:issuer"]'))), 2,
                "payload_not_object")


def test_duplicate_issuer_rejected_at_step_2_not_step_1(env):
    now = utc_now()
    vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"), mandate=buyer_mandate(),
                 constraints=buyer_constraints(DOMAINS), not_before=now - timedelta(minutes=1),
                 not_after=now + timedelta(hours=1))
    import json
    body = '{"issuer":"' + did_of("other-agent") + '",' + json.dumps(vc, separators=(",", ":"))[1:]
    rejected_at(run(_order(env, _signed_payload(body.encode()))), 2, "payload_not_json")
