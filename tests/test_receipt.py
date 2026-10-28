"""Decision and outcome, and request_digest (spec sections 8.2, 8.3, 8.5).

An ACCEPT receipt records the authorization decision. The task's terminal state
reports what the skill did. request_digest binds both kinds of result to the
request part the server froze.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from a2a.types import TaskState

from aae_a2a.buyer import task_result
from aae_a2a.challenge import utc_now
from aae_a2a.digest import request_bytes, request_digest
from aae_a2a.server import SkillFailed, perform_skill
from aae_a2a.testkeys import issue_buyer_aae

from .conftest import DOMAINS, run

VECTORS = json.loads((Path(__file__).parent / "vectors" / "request-digest.json").read_text())

ORDER_OK = {"amount": 120, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}
ORDER_UNSTOCKED = {"amount": 80, "currency": "EUR", "items": [{"sku": "DESK-02", "qty": 1}]}
ORDER_BIG = {"amount": 900, "currency": "EUR"}


def counting_skill(env):
    calls = []

    def perform(skill, tx):
        calls.append((skill, tx))
        return perform_skill(skill, tx)
    env.executor.perform = perform
    return calls


async def _order(env, aae, tx):
    buyer = await env.discovered()
    return await buyer.request("place-order", tx, aae=aae)


def digest_of(tx, skill="place-order"):
    return request_digest({"skill": skill, "transaction": tx})


# --- the shared test vector -------------------------------------------------------

def test_vectors_match_the_implementation():
    for v in VECTORS["vectors"]:
        assert request_bytes(v["request_part"]).decode("utf-8") == v["jcs"], v["id"]
        assert request_digest(v["request_part"]) == v["request_digest"], v["id"]


def test_vectors_need_only_sha256_over_the_stated_bytes():
    # An implementer with any JCS library checks the 'jcs' line, then this.
    for v in VECTORS["vectors"]:
        assert v["request_digest"] == "sha256:" + hashlib.sha256(v["jcs"].encode()).hexdigest()
        assert len(v["request_digest"]) == 71 and v["request_digest"] == v["request_digest"].lower()


# --- the paired case --------------------------------------------------------------

def test_accepted_request_whose_skill_fails_ends_failed_with_the_receipt(env):
    calls = counting_skill(env)
    task = run(_order(env, issue_buyer_aae(utc_now(), DOMAINS), ORDER_UNSTOCKED))
    assert task.status.state == TaskState.TASK_STATE_FAILED
    res = task_result(task)
    assert res["verdict"] == "ACCEPT"
    assert [int(s) for s in res["steps_passed"]] == [1, 2, 3, 4, 5, 6, 7]
    assert res["request_digest"] == digest_of(ORDER_UNSTOCKED)
    assert len(calls) == 1, "the skill must run exactly once after acceptance"
    assert not task.artifacts


def test_request_rejected_at_step_7_never_reaches_the_skill(env):
    calls = counting_skill(env)
    task = run(_order(env, issue_buyer_aae(utc_now(), DOMAINS), ORDER_BIG))
    assert task.status.state == TaskState.TASK_STATE_REJECTED
    res = task_result(task)
    assert res["verdict"] == "REJECT" and int(res["step"]) == 7
    assert res["request_digest"] == digest_of(ORDER_BIG)
    assert calls == []


def test_the_pair_under_one_aae(env):
    """Same AAE, two requests: one decision each, and only the accepted one runs."""
    calls = counting_skill(env)
    aae = issue_buyer_aae(utc_now(), DOMAINS)

    async def scenario():
        return await _order(env, aae, ORDER_UNSTOCKED), await _order(env, aae, ORDER_BIG)

    failed, rejected = run(scenario())
    assert failed.status.state == TaskState.TASK_STATE_FAILED
    assert task_result(failed)["verdict"] == "ACCEPT"
    assert rejected.status.state == TaskState.TASK_STATE_REJECTED
    assert [tx for _skill, tx in calls] == [ORDER_UNSTOCKED]


def test_no_rejection_invokes_the_skill(env):
    calls = counting_skill(env)
    now = utc_now()

    async def scenario():
        buyer = await env.discovered()
        tasks = [await buyer.request("place-order", ORDER_BIG, aae=issue_buyer_aae(now, DOMAINS)),
                 await buyer.request("place-order", ORDER_OK,
                                     aae=issue_buyer_aae(now, ["other.example"])),
                 await buyer.request("place-order", ORDER_OK,
                                     aae=issue_buyer_aae(now, DOMAINS, subject="did:example:x"))]
        return tasks

    tasks = run(scenario())
    assert all(t.status.state == TaskState.TASK_STATE_REJECTED for t in tasks)
    assert calls == []


def test_a_skill_failure_is_not_a_rejection():
    try:
        perform_skill("place-order", ORDER_UNSTOCKED)
    except SkillFailed as exc:
        assert "DESK-02" in exc.reason
    else:
        raise AssertionError("an unstocked item must fail the skill")


# --- request_digest ---------------------------------------------------------------

def test_two_transactions_under_the_same_aae_and_skill_have_different_digests(env):
    aae = issue_buyer_aae(utc_now(), DOMAINS)
    other = {**ORDER_OK, "amount": 121}

    async def scenario():
        return await _order(env, aae, ORDER_OK), await _order(env, aae, other)

    a, b = run(scenario())
    ra, rb = task_result(a), task_result(b)
    assert ra["aae_id"] == rb["aae_id"] and ra["skill"] == rb["skill"]
    assert ra["request_digest"] != rb["request_digest"]


def test_identical_requests_share_a_digest_and_differ_by_task_id(env):
    """The digest identifies content. The task id identifies the execution."""
    aae = issue_buyer_aae(utc_now(), DOMAINS)

    async def scenario():
        return await _order(env, aae, ORDER_OK), await _order(env, aae, ORDER_OK)

    a, b = run(scenario())
    assert task_result(a)["request_digest"] == task_result(b)["request_digest"]
    assert a.id != b.id


def test_digest_recomputed_from_the_request_matches_the_receipt(env):
    """The request crosses protobuf, which turns 120 into 120.0; the server
    maps it back (6.4) and JCS writes both the same way, so the buyer's own
    copy of the request reproduces the server's digest."""
    task = run(_order(env, issue_buyer_aae(utc_now(), DOMAINS), ORDER_OK))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    res = task_result(task)
    assert res["request_digest"] == digest_of(ORDER_OK)
    assert res["request_digest"] == VECTORS["vectors"][0]["request_digest"]


def test_digest_does_not_depend_on_member_order_or_integral_doubles():
    a = {"skill": "place-order", "transaction": {"amount": 120, "currency": "EUR"}}
    b = {"transaction": {"currency": "EUR", "amount": 120.0}, "skill": "place-order"}
    assert request_digest(a) == request_digest(b)


def test_digest_input_is_exactly_the_request_part():
    for bad in ({"skill": "x"}, {"skill": "x", "transaction": {}, "nonce": "n"}):
        try:
            request_digest(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")


# --- the spec text carries the same values ------------------------------------------

SPEC = (Path(__file__).parents[1] / "spec" / "aae-a2a-extension-v1.md").read_text()


def test_appendix_b_matches_the_vector_file():
    appendix = SPEC[SPEC.index("## Appendix B."):]
    for v in VECTORS["vectors"]:
        assert v["jcs"] in appendix and v["request_digest"] in appendix, v["id"]


def test_the_examples_in_sections_8_2_and_8_3_recompute():
    assert digest_of({"amount": 900, "currency": "EUR"}) in SPEC
    assert digest_of(ORDER_UNSTOCKED) in SPEC
