"""Deferred decisions (spec 7.6): a PENDING grant verdict held until a
ratification record of AAE -02 section 6.3 closes it."""
from __future__ import annotations

import pytest

from a2a.types import TaskState
from a2a.utils.errors import InvalidParamsError

from aae_a2a import enforce
from aae_a2a.buyer import task_result
from aae_a2a.challenge import utc_now
from aae_a2a.testkeys import (PRINCIPAL_DID, held_mandate, issue_buyer_aae,
                              ratification_proof)

from .conftest import DOMAINS, run

ACTION = {"verb": "pay", "category": "office-supplies"}
TX = {"action": ACTION, "amount": 120, "currency": "EUR"}


def _held_aae(single_use: bool = False):
    mandate = held_mandate(ACTION)
    return issue_buyer_aae(utc_now(), DOMAINS, mandate=mandate, single_use=single_use), mandate


async def _present(env, aae):
    buyer = await env.discovered()
    return buyer, await buyer.request("place-order", TX, aae=aae)


def test_without_the_declaration_pending_is_a_rejection_at_step_6(env):
    aae, _ = _held_aae()
    _buyer, task = run(_present(env, aae))
    res = task_result(task)
    assert task.status.state == TaskState.TASK_STATE_REJECTED
    assert (res["step"], res["reason_code"]) == (6, "grant_pending")


def test_the_card_declares_deferred_decisions(deferred_env):
    buyer = run(deferred_env.discovered())
    assert buyer.params.get("deferred_decisions") is True


def test_pending_without_a_decision_stays_held(deferred_env):
    aae, _ = _held_aae()
    _buyer, task = run(_present(deferred_env, aae))
    res = task_result(task)
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    assert res["verdict"] == "PENDING" and res["enforce"]["verdict"] == "PENDING"
    assert res["steps_passed"] == [1, 2, 3, 4, 5, 7] and res["authorities"] == [PRINCIPAL_DID]
    assert "result" not in [a.name for a in task.artifacts], "the skill ran"


def _held_then(env, decision, **proof_kw):
    aae, mandate = _held_aae(proof_kw.pop("single_use", False))

    async def go():
        buyer, task = await _present(env, aae)
        digest = task_result(task)["enforce"]["core_digest"]
        proof = ratification_proof(digest, decision, proof_kw.pop("mandate", mandate), **proof_kw)
        return task, await buyer.send_ratification(task, decision, proof)
    return run(go())


def test_ratified_approval_performs_the_held_request(deferred_env):
    held, task = _held_then(deferred_env, enforce.APPROVED)
    res = task_result(task)
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    assert res["verdict"] == "ACCEPT" and 6 in res["steps_passed"]
    assert res["ratification"]["status"] == "RATIFIED"
    assert res["ratification"]["authority"] == PRINCIPAL_DID
    assert res["enforce"]["verdict"] == "PENDING", "the held record is not edited"
    assert res["ratification"]["core"]["ratifies"] == res["enforce"]["core_digest"]
    assert res["request_digest"] == task_result(held)["request_digest"]


def test_a_stranger_does_not_close_the_hold(deferred_env):
    _held, task = _held_then(deferred_env, enforce.APPROVED, signer="mallory",
                             authority="did:example:mallory")
    res = task_result(task)
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    assert res["verdict"] == "PENDING" and res["ratification"]["status"] == "REJECTED"
    trace = res["ratification"]["core"]["trace"]
    assert [e["result"] for e in trace if e["predicate"] == "authority_in_mandate"] == ["FAIL"]


def test_after_a_rejected_ratification_a_valid_one_still_closes(deferred_env):
    aae, mandate = _held_aae()

    async def go():
        buyer, task = await _present(deferred_env, aae)
        digest = task_result(task)["enforce"]["core_digest"]
        bad = ratification_proof(digest, enforce.APPROVED, mandate, signer="mallory",
                                 authority="did:example:mallory")
        await buyer.send_ratification(task, enforce.APPROVED, bad)
        good = ratification_proof(digest, enforce.APPROVED, mandate)
        return await buyer.send_ratification(task, enforce.APPROVED, good)
    assert run(go()).status.state == TaskState.TASK_STATE_COMPLETED


def test_a_signature_by_the_right_did_with_another_key_is_rejected(deferred_env):
    _held, task = _held_then(deferred_env, enforce.APPROVED, signer="mallory")
    res = task_result(task)
    assert res["ratification"]["status"] == "REJECTED"
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED


def test_a_mandate_that_is_not_the_held_one_is_rejected(deferred_env):
    other = {**held_mandate(ACTION), "purpose": "something else"}
    _held, task = _held_then(deferred_env, enforce.APPROVED, mandate=other)
    trace = task_result(task)["ratification"]["core"]["trace"]
    assert [e["result"] for e in trace if e["predicate"] == "mandate_binding"] == ["FAIL"]


def test_ratified_disapproval_ends_the_hold_in_a_refusal(deferred_env):
    _held, task = _held_then(deferred_env, enforce.DISAPPROVED, single_use=True)
    res = task_result(task)
    assert task.status.state == TaskState.TASK_STATE_REJECTED
    assert (res["step"], res["reason_code"]) == (6, "ratification_disapproved")
    assert res["ratification"]["status"] == "RATIFIED"


def test_a_malformed_decision_is_a_protocol_error(deferred_env):
    aae, mandate = _held_aae()

    async def go():
        buyer, task = await _present(deferred_env, aae)
        await buyer.send_ratification(task, "MAYBE", {"mandate": mandate})
    with pytest.raises(InvalidParamsError):
        run(go())
