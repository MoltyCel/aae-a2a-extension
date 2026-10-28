"""The cross-run harness (CROSSRUN.md): case file, fixtures, the reference run
and the result-file check."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx

from aae_a2a import crossrun
from aae_a2a.digest import request_digest

from .conftest import BASE_URL, run

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "vectors" / "crossrun"
SHA = "0" * 40


def _cases():
    return crossrun.load_cases()


def test_every_expected_digest_is_that_of_the_request_part():
    spec, _ = _cases()
    for case in spec["cases"]:
        if case["expect"]["kind"] == "task":
            assert case["expect"]["request_digest"] == request_digest(case["request_part"]), case["id"]


def test_case_digests_include_the_appendix_b_vectors():
    spec, _ = _cases()
    vectors = json.loads((ROOT / "tests" / "vectors" / "request-digest.json").read_text())
    used = {c["expect"].get("request_digest") for c in spec["cases"]}
    assert {v["request_digest"] for v in vectors["vectors"]} - used == {
        "sha256:fd2490962a20b0d8223d69248ffa5f073180e791864295247ed1eed8661f48f9"}


def test_case_ids_unique_and_paired_case_present():
    spec, _ = _cases()
    ids = [c["id"] for c in spec["cases"]]
    assert len(ids) == len(set(ids))
    states = {c["expect"].get("task_state") for c in spec["cases"]}
    assert {"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_REJECTED"} <= states


def test_published_fixtures_match_the_test_keys():
    for name, doc in crossrun.fixture_documents().items():
        assert json.loads((FIXTURES / "did" / f"{name}.json").read_text()) == doc
    assert json.loads((FIXTURES / "test-keys.json").read_text()) == crossrun.fixture_keys()


def _reference_results(env):
    spec, _ = _cases()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=BASE_URL)
    return run(crossrun.run_cases(BASE_URL, spec["cases"], httpx_client=client))


def _doc(results):
    _, digest = _cases()
    return {"format": crossrun.RESULT_FORMAT, "profile": crossrun.EXTENSION_URI,
            "draft": crossrun.AAE_DRAFT, "cases_sha256": digest, "run_at": "2026-10-28T00:00:00Z",
            "participant": {"name": "test", "url": None},
            "client": {"implementation": "ref", "repository": crossrun.REFERENCE_REPO, "commit": SHA},
            "server": {"implementation": "ref", "repository": crossrun.REFERENCE_REPO, "commit": SHA},
            "cases": results, "summary": crossrun.summarize(results)}


def test_reference_supplier_passes_every_case(env):
    results = _reference_results(env)
    assert [r["result"] for r in results] == ["pass"] * len(results)
    spec, digest = _cases()
    assert crossrun.check_result(_doc(results), spec, digest) == []


def test_reference_supplier_records_each_decision(env):
    rows = []
    env.executor.observer = lambda task_id, result, state: rows.append((task_id, state, result))
    results = _reference_results(env)
    tasks = [r for r in results if r.get("task_id")]
    assert [(r["task_id"], r["task_state"]) for r in tasks] == [(t, s) for t, s, _ in rows]
    assert all(res["request_digest"] == r["request_digest"] for r, (_, _, res) in zip(tasks, rows))


def test_check_rejects_a_claim_its_observation_does_not_support(env):
    spec, digest = _cases()
    doc = _doc(_reference_results(env))
    bad = copy.deepcopy(doc)
    bad["cases"][2]["step"] = 6
    assert any("XR-03 claims pass" in e for e in crossrun.check_result(bad, spec, digest))
    bad = copy.deepcopy(doc)
    bad["cases"][5]["task_id"] = bad["cases"][0]["task_id"]
    assert any("XR-06 claims pass" in e for e in crossrun.check_result(bad, spec, digest))


def test_check_requires_commits_required_cases_and_the_case_file():
    spec, digest = _cases()
    skipped = [{"id": c["id"], "result": "skipped"} for c in spec["cases"]]
    doc = _doc(skipped)
    doc["server"]["commit"] = "main"
    errs = crossrun.check_result(doc, spec, digest)
    assert "server.commit is not a 40-character commit SHA" in errs
    assert "XR-01 is required and was skipped" in errs
    assert "XR-07 is required and was skipped" not in errs
    assert crossrun.check_result(doc, spec, "sha256:" + "1" * 64)[0].startswith("cases_sha256")


def test_reason_code_difference_is_a_note_not_a_failure():
    spec, _ = _cases()
    case = next(c for c in spec["cases"] if c["id"] == "XR-03")
    obs = {"task_state": "TASK_STATE_REJECTED", "verdict": "REJECT", "step": 7,
           "reason_code": "over_limit", "request_digest": case["expect"]["request_digest"]}
    result, notes = crossrun.evaluate(case, obs, {})
    assert result == "pass" and notes == ["reason_code over_limit != max_transaction_value_exceeded"]


def test_reported_runs_validate():
    spec, digest = _cases()
    files = sorted(p for p in (ROOT / "crossruns").glob("*.json") if p.name != "TEMPLATE.json")
    for p in files:
        assert crossrun.check_result(json.loads(p.read_text()), spec, digest) == [], p.name


def test_template_has_the_members_of_a_result_file(env):
    template = json.loads((ROOT / "crossruns" / "TEMPLATE.json").read_text())
    doc = _doc(_reference_results(env))
    assert set(template) == set(doc)
    for side in ("participant", "client", "server"):
        assert set(doc[side]) <= set(template[side])


def test_crossrun_md_lists_every_case_with_its_expected_result():
    spec, _ = _cases()
    rows = {line.split("|")[1].strip(): line for line in (ROOT / "CROSSRUN.md").read_text().splitlines()
            if line.startswith("| XR-")}
    assert list(rows) == [c["id"] for c in spec["cases"]]
    for c in spec["cases"]:
        e, row = c["expect"], rows[c["id"]]
        assert f"| {c['client_side']} |" in row
        for value in (e.get("task_state"), e.get("request_digest"), e.get("reason_code")):
            if value is not None:
                assert value in row, (c["id"], value)
