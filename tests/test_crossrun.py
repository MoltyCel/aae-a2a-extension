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
    flat = [o for r in results for o in (r["attempts"] if "attempts" in r else [r])]
    tasks = [r for r in flat if r.get("task_id")]
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
    files = sorted(p for p in (ROOT / "crossruns").glob("*.json") if not p.name.startswith("TEMPLATE"))
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


# --- offline receiver runs (CROSSRUN.md 6.1) ----------------------------------------

def _offline(results):
    doc = _doc(results)
    del doc["client"], doc["server"]
    doc.update({"form": "offline",
                "receiver": {"implementation": "receiver", "version": "1.0",
                             "content_sha256": "sha256:" + "a" * 64},
                "audience": crossrun.OFFLINE_AUDIENCE,
                "evaluation_instant": "2026-10-30T20:15:00Z",
                "inventions": [{"what": "task ids", "choice": "uuid5 of the case id"}]})
    return doc


def test_offline_run_validates(env):
    spec, digest = _cases()
    assert crossrun.check_result(_offline(_reference_results(env)), spec, digest) == []


def test_offline_run_needs_its_members_and_every_case(env):
    spec, digest = _cases()
    doc = _offline(_reference_results(env))
    doc["cases"][6] = {"id": doc["cases"][6]["id"], "result": "skipped"}
    doc["summary"] = crossrun.summarize(doc["cases"])
    doc["receiver"] = {"implementation": "receiver", "version": "1.0"}
    doc["audience"] = "https://elsewhere.example/a2a"
    doc["inventions"] = None
    errs = crossrun.check_result(doc, spec, digest)
    assert "XR-07 is required and was skipped" in errs
    assert "receiver needs a commit or a content_sha256" in errs
    assert f"audience is not {crossrun.OFFLINE_AUDIENCE}" in errs
    assert any(e.startswith("inventions") for e in errs)


def test_offline_template_has_the_members_of_an_offline_file(env):
    template = json.loads((ROOT / "crossruns" / "TEMPLATE-offline.json").read_text())
    doc = _offline(_reference_results(env))
    assert set(template) == set(doc)
    assert set(doc["receiver"]) <= set(template["receiver"])


# --- pinned bundle and the retry pair (CROSSRUN.md 4, 5) ----------------------------

PINNED = FIXTURES / "pinned"


def test_pinned_bundle_rebuilds_byte_for_byte(tmp_path):
    from aae_a2a import pinned
    pinned.build(tmp_path)
    for p in sorted(PINNED.rglob("*")):
        if p.is_file():
            assert (tmp_path / p.relative_to(PINNED)).read_bytes() == p.read_bytes(), p.name
    assert sorted(q.relative_to(tmp_path) for q in tmp_path.rglob("*") if q.is_file()) == \
        sorted(q.relative_to(PINNED) for q in PINNED.rglob("*") if q.is_file())


def test_pinned_manifest_covers_every_file():
    from aae_a2a import pinned
    assert pinned.verify_manifest(PINNED) == []


def test_pinned_authorization_is_separate_from_admission():
    """Every attempt is a valid authorization, the second of XR-20 included."""
    from aae_a2a import pinned
    bundle = pinned.load(PINNED)
    for case in bundle["cases"]:
        for att in case["attempts"]:
            if "authorization" in att["expect"]:
                assert pinned.authorization(PINNED, case, att) == att["expect"]["authorization"], \
                    (case["id"], att["attempt"])
    xr20 = next(c for c in bundle["cases"] if c["id"] == "XR-20")
    assert [a["expect"]["admission"]["admitted"] for a in xr20["attempts"]] == [True, False]


def test_pinned_bytes_give_the_expected_results_with_a_fixed_clock():
    from aae_a2a import pinned
    from aae_a2a.server import create_supplier_app
    bundle = pinned.load(PINNED)
    res = pinned.resolver(PINNED)
    at = pinned.VERIFY_AT
    app, _card, _ex = create_supplier_app(BASE_URL, resolver=res,
                                          accepted_issuers=bundle["params"]["accepted_issuers"],
                                          clock=lambda: at, binding=pinned.pinned_binding(res),
                                          audience=bundle["params"]["audience"])
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    results = run(crossrun.run_pinned(BASE_URL, PINNED, httpx_client=client))
    assert [(r["id"], r["result"]) for r in results] == [("XR-01", "pass"), ("XR-06", "pass"),
                                                         ("XR-20", "pass")], results


def test_pinned_cases_agree_with_cases_json():
    from aae_a2a import pinned
    spec, _ = _cases()
    by_id = {c["id"]: c for c in spec["cases"]}
    for case in pinned.load(PINNED)["cases"]:
        live = by_id[case["id"]]
        assert case["request_part"] == live["request_part"]
        exp = live["expect"]["attempts"] if live["expect"]["kind"] == "retry" else [live["expect"]]
        assert [a["expect"] for a in case["attempts"]] == exp, case["id"]


def test_crossrun_md_links_resolve_in_this_commit():
    import re
    text = (ROOT / "CROSSRUN.md").read_text()
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
        if not target.startswith("http"):
            assert (ROOT / target).exists(), target
