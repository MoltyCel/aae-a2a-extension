"""Run the section 5 verifier against MoltyCel/aae-conformance-vectors.

The vectors are not vendored. Point AAE_VECTORS_DIR at a checkout of the
repository (CI clones it at a pinned commit); the test is skipped otherwise.

The 15 native vectors carry section_ref -00, and their expected
verification_step uses the section 5 step numbering, which -02 keeps. Facts a
static vector cannot reproduce (step 4, revocation responses, consumed ids)
come from each vector's context object, as in the upstream reference verifier.
The enforce vectors are run against the grant-evaluation kernel.
"""
from __future__ import annotations

import glob
import json
import os

import pytest

from aae_a2a import enforce
from aae_a2a.didres import LocalDidResolver
from aae_a2a.verifier import AaeVerifier, Reject, SingleUseStore, parse_time

VECTORS = os.environ.get("AAE_VECTORS_DIR")
pytestmark = pytest.mark.skipif(not VECTORS, reason="AAE_VECTORS_DIR not set")


def _native():
    return sorted(glob.glob(os.path.join(VECTORS or "", "vectors", "*.json")))


def _enforce():
    return sorted(glob.glob(os.path.join(VECTORS or "", "vectors", "enforce", "*.json")))


def run_vector(vector: dict) -> tuple[str, int]:
    ctx = vector["input"]["context"]
    resolver = LocalDidResolver.from_directory(os.path.join(VECTORS, "testkeys", "did-documents"))
    responses = ctx.get("revocation_responses") or {}
    verifier = AaeVerifier(resolver,
                           revocation=lambda vc: responses.get(vc["id"]),
                           single_use=SingleUseStore(ctx.get("consumed_ids")))

    def binding(_vc):
        if not (ctx.get("subject_binding") or {}).get("challenge_response_valid", False):
            raise Reject(4, "subject_binding_failed")

    try:
        acc = verifier.verify(vector["input"]["secured_aae"],
                              now=parse_time(ctx["current_time"]),
                              action=ctx.get("requested_action"),
                              action_ctx=ctx.get("action_context", {}),
                              subject_binding=binding,
                              ancestor_jws=ctx.get("delegation_chain", []))
        return "ACCEPT", acc.last_step
    except Reject as r:
        return "REJECT", r.step


@pytest.mark.parametrize("path", _native(), ids=os.path.basename)
def test_native_vector(path):
    with open(path, encoding="utf-8") as fh:
        vector = json.load(fh)
    result, step = run_vector(vector)
    assert (result, step) == (vector["expected"]["result"], vector["expected"]["verification_step"])


@pytest.mark.parametrize("path", [p for p in _enforce()], ids=os.path.basename)
def test_enforce_vector(path):
    with open(path, encoding="utf-8") as fh:
        vector = json.load(fh)
    if vector.get("kernel") != "enforce_check":
        pytest.skip("ratification vectors are outside this profile")
    inp, exp = vector["input"], vector["expected"]
    got = enforce.enforce_check(inp.get("mandate"), inp.get("transaction"), inp.get("prev_core_digest"))
    assert got["verdict"] == exp["verdict"]
    assert got["core_digest"] == exp["core_digest"]
