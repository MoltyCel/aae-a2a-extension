"""CROSSRUN.md Section 3 states the base mandate as literal values.

The document used to point at `aae_a2a/testkeys.py` `buyer_mandate()` instead of
naming the values. Spelling them out only helps an outside implementer while the
text and the code say the same thing, so this test binds the two together: every
value of the base mandate must appear verbatim in Section 3, and no reference to
testkeys.py may come back.
"""

import pathlib
import re

from aae_a2a.testkeys import buyer_mandate

CROSSRUN = pathlib.Path(__file__).resolve().parent.parent / "CROSSRUN.md"


def _section_3() -> str:
    text = CROSSRUN.read_text(encoding="utf-8")
    start = re.search(r"^## 3\.", text, re.MULTILINE)
    assert start, "CROSSRUN.md has no Section 3"
    end = re.search(r"^## 4\.", text[start.end():], re.MULTILINE)
    return text[start.start():start.end() + end.start()] if end else text[start.start():]


def test_section_3_states_purpose_scope_and_principal_did() -> None:
    section = _section_3()
    mandate = buyer_mandate()
    for field in ("purpose", "scope", "principal_did"):
        value = mandate[field]
        assert f'`"{value}"`' in " ".join(section.split()), (
            f"CROSSRUN.md Section 3 does not state {field} as the literal "
            f'"{value}" that aae_a2a/testkeys.py buyer_mandate() returns'
        )


def test_crossrun_md_does_not_point_at_testkeys() -> None:
    text = CROSSRUN.read_text(encoding="utf-8")
    assert "testkeys" not in text, (
        "CROSSRUN.md refers to aae_a2a/testkeys.py again; Section 3 is meant to "
        "stand on its own for a reader outside this repository"
    )
