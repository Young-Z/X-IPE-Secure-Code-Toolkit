"""FEATURE-002-G: the appended Guard skill section (AC-002G-01f, 01h, 01i, 07k skill text)."""

from __future__ import annotations

import hashlib
import re

from conftest import SCRIPTS, TOOLKIT_ROOT

SKILL = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-guard" / "SKILL.md"
# Rebaselined (DAO-005, FEATURE-002-F): 002-F changed Guard skill bytes before the former offset 12017
# (step 3 methods line, step 5 Adapters line and the inserted step 5c), so the prefix before 002-G's
# section moved; was 12017 / cdbfc5bc9c312604641380feff7f8e704a158c97701bacfad7cd4927fd1da292.
DELIVERED_SIZE = 16160
DELIVERED_SHA256 = "e24862a3750071d772d6ae6adda5dae832510da4e61f73c15ef9431167083b73"
DELIVERED_SKILL_TESTS = {
    "tests/guard/test_guard_skill.py": "4999c6b4b570ff63246b001edd6c7c7c1f919b23a1e9c264d8259e7453e3e657",
    "tests/copilot/test_copilot_skill.py": "3025db4b2d09294725698988fabf4a8be0dfd21c5027891eada6764de9a6bc24",
    "tests/test_skill_skeletons.py": "c517fad1b9e78d48e2a904dbab127074a0a210c2da94df382f77c16ac3f954a8",
}


def _section() -> str:
    raw = SKILL.read_bytes()
    return raw[DELIVERED_SIZE:].decode("utf-8")


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def test_01f_comparing_section_rules():
    text = _norm(_section())
    assert "compare only when the user explicitly asks to compare two guard reports and names both" in text
    assert "when either report, or which one is earlier, is unclear, ask the user" in text
    assert "list the report file names of `reports/guard/` only" in text
    assert "never open their content to choose" in text
    assert "never list or name anything in `comparisons/`" in text
    assert "never select the reports for the user" in text
    assert "never start a scan, re-verification or fix because of a comparison" in text
    assert 'never say "fixed"' in text and '"not observed this time" does not mean fixed' in text
    assert "never cite a comparison as evidence of a check, a pass or a verdict" in text
    assert "secure-code guard compare --project . --earlier <id-or-file> --later <id-or-file> --json" in text


# maintenance (DAO-023/024): scoped to the 002-G section so later appended sections don't break AC-002G-01h
def test_01h_only_added_section():
    raw = SKILL.read_bytes()
    assert hashlib.sha256(raw[:DELIVERED_SIZE]).hexdigest() == DELIVERED_SHA256
    suffix = _section()
    assert suffix.startswith("\n## Comparing two reports\n")
    heading = "\n## Comparing two reports\n"
    later = re.search(r"(?m)^#{1,2} ", suffix[len(heading) :])
    own = suffix if later is None else suffix[: len(heading) + later.start()]
    assert len(re.findall(r"(?m)^#{1,6} ", own)) == 1
    assert set(re.findall(r"secure-code guard ([a-z-]+)", own)) == {"compare", "cleanup"}


def test_01i_delivered_skill_tests_unchanged():
    for rel, digest in DELIVERED_SKILL_TESTS.items():
        assert hashlib.sha256((SCRIPTS / rel).read_bytes()).hexdigest() == digest, rel


def test_07k_skill_states_pair_validity():
    text = _norm(_section())
    assert (
        "a comparison is valid only as a pair whose markdown footer (`guard-comparison-sha256`) equals the "
        "sha-256 of the structured comparison; a lone or mismatched file is not a comparison" in text
    )
    assert "`secure-code guard cleanup` does not touch them" in text
