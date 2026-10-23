"""Unit tests of the advisory K-22 normative-language lint (drafting_lint).

AC-001G-04b, 04c, 04f; DEC-8 (R12); design Implementation Step 5. The lint is advisory: it returns
warnings only and never decides a draft's status (status independence is asserted in the CLI tests).
"""

from __future__ import annotations

import json

import pytest
from drafthelp import FIXTURES, mod

TABLE = json.loads((FIXTURES / "lint_cases.json").read_text(encoding="utf-8"))
CASES = {case["id"]: case for case in TABLE["cases"]}


def run(case):
    return mod("drafting_lint").lint(case["language"], "unsafe", case["text"], TABLE["rule_lines"])


def pairs(warnings):
    return sorted((w["line"], w["term"]) for w in warnings)


# AC-001G-04b / 04f: expected table (normalisation, case, EN/ZH terms, code exclusion).
@pytest.mark.parametrize("case_id", sorted(CASES))
def test_04b_04f_expected_table(case_id):
    case = CASES[case_id]
    warnings = run(case)
    assert pairs(warnings) == sorted((line, term) for line, term in case["expected"])
    for warning in warnings:
        assert warning["language"] == case["language"] and warning["part"] == "unsafe"
        assert isinstance(warning["column"], int) and warning["column"] >= 1


def test_04b_returns_advisory_warnings_only():
    warnings = run(CASES["all_en_terms"])
    assert warnings and all(set(w) == {"language", "part", "line", "column", "term"} for w in warnings)


# AC-001G-04c: a verbatim quotation of a current non-AI rule line is exempt.
def test_04c_verbatim_quotation_not_reported():
    assert run(CASES["permitted_quotation"]) == []
    lint = mod("drafting_lint")
    spaced = "#   >   MUST   NOT build SQL text   from request data."
    assert lint.lint("python", "safe", spaced, TABLE["rule_lines"]) == []
    assert pairs(lint.lint("python", "safe", "# > MUST NOT build SQL text.", TABLE["rule_lines"])) == [
        (1, "must not")
    ]


# AC-001G-04f: the widening-prose case is a documented lint miss covered only by the attestation.
def test_04f_adversarial_table_and_documented_miss():
    misses = [c for c in TABLE["cases"] if c.get("documented_miss")]
    assert [c["id"] for c in misses] == ["widening_prose_after_quotation"]
    assert run(misses[0]) == [] and "applies to all inputs" in misses[0]["text"]
    for case_id in (
        "mixed_case_must",
        "fullwidth_must",
        "zero_width_inside_term",
        "zh_non_hits",
        "fenced_code_in_comment",
    ):
        assert case_id in CASES


# DEC-8 (R12): greedy lexicon segmentation; no single-character 应.
def test_dec8_zh_fixtures():
    lint = mod("drafting_lint")

    def hits(text):
        return [w["term"] for w in lint.lint("python", "safe", "# " + text, [])]

    assert hits("响应该请求") == [] and hits("应用") == []
    assert hits("应当") == ["应当"] and hits("必须") == ["必须"] and hits("应") == []
