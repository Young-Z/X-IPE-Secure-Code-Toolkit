"""FEATURE-002-G: comparison wording, masking and statements (AC-002G-03c, 03e, 06c, 06d, 06e)."""

from __future__ import annotations

import json
import re

from comparehelp import (
    CANARY,
    E_ID,
    L_ID,
    build,
    compare_render,
    entry_of,
    finding,
    result,
    rich_pair,
    tv,
)

CID = "gc-20261023T120501Z-5e6f7a8b"
FORBIDDEN = re.compile(r"\b(fixed|resolved|remediated|improved)\b", re.I)


def doc_and_md(e, lv, **facts):
    cmp = {**build(e, lv, **facts), "comparison_id": CID, "created_at": "2026-10-23T12:05:01Z"}
    return cmp, compare_render.markdown(cmp, "0" * 64)


def _without_statements(text, cmp):
    for value in cmp["statements"].values():
        for form in (value, json.dumps(value, ensure_ascii=False)[1:-1], compare_render.md_text(value)):
            text = text.replace(form, "")
    return text


def test_03c_never_fixed_wording():
    e, lv = rich_pair()
    cmp, md = doc_and_md(e, lv)
    assert any(x["class"] == "not_observed_this_time" for x in cmp["entries"])
    assert not FORBIDDEN.search(_without_statements(json.dumps(cmp, ensure_ascii=False), cmp))
    assert not FORBIDDEN.search(_without_statements(md, cmp))
    paragraphs = [p for p in md.split("\n\n") if p.strip() and not p.startswith("# ")]
    assert paragraphs[0] == f"**{compare_render.md_text(cmp['statements']['not_observed_meaning'])}**"
    assert '"Not observed this time" does not mean fixed' in cmp["statements"]["not_observed_meaning"]


def test_03e_verdicts_with_reasons_no_trend():
    e = result(E_ID, verdict="fail")
    e["reasons"] = [
        {"code": "CONFIRMED_FINDING", "subject": "F1", "detail": "high, confirmed by a valid review"}
    ]
    lv = result(L_ID, verdict="pass")
    lv["reasons"] = [
        {"code": "ALL_CHECKS_SATISFIED", "subject": "ledger", "detail": "every necessary check met"}
    ]
    cmp, md = doc_and_md(e, lv)
    assert (cmp["runs"]["earlier"]["verdict"], cmp["runs"]["later"]["verdict"]) == ("fail", "pass")
    assert cmp["runs"]["earlier"]["reasons"][0]["code"] == "CONFIRMED_FINDING"
    assert "CONFIRMED_FINDING" in md and "ALL_CHECKS_SATISFIED" in md
    keys = json.dumps(cmp)
    for word in ("score", "trend", "percentage", "derived_verdict", "improvement"):
        assert f'"{word}' not in keys
    body = _without_statements(md, cmp)
    assert "%" not in body and not re.search(r"\b(trend|score|percentage)\b", body, re.I)


def test_06c_masking_and_secret_never_output():
    e = result(
        E_ID,
        findings=[
            finding("F1", line=3, title=f"Token {CANARY} in code", description=f"uses {CANARY}"),
            tv(
                "T1",
                scanner="secret",
                rule_id="aws-key",
                check="C1",
                secret={
                    "representation": "masked",
                    "length": 20,
                    "value": CANARY,
                    "nested": {"value": CANARY},
                },
            ),
        ],
    )
    lv = result(
        L_ID,
        findings=[
            finding("G1", line=3, title="Other title"),
            tv("U1", scanner="secret", rule_id="aws-key", check="C1", secret={"value": CANARY + "2"}),
        ],
    )
    from comparehelp import tv_run

    e["adapter_runs"] = [tv_run(1, scanners=("secret",))]
    lv["adapter_runs"] = [tv_run(1, scanners=("secret",))]
    cmp, md = doc_and_md(e, lv)
    text = json.dumps(cmp, ensure_ascii=False)
    assert CANARY not in text and CANARY not in md
    side = entry_of(cmp, "F1")["earlier"]
    assert side["masked"] is True and "[masked:" in side["title"] and side["masked_types"]
    assert "(masked)" in md
    assert entry_of(cmp, "F1")["later"]["finding"] == "G1"  # identity independent of titles
    assert entry_of(cmp, "T1")["later"]["finding"] == "U1"


def test_06d_acceptance_earlier_only():
    e = result(E_ID, findings=[finding("F1", line=3)], risk=("F1",))
    lv = result(L_ID, findings=[finding("G1", line=3)])
    cmp, md = doc_and_md(e, lv)
    x = entry_of(cmp, "F1")
    assert x["class"] == "still_present"
    assert x["risk_acceptance"] == {"run": "earlier", "applies_to_later": False}
    assert cmp["runs"]["earlier"]["risk_acceptances"][0]["finding"] == "F1"
    assert cmp["runs"]["later"]["risk_acceptances"] == []
    assert "accepted in the earlier run only; it does not apply to the later run" in md


def test_06e_not_evidence_statement_in_both_outputs():
    cmp, md = doc_and_md(result(E_ID), result(L_ID))
    statement = cmp["statements"]["not_evidence"]
    assert statement == (
        "This comparison is a reading aid, not verification evidence; it does not change either verdict."
    )
    assert compare_render.md_text(statement) in md
    assert md.endswith("<!-- guard-comparison-sha256: " + "0" * 64 + " -->\n")
