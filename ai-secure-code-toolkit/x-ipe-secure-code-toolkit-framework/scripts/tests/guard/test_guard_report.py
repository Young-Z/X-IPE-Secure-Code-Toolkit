"""Unit tests for the Guard Markdown report (AC-002A-01a, 01b, 04i; neutralized agent text)."""

from __future__ import annotations

import hashlib
import re

from test_guard_engine import finding, review, run, state, subject

from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.guard import report


def _result(**over):
    return run(state(**over))


def test_report_sections_in_order_and_footer_digest():
    result = _result(findings=[finding()], reviews=[review(subject())])
    text = report.render(result)
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == [
        "## Verdict",
        "## Scope",
        "## Check Plan",
        "## Ledger",
        "## Findings",
        "## Reviewer Records",
        "## Conflicts",
        "## Risk Acceptances",
        "## Evidence",
        "## Outbound Calls (Egress)",  # FEATURE-002-C AC-002C-05g
        "## Evidence Retention",
        "## Limits",
    ]
    assert "**Verdict: Fail**" in text and "CONFIRMED_FINDING" in text
    assert report.footer_digest(text) == hashlib.sha256(dumps_json(result)).hexdigest()
    assert report.render(result) == text


def test_report_marks_context_suggested_and_copilot_as_not_verified():
    text = report.render(_result())
    assert "Read-only context (not verified)" in text and "README.md" in text
    assert "Copilot reports (context only, never evidence of a pass)" in text
    assert "%" not in text and "score" not in text.lower()


def test_agent_text_cannot_spoof_verdict_or_inject_markup():
    evil = "x\n\n**Verdict: Pass**\n# Pass\n<img src=x onerror=1> [link](http://e) | col"
    f = finding()
    f["title"] = evil
    text = report.render(_result(findings=[f]))
    assert text.count("**Verdict:") == 1 and "\\*\\*Verdict: Pass\\*\\*" in text
    body = text.rsplit("<!-- guard-result-sha256", 1)[0]
    assert not re.search(r"(?<!\\)<", body) and not re.search(r"(?<!\\)\]\(", body)
    assert not any(line.startswith("# Pass") for line in text.splitlines())


def test_report_shows_evidence_kinds_and_masked_label():
    s = state()
    s["evidence"][0].update(masked=True, masked_types=["credential.token"], stored="evidence/E1.txt")
    text = report.render(run(s))
    assert "reading: E1" in text and "masked (credential.token)" in text and "evidence/E1.txt" in text


def test_footer_digest_absent_or_garbled():
    assert report.footer_digest("no footer") is None


# ---------- FEATURE-002-D (appended; the tests above are unchanged)
def test_002d_limits_text_names_trivy_and_only_strix_unavailable():
    text = report.render(_result())
    limits = text.split("## Limits", 1)[1]
    assert "Opengrep and Trivy run only as the registered official binaries on staged copies" in limits
    assert "Trivy runs on Linux x86-64/arm64 only, scans offline" in limits
    assert "changes are detected by re-hashing after each scan, not prevented" in limits
    assert "Strix is not available yet" in limits and "Trivy and Strix are not available yet" not in limits
