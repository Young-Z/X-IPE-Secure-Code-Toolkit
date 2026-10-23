"""Guard skill package checks (AC-002A-02g, 05h, 07c, 08b) and request-format examples."""

from __future__ import annotations

import json
import re

from conftest import TOOLKIT_ROOT

from x_ipe_secure_code.cli import build_parser
from x_ipe_secure_code.guard.model import SCHEMA_OPEN, SCHEMA_PLAN, SCHEMA_RECORD, SCHEMA_REVIEW

GUARD = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-guard"


def _skill() -> str:
    return " ".join((GUARD / "SKILL.md").read_text(encoding="utf-8").lower().split())


def test_02g_scope_questions_only_when_unclear():
    text = _skill()
    assert "ask the user only when the project, baseline or targets are unclear" in text
    assert "do not ask again to confirm an explicit scope" in text
    assert "whole project only on an explicit user choice" in text
    assert "context and suggested files are not verified" in text


def test_05h_one_independent_reviewer_per_batch():
    text = _skill()
    assert "one independent read-only reviewer per batch" in text
    assert "only the relevant summaries and evidence locations" in text
    assert "with the reviewed target digests" in text
    assert "reviewers have no extra authority" in text


def test_07c_no_risk_acceptance_on_users_behalf():
    text = _skill()
    assert "never record a risk acceptance on the user's behalf" in text
    assert "maintainer authorization is not consent" in text


def test_08b_never_edits_or_remediates():
    text = _skill()
    assert "guard and its reviewer never edit business artifacts" in text
    assert "never start remediation or automatic re-scan loops" in text
    assert "fixes belong to the current task executor" in text
    assert "does not fix" in text


def test_skill_commands_exist_and_skeleton_note_removed():
    raw = (GUARD / "SKILL.md").read_text(encoding="utf-8")
    assert "Status of This Skill" not in raw
    parser = build_parser()
    guard_action = next(
        a
        for a in parser._subparsers._group_actions[0].choices["guard"]._actions
        if getattr(a, "choices", None)
    )
    for command in set(re.findall(r"secure-code guard ([a-z-]+)", raw)):
        assert command in guard_action.choices, command


def test_reference_examples_are_valid_requests():
    text = (GUARD / "references" / "guard-records.md").read_text(encoding="utf-8")
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    schemas = {b.get("schema") for b in blocks}
    assert {SCHEMA_OPEN, SCHEMA_PLAN, SCHEMA_RECORD, SCHEMA_REVIEW} <= schemas


def test_002b_04f_method_choice_and_tool_instructions():
    text = _skill()
    assert "prefer the cheapest sufficient method" in text
    assert "never run every tool by default" in text
    assert "ask the user before adding a new tool, wider targets, extra permissions or budget" in text
    assert "record the method choice" in text and "switch or supplement" in text
    assert "only local rule files" in text and "never record opengrep evidence or findings yourself" in text
    assert "not supported on windows" in text


def test_002b_reference_has_tool_request_and_new_fields():
    text = (GUARD / "references" / "guard-records.md").read_text(encoding="utf-8")
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    assert "ai-secure-code-toolkit/guard-tool/v1" in {b.get("schema") for b in blocks}
    assert "method_choice" in text and "method_changes" in text


def test_002c_06a_budget_cancel_and_egress_instructions():
    text = _skill()
    for phrase in (
        "open with the defaults or less",
        "ask the user to extend",
        "never extend the budget yourself",
        "register an attempt before every unit of work",
        "pause only while waiting for the user",
        "do no work while paused",
        "stop new attempts and conclude when the budget is exhausted",
        "cancel on the user's request",
        "stop your own reviewer and helper work",
        "declare every outbound call before making it",
        "send only the declared, minimized and masked data",
        "never send source, findings or credentials to another model or service without a submission grant",
        "the host session and its reviewer sub-agent are not egress",
    ):
        assert phrase in text, phrase


def test_002c_reference_examples_include_attempt_and_egress():
    from x_ipe_secure_code.guard.control import SCHEMA_ATTEMPT
    from x_ipe_secure_code.guard.egress import SCHEMA_EGRESS

    text = (GUARD / "references" / "guard-records.md").read_text(encoding="utf-8")
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    assert {SCHEMA_ATTEMPT, SCHEMA_EGRESS} <= {b.get("schema") for b in blocks}
    assert any("attempt" in b for b in blocks if b.get("schema") == SCHEMA_RECORD)


# ---------- FEATURE-002-D AC-002D-06d (appended; the tests above are unchanged)
def test_002d_06d_trivy_instructions():
    text = _skill()
    for phrase in (
        "strix is not available yet",
        "dependency vulnerabilities, misconfigurations",
        "secrets in `filesystem` mode",
        "vulnerabilities only for `docker save` image archives",
        "no compose misconfiguration analysis",
        "no registry or daemon images",
        "no license scanning",
        "list only files the chosen scanner analyses as a check's object",
        "use another method (e.g. semantic review) for compose files",
        "judge and record whether the reported database age is sufficient",
        "tool_update",
        "pkg-containers.githubusercontent.com",
        "never proceed without it",
        "never run trivy by default",
        "never record `trivy` evidence or findings yourself",
    ):
        assert phrase in text, phrase
    assert "trivy and strix are not available yet" not in text
    records = " ".join((GUARD / "references" / "guard-records.md").read_text(encoding="utf-8").split())
    for phrase in (
        '"adapter": "trivy"',
        "image_archive",
        "config_types",
        "IMAGE_ARCHIVE_INVALID",
        "IMAGE_ARCHIVE_TOO_LARGE",
        "TRIVY_COMPONENT_MISSING",
        "--recipient https://pkg-containers.githubusercontent.com",
        "secure-code tools provision",
        "secure-code tools remove-components",
    ):
        assert phrase in records, phrase
    for tool, guard_sev in (
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("UNKNOWN", "unknown"),
    ):
        assert re.search(rf"`?{tool}`?\s*(→|->|\|)\s*`?{guard_sev}`?", records), tool


def test_002d_trivy_request_examples_validate():
    """Every Trivy request example in the references is accepted by the request schema keys."""
    text = (GUARD / "references" / "guard-records.md").read_text(encoding="utf-8")
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    trivy = [b for b in blocks if b.get("adapter") == "trivy"]
    assert trivy
    for b in trivy:
        assert set(b) <= {"schema", "adapter", "time_limit_seconds", "checks"}
        for c in b["checks"]:
            assert set(c) <= {"check", "scanners", "mode", "targets", "config_types"}
            assert c["mode"] in ("filesystem", "image_archive") and set(c["scanners"]) <= {
                "vuln",
                "misconfig",
                "secret",
            }
