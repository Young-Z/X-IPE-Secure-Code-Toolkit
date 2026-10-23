"""Copilot skill package checks (AC-003A-01e, 03h, 04j, 06b, 06c) and reference examples."""

from __future__ import annotations

import json
import re

from conftest import TOOLKIT_ROOT

from x_ipe_secure_code.cli import build_parser
from x_ipe_secure_code.copilot.model import SCHEMA_ARTIFACTS, SCHEMA_OPEN, SCHEMA_REVIEW, SCHEMA_SUGGEST

COPILOT = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-copilot"


def _skill() -> str:
    return " ".join((COPILOT / "SKILL.md").read_text(encoding="utf-8").lower().split())


def _reference() -> str:
    return (COPILOT / "references" / "copilot-records.md").read_text(encoding="utf-8")


def test_01e_targeted_re_review_instructions():
    text = _skill()
    for phrase in (
        "do not re-review after every edit",
        "after a relevant change, run secure-code copilot show to see which suggestions are stale",
        "send only the stale and new suggestions to the reviewer",
    ):
        assert phrase in text, phrase


def test_03h_in_flow_concrete_suggestions():
    text = _skill()
    for phrase in (
        "design, implementation, bug fix and refactor",
        "including changes to an existing design",
        "load the adopted policies through the framework skill",
        "tied to an artifact location and a policy source",
        "no generic checklist",
        "focus on the change and its related impact",
        "leave all edits to the current executor",
    ):
        assert phrase in text, phrase


def test_04j_one_independent_read_only_reviewer_per_batch():
    text = _skill()
    for phrase in (
        "one independent read-only reviewer per batch through the host",
        "not one per rule",
        "pass only the task, the relevant suggestions, artifact locations and digests",
        "check the actual artifact, not the executor's claim",
        "never edits artifacts, never widens the review and never starts further agents",
    ):
        assert phrase in text, phrase


def test_06b_never_edits_and_never_blocks():
    text = _skill()
    for phrase in (
        "copilot and its reviewer never edit business artifacts",
        "the current executor makes all changes",
        "copilot does not pause or block the work",
        "the upstream caller decides from the attention list",
    ):
        assert phrase in text, phrase


def test_06c_honest_boundaries():
    text = _skill()
    for phrase in (
        "an upstream decision to continue is not adoption or a pass",
        "must not trigger the copilot or guard flow again",
        "failed or old reports never count as done for the current version",
        "never invent policies from memory",
    ):
        assert phrase in text, phrase


def test_skill_commands_exist_and_skeleton_note_removed():
    raw = (COPILOT / "SKILL.md").read_text(encoding="utf-8")
    assert "Status of This Skill" not in raw and "not yet available" not in raw
    parser = build_parser()
    action = next(
        a
        for a in parser._subparsers._group_actions[0].choices["copilot"]._actions
        if getattr(a, "choices", None)
    )
    used = set(re.findall(r"secure-code copilot ([a-z-]+)", raw))
    assert used == {"open", "artifacts", "suggest", "review", "report", "show", "close"}
    assert used <= set(action.choices)
    assert "references/copilot-records.md" in raw


def test_reference_examples_are_valid_requests():
    text = _reference()
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    schemas = {b.get("schema") for b in blocks}
    assert {SCHEMA_OPEN, SCHEMA_ARTIFACTS, SCHEMA_SUGGEST, SCHEMA_REVIEW} <= schemas
    for state in (
        "adopted",
        "partial",
        "not_adopted",
        "not_applicable",
        "cannot_verify",
        "not_reviewed",
        "stale",
        "policy_changed",
    ):
        assert f"`{state}`" in text, state
    lowered = " ".join(text.lower().split())
    assert "attention" in lowered and "high, critical or unknown" in lowered
    assert "absent" in text and "attempt" in text
