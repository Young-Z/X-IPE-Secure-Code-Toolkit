"""FEATURE-001-F Integration (structured package inspection): Framework skill instructions.

AC-001F-02a, 03g, 04d, 04e/06b (consistency, DAO-008 Q1), 04f, 04k, 05e, 07c, 09g, 01g.
Only the Framework package is read; Copilot and Guard skill packages are not read or changed.
"""

from __future__ import annotations

import re

from conftest import TOOLKIT_ROOT

FRAMEWORK = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework"


def reference() -> str:
    return (FRAMEWORK / "references" / "presets-and-tags.md").read_text(encoding="utf-8").lower()


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def skill_section(title: str) -> str:
    text = (FRAMEWORK / "SKILL.md").read_text(encoding="utf-8")
    return text.split(f"## {title}", 1)[1].split("\n## ", 1)[0].lower()


def section(text: str, title: str) -> str:
    return flat(text.split(f"## {title}", 1)[1].split("\n## ", 1)[0])


# AC-001F-02a
def test_skill_creates_preset_only_on_explicit_request():
    selecting = flat(skill_section("Selecting Policies"))
    conditional = "never create a preset from clues unless the user explicitly asks to make them reusable"
    assert conditional in selecting
    assert "presets-and-tags.md" in selecting
    save = section(reference(), "save as preset")
    assert "only when the user explicitly asks" in save
    assert "concrete list" in save and "reason" in save and "applicability summary" in save
    assert save.index("applicability summary") < save.index("--confirmed")
    assert "only after the user confirms" in save
    assert "temporary scope" in save


# AC-001F-03g
def test_skill_recompute_via_read_operations_and_confirmation():
    text = section(reference(), "recompute")
    for phrase in ("knowledge list", "knowledge show", "tag show", "policy resolve", "candidate",
                   "preset recompute", "diff", "explicit confirmation", "preset recompute-confirm",
                   "never run"):
        assert phrase in text, phrase
    assert text.index("preset recompute ") < text.index("explicit confirmation") < text.index(
        "preset recompute-confirm")


# AC-001F-04d
def test_skill_compares_applicability_and_waits():
    text = section(reference(), "applicability")
    for phrase in ("compare", "applicability summary", "current task", "clearly", "mismatch", "explain",
                   "wait", "continue or adjust", "before"):
        assert phrase in text, phrase


# AC-001F-04f
def test_skill_lists_matching_presets_unranked():
    text = section(reference(), "offering presets")
    for phrase in ("all matching presets", "name order", "no ranking", "applicability summary",
                   "mismatch", "the user picks"):
        assert phrase in text, phrase


# AC-001F-04k, AC-001F-01g, AC-001F-07c (honest limits, DAO-009 (4))
def test_skill_states_metadata_drift_limit():
    limits = section(reference(), "known limits")
    assert "metadata-only" in limits and "not detected" in limits
    assert "concrete references" in limits and "rule state" in limits
    assert "no preset/tag change history" in limits and "version control" in limits
    assert "snapshot_at is not a history" in limits
    assert "toolkit-mediated" in limits


# AC-001F-05e, AC-001F-07c
def test_skill_tags_as_clues_and_maintainer_only():
    text = section(reference(), "tags")
    assert "concrete references at proposal time" in text
    assert "maintainer" in text and "not_authorized" in text
    assert "toolkit-mediated" in text
    assert "never change severity" in text


# AC-001F-09g
def test_skill_makes_no_binding_claims():
    text = flat(reference())
    assert "information-only" in text
    for sentence in re.split(r"(?<=[.;:])\s", text):
        if re.search(r"\b(bound|verified|tamper-evident|binding)\b", sentence):
            assert re.search(r"\b(never|not|no)\b", sentence), sentence
    assert "never compose" in text


# AC-001F-04e (default branch), DAO-008 Q1
def test_policy_selection_no_clue_branches():
    selection = flat((FRAMEWORK / "references" / "policy-selection.md").read_text(encoding="utf-8").lower())
    for phrase in ("preset resolve", "--default", "no_default_preset", "--all",
                   "never propose apply all automatically", "preset scope-save default"):
        assert phrase in selection, phrase
    selecting = flat(skill_section("Selecting Policies"))
    assert "secure-code preset resolve --default" in selecting
    assert "because no clues were given" in selecting
    assert "separately and explicitly chooses it" in selecting
    combined = selecting + selection
    assert "apply all" in combined and "never create a preset" in combined


# AC-001F-06b, AC-001F-04e — DAO-008 Q1 consistency (Framework package only)
def test_framework_package_has_no_stale_preset_text():
    texts = {p.name: flat(p.read_text(encoding="utf-8").lower()) for p in
             [FRAMEWORK / "SKILL.md", *sorted((FRAMEWORK / "references").glob("*.md"))]}
    for name, text in texts.items():
        assert "there are no presets yet" not in text, name
        assert not re.search(r"presets,\s*tags,\s*reference cache", text), name
        assert not re.search(r"`presets`,\s*`tags`,\s*`reference_cache`", text), name
    exiting = flat(skill_section("Exiting Knowledge"))
    assert 'the kind "not checked in this version" (reference cache)' in exiting
    assert "presets and tags that reference it" in exiting
    assert re.search(r"show.{0,100}impact.{0,100}maintainer", exiting)


def test_cli_contract_lists_preset_tag_commands():
    contract = (FRAMEWORK / "references" / "cli-contract.md").read_text(encoding="utf-8")
    for command in ("preset list", "preset show", "preset save", "preset update", "preset delete",
                    "preset recompute", "preset recompute-confirm", "preset resolve", "preset scope-save",
                    "tag list", "tag show", "tag save", "tag update", "tag delete", "preset_tag_links"):
        assert command in contract, command
