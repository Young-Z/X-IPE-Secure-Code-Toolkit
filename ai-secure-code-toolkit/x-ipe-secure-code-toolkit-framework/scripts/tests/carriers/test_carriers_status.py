"""FEATURE-003-B integration tests: per-carrier status and honest host effect (AC-003B-06a…06d)."""

from __future__ import annotations

import re

import pytest
from carhelp import (
    AGENTS,
    BEGIN,
    CLAUDE,
    END,
    FRAMEWORK,
    FRONT_MATTER,
    HOST_EFFECT_RESULT,
    INSTR,
    KINDS,
    PATHS,
    SYSP,
    codes,
    entry,
    problem,
    sandbox,
    status_entry,
    watch_writes,
)
from conftest import TOOLKIT_ROOT

CLAIMS = re.compile(r"loaded by (the )?host|routing (is |was )?verified|host effect: verified", re.I)


def _ok(proc, out):
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return out


def _prepare(box, state: str) -> str:
    """Bring the instructions carrier (or the system-prompt carrier) into one status state."""
    _ok(*box.select_all())
    if state == "present":
        return "github-instructions"
    if state == "absent":
        text = box.text(INSTR)
        start, stop = text.index(BEGIN), text.index(END) + len(END) + 1
        box.write(INSTR, text[:start] + text[stop:])
    elif state == "missing file":
        box.path(INSTR).unlink()
    elif state == "modified":
        box.write(INSTR, box.text(INSTR).replace("in-flow", "in-flow, ours", 1))
    elif state == "customized":
        box.write(INSTR, box.text(INSTR).replace("in-flow", "in-flow, ours", 1))
        _ok(*box.carriers("--accept", "github-instructions"))
    elif state == "no longer managed":
        _ok(*box.carriers("--deselect", "system-prompt"))
        return "system-prompt"
    elif state == "malformed":
        box.write(INSTR, box.text(INSTR) + BEGIN + "\nx\n" + END + "\n")
    elif state == "unreadable":
        box.write(INSTR, box.read(INSTR) + b"\xff\xfe")
    return "github-instructions"


STATES = ["present", "absent", "missing file", "modified", "customized", "no longer managed", "malformed",
          "unreadable"]


# ---------------------------------------------------------------- AC-003B-06a

@pytest.mark.parametrize("state", STATES)
def test_06a_per_carrier_states_metadata_and_host_effect_not_verified(tmp_path, state):
    box = sandbox(tmp_path)
    box.write(CLAUDE, "# other environment's host entry\n")
    kind = _prepare(box, state)
    out = _ok(*box.status())
    host = out["data"]["host_integration"]
    item = status_entry(out, kind)
    assert item["fragment"] == state
    assert item["path"] == PATHS[kind]
    assert item["selection"] == ("no longer managed" if state == "no longer managed" else "selected")
    assert item["front_matter"] in ("ok", "n/a") or item["front_matter"].startswith("drift: ")
    assert isinstance(item["next_step"], str) and item["next_step"]
    assert [c["carrier"] for c in host["carriers"]] == list(KINDS)  # only the record's environment
    assert CLAUDE not in str(host["carriers"])
    for carrier in host["carriers"]:
        assert carrier["host_effect"] == "not verified"
        assert carrier["next_step"]
    assert host["host_effect"] == "not verified"


# ---------------------------------------------------------------- AC-003B-06b

@pytest.mark.parametrize("state", ["fresh-init", *STATES])
def test_06b_status_writes_nothing_in_any_state(tmp_path, state):
    box = sandbox(tmp_path)
    if state != "fresh-init":
        _prepare(box, state)
    before = box.hashes()
    with watch_writes() as writes:
        _ok(*box.status())
        proc, _ = box.status(json_out=False)
        assert proc.returncode == 0
    assert writes == []
    assert box.hashes() == before


# ---------------------------------------------------------------- AC-003B-06c

def test_06c_no_claim_of_host_loading_or_verified_routing(tmp_path):
    box = sandbox(tmp_path)
    texts = []
    for args in ((), ("--select", "github-instructions", "--select", "system-prompt", "--system-prompt-host",
                      "copilot-cli")):
        proc, out = box.carriers(*args)
        _ok(proc, out)
        assert out["data"]["host_effect"] == HOST_EFFECT_RESULT
        texts.append(proc.stdout)
        proc, _ = box.carriers(*args, json_out=False)
        assert HOST_EFFECT_RESULT in proc.stdout
        texts.append(proc.stdout)
    proc, out = box.status()
    assert out["data"]["host_integration"]["host_effect"] == "not verified"
    texts.append(proc.stdout)
    texts.append(box.status(json_out=False)[0].stdout)
    texts += [box.text(rel) for rel in (AGENTS, INSTR, SYSP)]
    texts.append((TOOLKIT_ROOT / FRAMEWORK / "SKILL.md").read_text(encoding="utf-8"))
    references = sorted((TOOLKIT_ROOT / FRAMEWORK / "references").glob("*.md"))
    texts += [p.read_text(encoding="utf-8") for p in references]
    texts.append(box.definition_path().read_text(encoding="utf-8"))
    for text in texts:
        assert CLAIMS.search(text) is None, CLAIMS.search(text)


def test_docs_framework_skill_describes_carriers_and_honest_limit():
    skill = " ".join((TOOLKIT_ROOT / FRAMEWORK / "SKILL.md").read_text(encoding="utf-8").split())
    when = skill[skill.index("## When to Use"):skill.index("## ", skill.index("## When to Use") + 3)]
    assert "secure-code carriers" in when
    assert "secure-code carriers" in skill[skill.index("## How to Call"):]
    assert "host effect: not verified" in skill
    environments = (TOOLKIT_ROOT / FRAMEWORK / "references" / "environments.md").read_text(encoding="utf-8")
    assert FRONT_MATTER in environments
    assert ".github/instructions/x-ipe-secure-code-toolkit.instructions.md" in environments
    contract = (TOOLKIT_ROOT / FRAMEWORK / "references" / "cli-contract.md").read_text(encoding="utf-8")
    assert "secure-code carriers" in contract
    for code in ("CARRIER_UNSUPPORTED", "ENV_MISMATCH", "LOCK_UNAVAILABLE", "SKILLS_INVALID",
                 "ROUTING_DEFINITION_INVALID", "CARRIER_UNREADABLE", "DECISION_NOT_APPLICABLE",
                 "FRONT_MATTER_DRIFT", "CUSTOMIZATION_ROUTING_CHANGED"):
        assert code in contract, code


# ---------------------------------------------------------------- AC-003B-06d

def _drift(text: str, how: str) -> tuple[str, str]:
    rest = text[len(FRONT_MATTER):]
    if how == "removed":
        return rest, "drift: missing"
    if how == "applyTo-changed":
        return '---\napplyTo: "src/**"\n---\n' + rest, "drift: altered"
    if how == "key-added":
        return '---\napplyTo: "**"\nexcludeAgent: "code-review"\n---\n' + rest, "drift: altered"
    return "My heading\n\n" + FRONT_MATTER + rest, "drift: moved"


@pytest.mark.parametrize("how", ["removed", "applyTo-changed", "key-added", "moved"])
def test_06d_front_matter_drift_reported_distinct_and_kept_until_regenerate(tmp_path, how):
    box = sandbox(tmp_path)
    _ok(*box.carriers("--select", "github-instructions"))
    drifted, label = _drift(box.text(INSTR), how)
    box.write(INSTR, drifted)
    box.edit_definition()  # even a would-be body update does not rewrite a drifted file
    for proc_out in (box.carriers(), box.status()):
        out = _ok(*proc_out)
        if "host_integration" in out["data"]:
            item = status_entry(out, "github-instructions")
            differences = out["data"]["host_integration"]["differences"]
        else:
            item = entry(out, "github-instructions")
            assert item["state"] == "kept-differs" and problem(out, "FRONT_MATTER_DRIFT")
            differences = out["data"]["differences"]
        assert item["front_matter"] == label
        expected_user = "detected outside the managed boundaries (kept)" if how == "moved" else "none"
        assert item["user_content"] == expected_user  # distinct from front-matter drift (03g)
        assert differences[INSTR]["front_matter_diff"]
        assert "next_step" in item and item["next_step"]
        assert box.text(INSTR) == drifted
    out = _ok(*box.carriers("--regenerate", "github-instructions"))
    assert entry(out, "github-instructions")["state"] == "replaced"
    result = box.text(INSTR)
    assert result.startswith(FRONT_MATTER) and result.count(FRONT_MATTER) == 1
    if how == "moved":
        assert "My heading\n\n" in result
    status = status_entry(_ok(*box.status()), "github-instructions")
    assert status["front_matter"] == "ok"
    assert "FRONT_MATTER_DRIFT" not in codes(_ok(*box.carriers()))
