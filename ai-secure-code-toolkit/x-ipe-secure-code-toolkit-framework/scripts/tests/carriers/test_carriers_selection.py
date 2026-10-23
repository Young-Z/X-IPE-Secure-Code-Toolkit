"""FEATURE-003-B integration tests: carrier selection and write boundaries (AC-003B-03a…03h)."""

from __future__ import annotations

import json
import os

import pytest
from carhelp import (
    AGENTS,
    BEGIN,
    CLAUDE,
    DEF_REL,
    END,
    FRONT_MATTER,
    HOST,
    INSTR,
    RECORD,
    SYSP,
    codes,
    entry,
    inner,
    listing,
    sandbox,
    split_outside,
    status_entry,
    watch_writes,
    written_paths,
)

from x_ipe_secure_code.guard.mask import mask_text


def _ok(proc, out):
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return out


# ---------------------------------------------------------------- AC-003B-03a

def test_03a_default_selection_only_host_entry(tmp_path):
    box = sandbox(tmp_path)
    out = _ok(*box.carriers())
    assert [item["carrier"] for item in out["data"]["carriers"]] == ["host-entry"]
    assert entry(out, "host-entry")["state"] == "current"
    assert not box.path(INSTR).exists() and not box.path(SYSP).exists()
    assert not box.path(".github/instructions").exists()
    assert not box.path(".x-ipe/private/secure-code/carriers").exists()
    assert "carriers" not in box.record()  # nothing optional selected → no member


# ---------------------------------------------------------------- AC-003B-03b

def test_03b_instructions_file_two_managed_boundaries(tmp_path):
    box = sandbox(tmp_path)
    out = _ok(*box.carriers("--select", "github-instructions"))
    item = entry(out, "github-instructions")
    assert item["path"] == INSTR and item["state"] == "created"
    data = box.read(INSTR)
    assert data.startswith((FRONT_MATTER + "\n" + BEGIN + "\n").encode())  # front matter at file start
    assert data.count(BEGIN.encode()) == 1 and data.count(END.encode()) == 1
    assert data.endswith((END + "\n").encode())
    assert item["front_matter"] == "ok"


# ---------------------------------------------------------------- AC-003B-03c

def test_03c_system_prompt_file_shown_with_manual_step_no_host_config(tmp_path):
    box = sandbox(tmp_path)
    home_before = {name: os.path.exists(os.path.expanduser(name)) for name in
                   ("~/.copilot", "~/.config/github-copilot", "~/.claude")}
    with watch_writes() as writes:
        out = _ok(*box.carriers("--select", "system-prompt", "--system-prompt-host", HOST))
    item = entry(out, "system-prompt")
    assert item["path"] == SYSP and item["state"] == "created"
    shown = out["data"]["system_prompt"]
    assert shown["path"] == SYSP and shown["host"] == HOST
    assert "\n".join(shown["content"]) + "\n" == inner(box.text(SYSP))
    assert "manual" in shown["manual_step"].lower()
    root = box.root.resolve()
    for path in written_paths(writes):
        assert path == root or root in path.parents, path  # nothing outside the project root
    assert not any(box.trust.resolve() in path.parents for path in written_paths(writes))
    assert home_before == {name: os.path.exists(os.path.expanduser(name)) for name in home_before}


def test_03c_system_prompt_requires_an_explicit_host(tmp_path):
    box = sandbox(tmp_path)
    before = box.hashes()
    proc, out = box.carriers("--select", "system-prompt")
    assert proc.returncode == 1 and codes(out) == ["ARGUMENT_INVALID"]
    assert any("--system-prompt-host" in step for step in out["next_steps"])
    assert box.hashes() == before


# ---------------------------------------------------------------- AC-003B-03d

def test_03d_write_set_only_selected_carriers_and_record(tmp_path):
    box = sandbox(tmp_path)
    box.write(".gitignore", "node_modules/\n")
    box.write(CLAUDE, "# Claude rules\n")
    box.write(".github/copilot-instructions.md", "# Repo instructions\n")
    before = box.hashes()
    with watch_writes() as writes:
        _ok(*box.select_all())
    root = box.root.resolve()
    allowed_files = {root / AGENTS, root / INSTR, root / SYSP, root / RECORD}
    allowed_dirs = {path.parent for path in allowed_files}  # created (or re-checked) parent folders
    assert written_paths(writes)
    for path in written_paths(writes):
        if path in allowed_files or path in allowed_dirs:
            continue
        assert path.parent in allowed_dirs and path.name.startswith(".") and ".tmp-" in path.name, path
    after = box.hashes()
    changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    r = str(box.root)
    expected = {f"{r}/{INSTR}", f"{r}/{SYSP}", f"{r}/{RECORD}", f"{r}/.github/instructions/",
                f"{r}/.x-ipe/private/secure-code/carriers/"}
    assert {f"{r}/{INSTR}", f"{r}/{SYSP}", f"{r}/{RECORD}"} <= changed <= expected
    for rel in (".gitignore", CLAUDE, ".github/copilot-instructions.md", AGENTS):
        assert after[f"{r}/{rel}"] == before[f"{r}/{rel}"]
    skills = [key for key in after if "/.github/skills/" in key]
    assert skills and all(after[key] == before.get(key) for key in skills)


def _break_prerequisite(box, case: str) -> None:
    definition = box.definition_path()
    if case == "missing-skill":
        (box.root / ".github/skills/x-ipe-secure-code-toolkit-guard/SKILL.md").unlink()
    elif case == "missing-definition":
        definition.unlink()
    elif case == "unreadable-definition":
        definition.write_bytes(b"\xff\xfe\x00not utf-8")
    elif case == "invalid-json":
        definition.write_text("{ not json", encoding="utf-8")
    elif case == "invalid-edit":
        obj = json.loads(definition.read_text(encoding="utf-8"))
        obj["sections"] = [s for s in obj["sections"] if s["id"] != "guard"]
        definition.write_text(json.dumps(obj, indent=2), encoding="utf-8")


@pytest.mark.parametrize("case,code", [
    ("missing-skill", "SKILLS_INVALID"),
    ("missing-definition", "ROUTING_DEFINITION_INVALID"),
    ("unreadable-definition", "ROUTING_DEFINITION_INVALID"),
    ("invalid-json", "ROUTING_DEFINITION_INVALID"),
    ("invalid-edit", "ROUTING_DEFINITION_INVALID"),
])
def test_03d_missing_or_invalid_skills_or_definition_refused_with_init_step(tmp_path, case, code):
    box = sandbox(tmp_path)
    _break_prerequisite(box, case)
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.select_all()
    assert proc.returncode == 1 and codes(out) == [code]
    assert any("secure-code init" in step for step in out["next_steps"])
    assert box.hashes() == before and writes == []  # nothing written, no implicit reinstall


def test_03d_valid_maintainer_edit_of_definition_is_not_invalid(tmp_path):
    box = sandbox(tmp_path)
    box.edit_definition()
    before_skills = {k: v for k, v in box.hashes().items() if "/.github/skills/" in k}
    out = _ok(*box.carriers())
    assert entry(out, "host-entry")["state"] == "updated"
    assert "Keep the change small." in box.text(AGENTS)
    assert {k: v for k, v in box.hashes().items() if "/.github/skills/" in k} == before_skills
    assert (box.root / ".github/skills" / DEF_REL).exists()


# ---------------------------------------------------------------- AC-003B-03e

@pytest.mark.parametrize("how", ["deselect", "select-replaces"])
def test_03e_deselected_carrier_left_and_reported_no_longer_managed(tmp_path, how):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    box.write(SYSP, box.text(SYSP) + "\nMy own note.\n")
    left = box.read(SYSP)
    args = ("--deselect", "system-prompt") if how == "deselect" else ("--select", "github-instructions")
    with watch_writes() as writes:
        out = _ok(*box.carriers(*args))
    item = entry(out, "system-prompt")
    assert item["selection"] == "no longer managed" and item["state"] == "no longer managed"
    assert "manual" in item["next_step"].lower()
    assert box.read(SYSP) == left
    assert box.path(SYSP).resolve() not in written_paths(writes)
    assert "system_prompt" not in out["data"]
    assert box.record()["carriers"]["selected"] == ["host-entry", "github-instructions"]

    status = _ok(*box.status())
    assert status_entry(status, "system-prompt")["fragment"] == "no longer managed"
    assert "manual" in status_entry(status, "system-prompt")["next_step"].lower()

    box.write(INSTR, box.text(INSTR) + "\nuser tail\n")
    out = _ok(*box.carriers())  # a later run without any selection: stored set checked again
    assert entry(out, "host-entry")["state"] == "current"
    assert entry(out, "github-instructions")["state"] == "current"
    assert entry(out, "system-prompt")["state"] == "no longer managed"
    assert box.read(SYSP) == left


def test_03e_host_entry_cannot_be_deselected(tmp_path):
    box = sandbox(tmp_path)
    before = box.hashes()
    proc, out = box.carriers("--deselect", "host-entry")
    assert proc.returncode == 1 and codes(out) == ["ARGUMENT_INVALID"]
    assert box.hashes() == before


# ---------------------------------------------------------------- AC-003B-03f

@pytest.mark.parametrize("env,kind,supported", [
    ("github-copilot", "bogus", ["host-entry", "github-instructions", "system-prompt"]),
    ("claude-code", "github-instructions", ["host-entry", "system-prompt"]),
    ("claude-code", "bogus", ["host-entry", "system-prompt"]),
])
def test_03f_unknown_or_unsupported_carrier_refused_lists_supported(tmp_path, env, kind, supported):
    box = sandbox(tmp_path, env=env)
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.carriers("--select", kind)
    assert proc.returncode == 1 and codes(out) == ["CARRIER_UNSUPPORTED"]
    assert out["data"]["supported_carriers"] == supported
    assert kind in out["problems"][0]["message"]
    assert box.hashes() == before and writes == []


# ---------------------------------------------------------------- AC-003B-03g

def test_03g_user_content_outside_boundaries_preserved_and_reported(tmp_path):
    box = sandbox(tmp_path)
    _ok(*box.carriers("--select", "github-instructions"))
    data = box.read(INSTR)
    head, block, tail = split_outside(data)
    assert head == (FRONT_MATTER + "\n").encode()
    between = "Team note between the boundaries ü\n\n".encode()
    after = b"\n## Our own rules\nUse tabs.\n"
    user_file = FRONT_MATTER.encode() + b"\n" + between + block + tail + after
    box.write(INSTR, user_file)
    out = _ok(*box.carriers())
    item = entry(out, "github-instructions")
    assert item["state"] == "current"  # not a toolkit difference
    assert item["user_content"] == "detected outside the managed boundaries (kept)"
    assert item["front_matter"] == "ok"  # reported separately from front-matter drift
    assert "FRAGMENT_EDITED" not in codes(out) and "FRONT_MATTER_DRIFT" not in codes(out)
    assert INSTR not in out["data"].get("differences", {})
    assert box.read(INSTR) == user_file
    status = _ok(*box.status())
    item = status_entry(status, "github-instructions")
    assert item["user_content"] == "detected outside the managed boundaries (kept)"
    assert item["front_matter"] == "ok" and item["fragment"] == "present"
    assert box.read(INSTR) == user_file


# ---------------------------------------------------------------- AC-003B-03h

def test_03h_system_prompt_fragment_has_no_secrets_and_no_key_material_nearby(tmp_path):
    box = sandbox(tmp_path)
    box.trust.mkdir(parents=True, exist_ok=True)
    (box.trust / "marker.txt").write_text("trust store stays outside the project\n")
    trust_before = {p.name: p.read_bytes() for p in box.trust.rglob("*") if p.is_file()}
    _ok(*box.carriers("--select", "system-prompt", "--system-prompt-host", HOST))
    text = box.text(SYSP)
    assert mask_text(text)[0] == text
    for forbidden in ("private key", "public key", "passphrase", "-----begin", "ssh-", "signature:"):
        assert forbidden not in text.lower(), forbidden
    folder = box.path(SYSP).parent
    assert listing(folder) == {"system-prompt.md"}
    for name in listing(folder):
        for word in ("key", ".pem", "trust", "grant", "revocation", "auth"):
            assert word not in name.lower(), name
    assert not str(box.trust.resolve()).startswith(str(box.root.resolve()))
    assert {p.name: p.read_bytes() for p in box.trust.rglob("*") if p.is_file()} == trust_before
