"""Integration tests for project initialization (AC-001A-04a…04i, 05a…05d)."""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import TOOLKIT_ROOT, run_cli, tree_hashes

from x_ipe_secure_code import host_fragment
from x_ipe_secure_code.payload import SKILL_NAMES

LAYOUT = [
    "knowledge/local", "knowledge/reference", "presets", "tags", "improvements",
    "reports/copilot", "reports/guard",
]


def _init(project, trust, *extra, env="github-copilot", block_network=False):
    args = ["init", "--project", str(project), "--json", *extra]
    if env:
        args += ["--env", env]
    flags = ["--block-network"] if block_network else []
    proc = run_cli(args, trust, extra=flags)
    return proc, json.loads(proc.stdout)


# AC-001A-04a, 04c
def test_init_copilot_project_creates_skills_layout_fragment(project, tmp_path):
    trust = tmp_path / "trust-app"
    proc, out = _init(project, trust, block_network=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for name in SKILL_NAMES:
        assert (project / ".github/skills" / name / "SKILL.md").is_file()
    assert (project / ".github/skills/x-ipe-secure-code-toolkit-framework/scripts/src"
            / "x_ipe_secure_code/cli.py").is_file()
    assert not (project / ".github/skills/x-ipe-secure-code-toolkit-framework/scripts/tests").exists()
    data_root = project / "x-ipe-docs/secure-code"
    for rel in LAYOUT:
        assert (data_root / rel).is_dir()
    assert [p for p in data_root.rglob("*") if p.is_file()] == []
    agents = (project / "AGENTS.md").read_text(encoding="utf-8")
    assert agents.count(host_fragment.BEGIN) == 1
    assert out["data"]["environment"] == "github-copilot"
    # AC-001A-04c: no authorization created, no scanner, no network (socket blocked)
    assert not trust.exists()
    assert not any("opengrep" in p.name or "trivy" in p.name for p in project.rglob("*")
                   if p.is_file() and p.suffix in ("", ".exe"))


# AC-001A-04b
@pytest.mark.parametrize("bad", [None, "missing-dir", "a-file"])
def test_init_refuses_missing_or_invalid_root_writes_nothing(tmp_path, bad):
    trust = tmp_path / "trust-app"
    (tmp_path / "a-file").write_text("x")
    before = tree_hashes(tmp_path)
    args = ["init", "--env", "github-copilot", "--json"]
    if bad:
        args += ["--project", str(tmp_path / bad)]
    proc = run_cli(args, trust, cwd=tmp_path)
    out = json.loads(proc.stdout)
    assert proc.returncode == 1 and not out["ok"]
    assert out["problems"][0]["code"] in ("ROOT_REQUIRED", "ROOT_INVALID")
    assert tree_hashes(tmp_path) == before


def test_init_nested_project_does_not_use_parent(tmp_path):
    trust = tmp_path / "trust-app"
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    _init(parent, trust)
    proc, out = _init(child, trust)
    assert proc.returncode == 0
    assert (child / ".github/skills" / SKILL_NAMES[0] / "SKILL.md").is_file()


# AC-001A-04e
def test_plain_repo_has_no_xipe_files_after_init(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    run_cli(["status", "--project", str(project), "--json"], trust)
    assert not (project / ".x-ipe.yaml").exists()
    assert not (project / "x-ipe-docs/planning").exists()


# AC-001A-04f
def test_init_uses_explicit_env_independent_of_existing_agent_files(project, tmp_path):
    trust = tmp_path / "trust-app"
    (project / "AGENTS.md").write_text("agents\n")
    (project / ".github").mkdir()
    proc, out = _init(project, trust, env="claude-code")
    assert proc.returncode == 0
    assert out["data"]["environment"] == "claude-code"
    assert (project / ".claude/skills" / SKILL_NAMES[1] / "SKILL.md").is_file()
    assert host_fragment.BEGIN in (project / "CLAUDE.md").read_text()
    assert (project / "AGENTS.md").read_text() == "agents\n"


# AC-001A-04g
@pytest.mark.parametrize("env,code", [(None, "ENV_REQUIRED"), ("vim-plugin", "ENV_UNSUPPORTED")])
def test_env_missing_or_unsupported_refuses_no_write(project, tmp_path, env, code):
    trust = tmp_path / "trust-app"
    before = tree_hashes(project)
    proc, out = _init(project, trust, env=env)
    assert proc.returncode == 1 and out["problems"][0]["code"] == code
    assert "github-copilot" in json.dumps(out)
    assert tree_hashes(project) == before


# AC-001A-04h (integration)
def test_existing_agents_md_user_content_preserved(project, tmp_path):
    trust = tmp_path / "trust-app"
    original = b"# Team rules\r\n\r\nBe nice.\r\n"
    (project / "AGENTS.md").write_bytes(original)
    _init(project, trust)
    assert (project / "AGENTS.md").read_bytes().startswith(original)


# AC-001A-04i (integration)
def test_rerun_no_second_fragment_and_edited_fragment_reported(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    first = (project / "AGENTS.md").read_bytes()
    _init(project, trust)
    assert (project / "AGENTS.md").read_bytes() == first
    edited = first.replace(b"in-flow", b"IN-FLOW")
    assert edited != first
    (project / "AGENTS.md").write_bytes(edited)
    proc, out = _init(project, trust)
    assert proc.returncode == 0
    assert (project / "AGENTS.md").read_bytes() == edited
    assert any(p["code"] == "FRAGMENT_EDITED" for p in out["problems"])
    _init(project, trust, "--replace", "AGENTS.md")
    assert (project / "AGENTS.md").read_bytes() == first


def test_same_named_foreign_skill_conflict_writes_nothing(project, tmp_path):
    trust = tmp_path / "trust-app"
    foreign = project / ".github/skills" / SKILL_NAMES[2]
    foreign.mkdir(parents=True)
    (foreign / "SKILL.md").write_text("someone else's skill\n")
    before = tree_hashes(project)
    proc, out = _init(project, trust)
    assert proc.returncode == 1
    assert any(p["code"] == "SKILL_NAME_CONFLICT" for p in out["problems"])
    assert tree_hashes(project) == before


# AC-001A-05a
def test_reinit_same_version_no_change(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    before = tree_hashes(project)
    proc, out = _init(project, trust)
    assert proc.returncode == 0 and out["data"]["already_current"] is True
    assert tree_hashes(project) == before


def _copy_toolkit(tmp_path):
    dest = tmp_path / "toolkit-v2"
    shutil.copytree(TOOLKIT_ROOT, dest, ignore=shutil.ignore_patterns(
        ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "*.pyc"))
    return dest


# AC-001A-05b, 05c, 05d
def test_reinit_updates_unedited_keeps_edited_and_never_touches_data(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    data_file = project / "x-ipe-docs/secure-code/reports/guard/r1.md"
    data_file.write_text("my report\n")
    data_before = tree_hashes(project / "x-ipe-docs")
    skills = project / ".github/skills"
    guard_skill = skills / SKILL_NAMES[2] / "SKILL.md"
    copilot_skill = skills / SKILL_NAMES[1] / "SKILL.md"
    copilot_skill.write_text(copilot_skill.read_text() + "\nLocal note.\n")

    newer = _copy_toolkit(tmp_path)
    for name in SKILL_NAMES[1:]:
        path = newer / name / "SKILL.md"
        path.write_text(path.read_text() + "\nNew upstream line.\n")
    proc, out = _init(project, trust, "--toolkit-source", str(newer))
    assert proc.returncode == 0, proc.stdout
    files = out["data"]["files"]
    assert f".github/skills/{SKILL_NAMES[2]}/SKILL.md" in files["updated"]
    assert "New upstream line." in guard_skill.read_text()
    assert f".github/skills/{SKILL_NAMES[1]}/SKILL.md" in files["locally_edited"]
    assert "Local note." in copilot_skill.read_text()
    assert "New upstream line." not in copilot_skill.read_text()
    assert tree_hashes(project / "x-ipe-docs") == data_before

    rel = f".github/skills/{SKILL_NAMES[1]}/SKILL.md"
    proc, out = _init(project, trust, "--toolkit-source", str(newer), "--replace", rel)
    assert rel in out["data"]["files"]["replaced"]
    assert "New upstream line." in copilot_skill.read_text()
    assert tree_hashes(project / "x-ipe-docs") == data_before


# Code review regressions: symlinked/blocked write targets, mid-write failure
@pytest.mark.parametrize("link", [".x-ipe", "x-ipe-docs"])
def test_symlinked_record_or_data_folder_refused_nothing_written(project, tmp_path, link):
    trust = tmp_path / "trust-app"
    outside = tmp_path / "outside"
    outside.mkdir()
    (project / link).symlink_to(outside, target_is_directory=True)
    before_project, before_outside = tree_hashes(project), tree_hashes(outside)
    proc, out = _init(project, trust)
    assert proc.returncode == 1
    assert any(p["code"] == "PATH_UNSAFE" for p in out["problems"])
    assert tree_hashes(outside) == before_outside
    assert tree_hashes(project) == before_project


def test_layout_path_blocked_by_file_refused_before_writing(project, tmp_path):
    trust = tmp_path / "trust-app"
    data = project / "x-ipe-docs/secure-code"
    data.mkdir(parents=True)
    (data / "presets").write_text("not a folder")
    before = tree_hashes(project)
    proc, out = _init(project, trust)
    assert proc.returncode == 1
    assert any(p["code"] == "PATH_UNSAFE" for p in out["problems"])
    assert tree_hashes(project) == before


def test_symlinked_record_is_not_loaded(project, tmp_path):
    from x_ipe_secure_code.install_record import RecordError, load

    outside = tmp_path / "outside"
    (outside / "private/secure-code").mkdir(parents=True)
    from x_ipe_secure_code.install_record import InstallRecord

    record = InstallRecord("0.1.0", "github-copilot", ".github/skills", "AGENTS.md", None,
                           "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", {})
    (outside / "private/secure-code/install-record.json").write_text(json.dumps(record.to_dict()))
    (project / ".x-ipe").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RecordError):
        load(project.resolve())


def test_write_failure_returns_io_error_listing_written_files(project, monkeypatch):
    from x_ipe_secure_code import project_init

    real = project_init.atomic_write_bytes
    calls = {"n": 0}

    def flaky(path, data, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, data, **kwargs)

    monkeypatch.setattr(project_init, "atomic_write_bytes", flaky)
    result = project_init.initialize_project(str(project), "github-copilot")
    assert not result.ok and result.problems[-1].code == "IO_ERROR"
    assert len(result.data["written_before_failure"]) == 2
