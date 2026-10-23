"""Integration tests for read-only status (AC-001A-09a…09e)."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import PASSPHRASE, FakeInteraction, run_cli, tree_hashes

from x_ipe_secure_code.auth.service import initialize_authorization, revoke_authorization
from x_ipe_secure_code.auth.trust_store import resolve


def _status(project, trust, extra=()):
    proc = run_cli(["status", "--project", str(project), "--json"], trust, extra=list(extra))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _init(project, trust):
    proc = run_cli(["init", "--project", str(project), "--env", "github-copilot", "--json"], trust)
    assert proc.returncode == 0, proc.stdout


# AC-001A-09a
def test_status_fresh_init_sections_and_next_steps_no_ready(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    out = _status(project, trust)
    data = out["data"]
    assert data["install"]["state"] == "installed"
    assert data["authorization"]["state"] == "not_initialized"
    assert "auth init" in data["authorization"]["next_step"]
    assert data["policies"]["local"] == 0 and data["policies"]["reference"] == 0
    assert "Maintainer" in data["policies"]["next_step"]
    assert set(data["tools"]) == {"opengrep", "trivy", "strix"}
    strix = data["tools"]["strix"]  # FEATURE-002-B AC-002B-06b (Strix part); Trivy: FEATURE-002-D AC-002D-08a
    assert strix["state"] == "adapter not provided by this toolkit version" and strix["next_step"]
    trivy = data["tools"]["trivy"]
    assert trivy["state"] == "provided" and trivy["registered"] is False and trivy["next_step"]
    opengrep = data["tools"]["opengrep"]  # FEATURE-002-B AC-002B-06a: provided, not registered yet
    assert opengrep["state"] == "provided" and opengrep["registered"] is False and opengrep["next_step"]
    host = data["host_integration"]
    assert host["environment"] == "github-copilot" and host["fragment"] == "present"
    assert host["host_effect"] == "not verified"
    assert "ready" not in json.dumps(out).lower()


# AC-001A-09b
def test_status_changes_nothing_and_reads_only_metadata(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    business = project / "src" / "app.py"
    business.parent.mkdir()
    business.write_text("password = 'x'\n")
    rule = project / "x-ipe-docs/secure-code/knowledge/local/@CUSTOM/v1/R-1"
    rule.mkdir(parents=True)
    (rule / "rule.md").write_text("rule body\n")
    audit = tmp_path / "audit.log"
    before = tree_hashes(project, trust)
    out = _status(project, trust, extra=["--audit-open", str(audit)])
    assert out["data"]["policies"]["local"] == 1
    assert tree_hashes(project, trust) == before
    opened = {Path(line).resolve() for line in audit.read_text().splitlines() if line}
    project_real = project.resolve()
    allowed_prefixes = [
        project_real / ".github/skills",
        project_real / ".x-ipe/private/secure-code/install-record.json",
        project_real / "AGENTS.md",
    ]
    inside = [p for p in opened if project_real in p.parents]
    assert business.resolve() not in opened
    assert (rule / "rule.md").resolve() not in opened
    for path in inside:
        assert any(path == a or a in path.parents for a in allowed_prefixes), path


# AC-001A-09c
def test_status_reports_root_entry_preset_problems(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    (project / "x-ipe-docs/secure-code/tags").rmdir()
    (project / "x-ipe-docs/secure-code/presets/default.json").write_text("{}")
    data = _status(project, trust)["data"]
    assert Path(data["install"]["root"]) == project.resolve()
    assert data["install"]["skills_dir"] == ".github/skills"
    assert data["default_preset"]["exists"] is True
    assert any("tags" in p["message"] for p in data["problems"])


# AC-001A-09d
def test_status_not_installed_no_parent_lookup(tmp_path):
    trust = tmp_path / "trust-app"
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    _init(parent, trust)
    data = _status(child, trust)["data"]
    assert data["install"]["state"] == "not installed"
    assert "secure-code init" in data["install"]["next_step"]
    assert Path(data["install"]["root"]) == child.resolve()


# AC-001A-09e
def test_status_invalid_or_revoked_auth(project, tmp_path):
    trust = tmp_path / "trust-app"
    paths = resolve(trust)
    initialize_authorization(paths=paths, interaction=FakeInteraction(answers=[PASSPHRASE] * 2))
    revoke_authorization(paths=paths, interaction=FakeInteraction(answers=[PASSPHRASE]))
    auth = _status(project, trust)["data"]["authorization"]
    assert auth["state"] == "revoked" and auth["role"] == "user" and auth["next_step"]
    paths.public_key.write_text("garbage")
    auth = _status(project, trust)["data"]["authorization"]
    assert auth["state"] == "invalid" and auth["role"] == "user" and auth["reason"]


def test_status_invalid_root_refused(tmp_path):
    proc = run_cli(["status", "--project", str(tmp_path / "nope"), "--json"], tmp_path / "t")
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["problems"][0]["code"] == "ROOT_INVALID"


def test_status_text_output_is_sectioned(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    proc = run_cli(["status", "--project", str(project)], trust)
    for section in ("Install", "Authorization", "Policies", "Tools", "Host integration"):
        assert section in proc.stdout


# FEATURE-002-D AC-002D-08b / 08a (appended; the tests above are unchanged)
def test_status_reports_strix_not_provided(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    tools = _status(project, trust)["data"]["tools"]
    strix = tools["strix"]
    assert strix["state"] == "adapter not provided by this toolkit version" and strix["next_step"]
    trivy = tools["trivy"]
    assert trivy["state"] == "provided" and trivy["registered"] is False
    assert "tools register --tool trivy" in trivy["next_step"]
    assert set(trivy["components"]) == {"vulnerability_db", "java_db", "checks_bundle"}
    assert {c["state"] for c in trivy["components"].values()} == {"missing"}
