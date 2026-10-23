"""CLI integration tests for owner authorization (AC-001A-06a/b/e, 07d, 08a/b, 10b)."""

from __future__ import annotations

import json

from conftest import CANARY, PASSPHRASE, posix_only, run_cli, run_cli_pty, tree_hashes


def _json(proc):
    return json.loads(proc.stdout)


# AC-001A-06b
def test_auth_init_piped_stdin_refused_no_files(tmp_path):
    trust = tmp_path / "trust-app"
    proc = run_cli(["auth", "init", "--json"], trust, input_text=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    assert proc.returncode == 1
    out = _json(proc)
    assert out["ok"] is False and out["problems"][0]["code"] == "NOT_INTERACTIVE"
    assert not (trust / "trust").exists()


# AC-001A-08b (CLI side)
def test_revoke_non_interactive_refused(tmp_path):
    trust = tmp_path / "trust-app"
    proc = run_cli(["auth", "revoke", "--json"], trust, input_text=f"{PASSPHRASE}\n")
    assert proc.returncode == 1 and _json(proc)["problems"][0]["code"] == "NOT_INTERACTIVE"


@posix_only
def test_pty_init_status_revoke_cycle(tmp_path):
    trust = tmp_path / "trust-app"
    env = {"OPENAI_API_KEY": CANARY}
    code, out = run_cli_pty(["auth", "init"], trust, [PASSPHRASE, PASSPHRASE], env_extra=env)
    assert code == 0, out
    assert PASSPHRASE not in out  # AC-001A-06e: passphrase not echoed/printed
    assert "PRIVATE KEY" not in out and CANARY not in out
    status = run_cli(["auth", "status", "--json"], trust, env_extra=env)
    data = _json(status)["data"]
    assert data["role"] == "maintainer" and data["state"] == "valid"

    # AC-001A-08b wrong passphrase over a real terminal
    code, out = run_cli_pty(["auth", "revoke"], trust, ["definitely wrong!!"])
    assert code == 1 and "PASSPHRASE_WRONG" in out
    assert _json(run_cli(["auth", "status", "--json"], trust))["data"]["state"] == "valid"

    # AC-001A-08a
    code, out = run_cli_pty(["auth", "revoke"], trust, [PASSPHRASE])
    assert code == 0, out
    after = _json(run_cli(["auth", "status", "--json"], trust))["data"]
    assert after["role"] == "user" and after["state"] == "revoked"


# AC-001A-07d: same machine, two workspaces, same qualification
@posix_only
def test_verify_same_result_from_two_projects(tmp_path):
    trust = tmp_path / "trust-app"
    run_cli_pty(["auth", "init"], trust, [PASSPHRASE, PASSPHRASE])
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    ra = _json(run_cli(["auth", "status", "--json"], trust, cwd=a))["data"]
    rb = _json(run_cli(["auth", "status", "--json"], trust, cwd=b))["data"]
    assert ra["role"] == rb["role"] == "maintainer"


# AC-001A-10b: no secrets or model credentials in any output or project file
@posix_only
def test_no_secret_or_model_credential_in_any_output(tmp_path):
    trust = tmp_path / "trust-app"
    project = tmp_path / "proj"
    project.mkdir()
    env = {"OPENAI_API_KEY": CANARY, "ANTHROPIC_API_KEY": CANARY}
    outputs = []
    _, out = run_cli_pty(["auth", "init"], trust, [PASSPHRASE, PASSPHRASE], env_extra=env)
    outputs.append(out)
    for args in (
        ["init", "--project", str(project), "--env", "github-copilot", "--json"],
        ["init", "--project", str(project), "--env", "github-copilot"],
        ["status", "--project", str(project), "--json"],
        ["status", "--project", str(project)],
        ["auth", "status", "--json"],
        ["auth", "init", "--json"],
    ):
        proc = run_cli(args, trust, env_extra=env)
        outputs += [proc.stdout, proc.stderr]
    blob = "\n".join(outputs)
    for project_file in tree_hashes(project):
        if not project_file.endswith("/"):
            with open(project_file, "rb") as handle:
                blob += handle.read().decode(errors="replace")
    assert CANARY not in blob
    assert PASSPHRASE not in blob
    # Actual key material starts with this PEM header; the toolkit's own pre-check pattern
    # (shipped in project files) merely mentions "PRIVATE KEY" and is not key material.
    assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" not in blob
