"""Internal content gate and drafting authorization (FEATURE-001-G, AC-001G-07*).

B14 = No (human): no authorization exists for any real host label. Every authorization here is
recorded inside a disposable `tmp_path` project for the fixture label `fixture-host`, and the
internal rule is the synthetic `@SYNTH/T-1.0/R-01` fixture only.
"""

from __future__ import annotations

import json
import os

import pytest
from conftest import FakeInteraction, posix_only, run_cli
from drafthelp import AUTH_FILE, HOST, R89, SYNTH, DEnv, codes, mod, run_pty


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path, synth=True)


def authorize(env, host=HOST, *, revoke=False, answer=None, interactive=True, paths=None):
    return mod("drafting_auth").authorize(
        str(env.project),
        host,
        revoke,
        interaction=FakeInteraction(interactive=interactive, answers=[host if answer is None else answer]),
        trust_paths=paths or env.paths,
    )


def listing(env, host=None):
    return mod("drafting_auth").list_authorizations(str(env.project), host)


# AC-001G-07e (in-process): record, list read-only, revoke; the record is outside formal knowledge.
def test_07e_record_list_revoke_in_process(env):
    record = env.project / AUTH_FILE
    assert listing(env, HOST).data["status"] == "not_authorized" and not record.exists()
    done = authorize(env)
    assert done.ok and done.data["outcome"] == "recorded", done.to_dict()
    data = json.loads(record.read_text())
    entry = data["authorizations"][0]
    assert data["schema"] == "ai-secure-code-toolkit/drafting-authorizations/v1"
    assert (entry["host"], entry["classification"], entry["state"], entry["maintainer_check"]) == (
        HOST,
        "internal",
        "active",
        "maintainer",
    )
    assert entry["authorized_at"].endswith("Z") and entry["revoked_at"] is None
    if os.name != "nt":
        assert (record.stat().st_mode & 0o777) == 0o600
    assert authorize(env).data["outcome"] == "unchanged"
    before = env.tree()
    shown = listing(env, HOST)
    assert shown.ok and shown.data["status"] == "authorized" and env.tree() == before
    assert mod("drafting_auth").is_authorized(env.project, HOST) == (True, None)
    assert authorize(env, revoke=True).data["outcome"] == "revoked"
    assert listing(env, HOST).data["status"] == "not_authorized"
    assert authorize(env, revoke=True).data["outcome"] == "unchanged"
    assert not (env.project / "x-ipe-docs/secure-code/knowledge/local/drafting-authorizations.json").exists()


# AC-001G-07e (CLI, real pseudo-terminal): typed label; init/status outputs unchanged.
@posix_only
def test_07e_interactive_record_list_revoke_init_status_unchanged(env, tmp_path):
    p = str(env.project)
    status_before = run_cli(["status", "--project", p, "--json"], env.trust).stdout
    init_before = run_cli(["init", "--project", p, "--env", "github-copilot", "--json"], env.trust).stdout
    code, out = run_pty(["knowledge", "drafting-authorize", "--project", p, "--host", HOST], env.trust, HOST)
    assert code == 0 and "recorded" in out, out
    listed = run_cli(["knowledge", "drafting-authorize", "--project", p, "--list", "--json"], env.trust)
    entries = json.loads(listed.stdout)["data"]["authorizations"]
    assert listed.returncode == 0 and [e["host"] for e in entries] == [HOST]
    assert run_cli(["status", "--project", p, "--json"], env.trust).stdout == status_before
    assert (
        run_cli(["init", "--project", p, "--env", "github-copilot", "--json"], env.trust).stdout
        == init_before
    )
    code, out = run_pty(
        ["knowledge", "drafting-authorize", "--project", p, "--host", HOST, "--revoke"], env.trust, HOST
    )
    assert code == 0 and "revoked" in out, out
    code, out = run_pty(
        ["knowledge", "drafting-authorize", "--project", p, "--host", HOST], env.trust, "other-host"
    )
    assert code == 1 and "CONFIRMATION_MISMATCH" in out


# AC-001G-07f: no TTY or non-Maintainer → refused, nothing recorded.
def test_07f_no_tty_or_non_maintainer_refused_nothing_recorded(env, tmp_path):
    from x_ipe_secure_code.auth.trust_store import resolve

    before = env.tree()
    assert codes(authorize(env, interactive=False)) == ["INTERACTIVE_REQUIRED"]
    stranger = resolve(tmp_path / "no-trust")
    assert codes(authorize(env, paths=stranger)) == ["NOT_AUTHORIZED"]
    assert codes(authorize(env, answer="fixture-hos")) == ["CONFIRMATION_MISMATCH"]
    assert codes(authorize(env, host="Bad Label")) == ["HOST_LABEL_INVALID"]
    cli = run_cli(
        ["knowledge", "drafting-authorize", "--project", str(env.project), "--host", HOST, "--json"],
        env.trust,
    )
    assert cli.returncode == 1 and json.loads(cli.stdout)["problems"][0]["code"] == "INTERACTIVE_REQUIRED"
    assert env.tree() == before and not (env.project / AUTH_FILE).exists()


def test_argument_shapes_refused(env):
    auth = mod("drafting_auth")
    assert codes(auth.run(str(env.project), False, None, False)) == ["ARGUMENT_INVALID"]
    assert codes(auth.run(str(env.project), True, None, True)) == ["ARGUMENT_INVALID"]


def test_malformed_record_fails_closed(env):
    record = env.project / AUTH_FILE
    record.write_text(json.dumps({"schema": "x", "authorizations": []}))
    assert codes(listing(env)) == ["AUTHORIZATION_RECORD_INVALID"]
    assert mod("drafting_auth").is_authorized(env.project, HOST) == (False, "AUTHORIZATION_RECORD_INVALID")
    record.write_text(
        json.dumps(
            {
                "schema": "ai-secure-code-toolkit/drafting-authorizations/v1",
                "authorizations": [
                    {
                        "host": HOST,
                        "classification": "internal",
                        "state": "active",
                        "authorized_at": "now",
                        "maintainer_check": "maintainer",
                        "revoked_at": None,
                    }
                ],
            }
        )
    )
    assert mod("drafting_auth").is_authorized(env.project, HOST)[0] is False


def test_list_is_read_only_and_never_creates_private_files(env):
    before = env.tree()
    shown = listing(env)
    assert shown.ok and shown.data["authorizations"] == [] and env.tree() == before
    assert R89 and SYNTH  # fixture identities only


SYNTH_EXAMPLE = {
    "unsafe": "def change_role(user, role):\n    user.role = role",
    "safe": "def change_role(user, role, actor):\n    user.role = role\n"
    "    audit.record(actor, 'role', utc_now())",
    "demonstrates": ["MUST record every administrative change together with its actor and time."],
}


def synth_draft(env, **over):
    return env.drafted(SYNTH, {"python": dict(SYNTH_EXAMPLE)}, name="synth--python", **over)


# AC-001G-07a: synthetic internal rule + recorded authorization for fixture-host → accepted; notice internal.
def test_07a_synthetic_internal_rule_authorized_fixture_host(env):
    assert authorize(env).ok
    draft, review = synth_draft(env)
    checked = env.check(draft, review)
    assert checked.ok, checked.to_dict()
    assert "# confidentiality: internal" in checked.data["preview"]["masked_diff"]
    approved = env.approve(draft, review, checked.data["validation_digest"])
    assert approved.ok, approved.to_dict()
    assert b"# confidentiality: internal" in env.rule_files(SYNTH)["example-python.md"]
    rows = env.supplements(SYNTH).data["supplements"]
    assert rows[0]["confidentiality"] == "internal"


# AC-001G-07b: a draft declaring `internal` for a non-@ rule is gated too; internal drafts use stored
# content only (any URL source is refused).
def test_07b_declared_internal_on_non_at_rule_gated(env):
    draft, review = env.drafted(confidentiality="internal")
    assert codes(env.check(draft, review)) == ["INTERNAL_DRAFTING_NOT_AUTHORIZED"]
    assert authorize(env).ok
    assert env.check(draft, review).ok
    url = {"kind": "not_retrieved", "url": "https://cwe.mitre.org/data/definitions/89.html", "reason": "r"}
    draft, review = env.drafted(confidentiality="internal", sources=[url])
    checked = env.check(draft, review)
    assert checked.data["status"] == "invalid"
    assert checked.data["provenance"][0]["result"] == "source_not_allowed"
    draft, review = synth_draft(env, sources=[url])
    assert env.check(draft, review).data["provenance"][0]["result"] == "source_not_allowed"


# AC-001G-07d: no active authorization for drafted_by.host → refused on check and approve; revoked too.
def test_07d_not_authorized_check_and_approve(env):
    draft, review = synth_draft(env)
    before = env.tree()
    for result in (env.check(draft, review), env.approve(draft, review, "sha256:" + "5" * 64)):
        assert codes(result) == ["INTERNAL_DRAFTING_NOT_AUTHORIZED"]
        assert "fixture-host" in result.problems[0].message
    assert env.tree() == before
    assert authorize(env).ok and authorize(env, revoke=True).ok
    assert codes(env.check(draft, review)) == ["INTERNAL_DRAFTING_NOT_AUTHORIZED"]
    other = env.write_draft(
        env.draft_doc(SYNTH, {"python": dict(SYNTH_EXAMPLE)}, drafted_by={"host": "other-host"}),
        "synth--other",
    )
    assert authorize(env).ok
    assert codes(env.check(other)) == ["INTERNAL_DRAFTING_NOT_AUTHORIZED"]
