"""AC-001D-02f,04f Integration: real Guard/Copilot consumption and immutable history.

Arrange complete adopted scopes/open runs/prior Markdown+JSON reports; Act exit and
next conclusion/report; Assert Policy changes and unchanged prior artifacts.
Failure-wrapper tests supplement (not replace) that real integration.
"""

from __future__ import annotations

import json

import pytest
from knowledge.exithelp import (
    R1,
    R3,
    Env,
    cleanup,
    files,
    finish,
    refusal,
    wait_blocked,
    wait_ready,
)

from x_ipe_secure_code.copilot import model
from x_ipe_secure_code.copilot import service as copilot
from x_ipe_secure_code.guard import runs
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import service as policy
from x_ipe_secure_code.results import Result


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate()
    return result


def prepared(env):
    saved = env.save()
    assert saved.ok
    sid = saved.data["scope_id"]
    vid, cid = env.open_runs(sid, history=True)
    suggestion = env.req({
        "schema": "ai-secure-code-toolkit/copilot-suggest/v1",
        "suggestions": [{
            "id": "S1", "rule": R1, "files": ["src/entry.py"], "location": "entry(), line 2",
            "action": "Encode returned output", "reason": "User input reaches output", "severity": "high",
        }],
    })
    added = copilot.suggest(str(env.project), cid, suggestion)
    assert added.ok, added.to_dict()
    return sid, vid, cid


@pytest.mark.parametrize("action", ["deactivate", "reactivate", "delete", "rename", "cycle"])
def test_old_reports_immutable_open_runs_detect_lifecycle(env, action):
    if action == "reactivate":
        env.exit("deactivate")
        env.exit("reactivate")
    sid, vid, cid = prepared(env)
    scopes = files(env.project / "x-ipe-docs/secure-code/scopes")
    reports = files(env.project / "x-ipe-docs/secure-code/reports")
    historical = {path: data for path, data in reports.items() if isinstance(data, bytes)}
    for consumer in ("guard", "copilot"):
        for suffix in (".md", ".json"):
            existing = [p for p in historical if p.startswith(consumer + "/") and p.endswith(suffix)]
            assert existing, f"Arrange needs prior {consumer} {suffix} reports: {sorted(reports)}"
            assert all(historical[p] for p in existing), f"empty prior {consumer} {suffix} report"
    assert scopes, "Arrange needs the adopted scope record"
    private = {
        "guard": files(env.project / ".x-ipe/private/secure-code/guard"),
        "copilot": files(env.project / ".x-ipe/private/secure-code/copilot"),
    }
    gs = runs.read_state(env.project, vid)
    cs = model.read_state(env.project, cid)
    if action in ("reactivate", "cycle"):
        env.exit("deactivate")
        env.exit("reactivate")
    else:
        env.exit(action)
    assert files(env.project / "x-ipe-docs/secure-code/scopes") == scopes
    assert files(env.project / "x-ipe-docs/secure-code/reports") == reports
    assert files(env.project / ".x-ipe/private/secure-code/guard") == private["guard"]
    assert files(env.project / ".x-ipe/private/secure-code/copilot") == private["copilot"]
    expected = "changed" if action in ("reactivate", "cycle") else "missing"
    assert policy.adoption_now(env.project, sid, gs["scope"]["adopted"], "guard conclude") == {
        R1: expected, R3: "unchanged",
    }
    assert policy.adoption_now(env.project, sid, cs["scope"]["adopted"], "copilot report") == {
        R1: expected, R3: "unchanged",
    }
    concluded = guard.conclude(str(env.project), vid)
    assert concluded.ok, concluded.to_dict()
    structured = json.loads((env.project / concluded.data["result"]).read_text())
    assert any(b["code"] == "POLICY_CHANGED" for b in (
        structured["reasons"] + structured["other_blockers"]
    ))
    adopted = next(a for a in structured["scope"]["adopted"] if a["rule"] == R1)
    assert adopted["at_conclusion"] == expected
    reported = copilot.report(str(env.project), cid)
    assert reported.ok, reported.to_dict()
    result = json.loads((env.project / reported.data["result"]).read_text())
    assert result["suggestions"][0]["state"] == "policy_changed"
    assert reported.data["policy_next_step"]
    for path, data in historical.items():
        assert (env.project / "x-ipe-docs/secure-code/reports" / path).read_bytes() == data, path
    assert files(env.project / "x-ipe-docs/secure-code/scopes") == scopes


@pytest.mark.parametrize("kind", ["guard", "copilot"])
@pytest.mark.parametrize("phase", ["open", "conclusion"])
@pytest.mark.parametrize("code", ["EXIT_JOURNAL_INVALID", "PATH_UNSAFE", "LOCKED", "IO_ERROR"])
def test_policy_refusal_next_step_passthrough(env, monkeypatch, kind, phase, code):
    """Behavioral RED: Copilot currently overwrites the authoritative Policy next step."""
    sid, vid, cid = prepared(env)
    service = guard if kind == "guard" else copilot
    step = "A Maintainer must inspect the exit journal; do not edit private files automatically"
    denied = Result.refused("scope show", code, "Injected Policy failure", step)
    if phase == "open":
        request = env.open_request(sid, kind)
        monkeypatch.setattr(service, "load_adopted", lambda *args: denied)
        result = (
            guard.open_verification(str(env.project), request) if kind == "guard"
            else copilot.open_collaboration(str(env.project), request)
        )
    else:
        monkeypatch.setattr(service, "adoption_now", lambda *args: denied)
        result = (
            guard.conclude(str(env.project), vid) if kind == "guard"
            else copilot.report(str(env.project), cid)
        )
    refusal(result, code)
    assert result.next_steps == [step]


@pytest.mark.parametrize("kind", ["guard", "copilot"])
def test_run_open_during_confirmation_waits_then_detects_exit(env, kind):
    saved = env.save()
    request = env.open_request(saved.data["scope_id"], kind)
    preview = env.preview()
    assert preview.ok
    barrier = env.work / "exit-held"
    exiting = env.spawn(
        env.cli_args("deactivate", preview.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
    )
    opening = None
    try:
        wait_ready(exiting, barrier)
        args = [kind, "open", "--project", str(env.project), "--request", request, "--json"]
        probe = env.work / "open-probe"
        opening = env.spawn(args, probe=probe)
        wait_blocked(opening, probe, env.project / store.LOCK_REL)
        assert opening.poll() is None, "run opened through a held knowledge lock"
        barrier.with_suffix(".go").touch()
        assert finish(exiting)["ok"] is True
        result = finish(opening)
        assert result["ok"] is False
        assert result["problems"][0]["code"] == "SCOPE_PARTIAL"
    finally:
        cleanup(*[p for p in (exiting, opening) if p is not None])
