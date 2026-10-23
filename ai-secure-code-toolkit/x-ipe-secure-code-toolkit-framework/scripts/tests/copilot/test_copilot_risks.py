"""FEATURE-003-A risk tests: crash recovery (Publication Protocol), concurrency, Guard context (06e), CLI."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from conftest import LAUNCHER
from cphelp import PRIVATE, R1, R2, REPORTS, S_REV, S_SUG, Env, adoption, by_id, sug

from x_ipe_secure_code.copilot import report as cp_report
from x_ipe_secure_code.copilot import service as copilot


@pytest.fixture
def cp(project, tmp_path):
    env = Env(project, tmp_path)
    env.cid = env.opened()
    assert env.suggest(env.cid, [sug("S1"), sug("S2", rule=R2, files=("src/util.py",), severity="low")]).ok
    return env


class Crash(RuntimeError):
    pass


def _crash_on(monkeypatch, suffix):
    original = copilot._create_new

    def wrapper(path, data):
        original(path, data)
        if path.name.endswith(suffix):
            raise Crash(f"crash after {suffix}")

    monkeypatch.setattr(copilot, "_create_new", wrapper)


def _crash_before_commit(monkeypatch):
    def boom(root, state):
        raise Crash("crash before the state write")

    monkeypatch.setattr(copilot, "_commit_round", boom)


@pytest.mark.parametrize("step", ["json", "md", "state"])
def test_crash_recovery_then_mutation(cp, monkeypatch, step):
    with monkeypatch.context() as m:
        if step == "state":
            _crash_before_commit(m)
        else:
            _crash_on(m, f".{step}")
        with pytest.raises(Crash):
            cp.report(cp.cid)
    residue_json = (cp.project / REPORTS / f"{cp.cid}-r1.json").read_bytes()
    assert cp.state(cp.cid)["rounds"] == []
    shown = cp.show(cp.cid)
    assert shown.ok and shown.data["latest_round"] is None and shown.data["reports"] == []
    assert cp.suggest(cp.cid, [sug("S3")]).ok  # reconcile commits r1 before the mutation
    rounds = cp.state(cp.cid)["rounds"]
    assert [r["n"] for r in rounds] == [1]
    data1 = json.loads(residue_json)
    assert rounds[0]["signature"] == data1["state_signature"]
    md1 = cp.report_md(cp.cid, 1)
    assert md1 == cp_report.render(data1)
    assert cp_report.footer_digest(md1) == cp_report.sha256_hex(residue_json)
    second = cp.report(cp.cid)
    assert second.data["round"] == 2 and "S3" in by_id(cp.result_json(cp.cid, 2))
    assert (cp.project / REPORTS / f"{cp.cid}-r1.json").read_bytes() == residue_json
    assert cp.report_md(cp.cid, 1) == md1
    assert cp.rounds(cp.cid) == [
        f"{cp.cid}-r1.json",
        f"{cp.cid}-r1.md",
        f"{cp.cid}-r2.json",
        f"{cp.cid}-r2.md",
    ]


def test_crash_recovery_by_report_returns_committed_round(cp, monkeypatch):
    with monkeypatch.context() as m:
        _crash_on(m, ".json")
        with pytest.raises(Crash):
            cp.report(cp.cid)
    again = cp.report(cp.cid)
    assert again.ok and again.data["round"] == 1 and again.data["published"] is False
    assert (cp.project / REPORTS / f"{cp.cid}-r1.md").is_file()


@pytest.mark.parametrize("case", ["md_without_json", "tampered_json", "footer_mismatch", "foreign_json"])
def test_report_conflict_never_overwrites(cp, case):
    folder = cp.project / REPORTS
    folder.mkdir(parents=True, exist_ok=True)
    md = folder / f"{cp.cid}-r1.md"
    js = folder / f"{cp.cid}-r1.json"
    if case == "md_without_json":
        md.write_text("planted\n")
    else:
        assert cp.report(cp.cid).ok
        state = cp.state(cp.cid)
        state["rounds"] = []
        (cp.project / PRIVATE / cp.cid / "state.json").write_text(json.dumps(state))
        data = json.loads(js.read_text())
        if case == "tampered_json":
            data["attention"] = []
            js.write_text(json.dumps(data))
        elif case == "foreign_json":
            data["collaboration_id"] = "cp-20200101T000000Z-00000000"
            js.write_text(json.dumps(data))
        else:
            md.write_text(md.read_text().replace("round 1", "round one"))
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    for result in (cp.suggest(cp.cid, [sug("S3")]), cp.report(cp.cid), cp.close(cp.cid)):
        assert result.problems[0].code == "REPORT_CONFLICT"
        assert "move" in result.next_steps[0].lower() and f"{cp.cid}-r1" in result.next_steps[0]
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before
    assert cp.show(cp.cid).ok


# ---------- concurrency (processes)


def _cli(cp, *args):
    cmd = [
        sys.executable,
        str(LAUNCHER),
        "--test-trust-dir",
        str(cp.tmp / "trust-app"),
        "copilot",
        *args,
        "--project",
        str(cp.project),
        "--json",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _wait(procs):
    out = []
    for p in procs:
        stdout, stderr = p.communicate(timeout=120)
        assert stdout, stderr
        out.append(json.loads(stdout))
    return out


def test_concurrent_reports_publish_one_round(cp):
    assert cp.report(cp.cid).data["round"] == 1
    (cp.project / "src" / "util.py").write_text("changed\n")
    results = _wait([_cli(cp, "report", "--id", cp.cid) for _ in range(5)])
    assert all(r["ok"] for r in results), results
    assert {r["data"]["round"] for r in results} == {2}
    assert sum(r["data"]["published"] for r in results) == 1
    assert cp.rounds(cp.cid)[-2:] == [f"{cp.cid}-r2.json", f"{cp.cid}-r2.md"] and len(cp.rounds(cp.cid)) == 4


def test_concurrent_reports_and_suggestions(cp):
    procs = []
    for i in range(4):
        path = cp.tmp / f"cs-{i}.json"
        path.write_text(json.dumps({"schema": S_SUG, "suggestions": [sug(f"C{i}")]}))
        procs.append(_cli(cp, "suggest", "--id", cp.cid, "--request", str(path)))
        procs.append(_cli(cp, "report", "--id", cp.cid))
    results = _wait(procs)
    assert all(r["ok"] for r in results), [r for r in results if not r["ok"]]
    ids = [s["id"] for s in cp.state(cp.cid)["suggestions"]]
    assert sorted(ids) == ["C0", "C1", "C2", "C3", "S1", "S2"]
    rounds = [r["n"] for r in cp.state(cp.cid)["rounds"]]
    assert rounds == list(range(1, len(rounds) + 1))
    names = cp.rounds(cp.cid)
    assert names == sorted(f"{cp.cid}-r{n}.{ext}" for n in rounds for ext in ("json", "md"))
    signatures = [cp.result_json(cp.cid, n)["state_signature"] for n in rounds]
    assert len(set(signatures)) == len(signatures)
    final = cp.report(cp.cid)
    assert {f"C{i}" for i in range(4)} <= set(by_id(cp.result_json(cp.cid, final.data["round"])))


# ---------- AC-003A-06e


def test_06e_guard_takes_copilot_report_as_context_only(cp):
    assert cp.review(cp.cid, [adoption("S1")]).ok
    published = cp.report(cp.cid)
    md_rel = published.data["report"]
    from x_ipe_secure_code.guard import service as guard

    doc = {
        "schema": "ai-secure-code-toolkit/guard-open/v1",
        "scope_id": cp.scope,
        "targets": [{"path": "src/register.py", "change": "modified"}],
        "copilot_reports": [{"path": md_rel}, {"path": published.data["result"]}],
    }
    opened = guard.open_verification(str(cp.project), cp.req(doc))
    assert opened.ok, opened.to_text()
    vid = opened.data["verification_id"]
    assert opened.data["copilot_reports"] == [md_rel, published.data["result"]]
    plan = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": [
            {
                "id": "C1",
                "rule": R1,
                "object": ["src/register.py"],
                "methods": [{"name": "semantic-review", "kind": "reading"}],
                "minimum_evidence": ["reading"],
            }
        ],
        "not_applicable": [{"rule": R2, "reason": "no database access"}],
    }
    assert guard.record_plan(str(cp.project), vid, cp.req(plan)).ok
    from x_ipe_secure_code.guard import control

    att = control.attempt(
        str(cp.project),
        vid,
        cp.req(
            {
                "schema": "ai-secure-code-toolkit/guard-attempt/v1",
                "kind": "semantic_review",
                "covers": {"pairs": [{"check": "C1", "method": "semantic-review"}]},
            }
        ),
    )
    assert att.ok, att.to_text()
    rec = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "attempt": att.data["attempt"],
        "evidence": [
            {
                "id": "E1",
                "kind": "reading",
                "method": "semantic-review",
                "method_status": "ok",
                "checks": ["C1"],
                "paths": [md_rel],
                "summary": "Copilot says adopted",
            }
        ],
        "ledger": [{"check": "C1", "state": "met", "evidence": ["E1"]}],
    }
    assert guard.record(str(cp.project), vid, cp.req(rec)).ok
    concluded = guard.conclude(str(cp.project), vid)
    assert concluded.data["verdict"] != "pass"
    result = json.loads((cp.project / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.json").read_text())
    assert result["ledger"][0]["state"] == "unconfirmed"
    assert [c["path"] for c in result["artifact"]["copilot_reports"]] == [md_rel, published.data["result"]]


# ---------- CLI round trip


def test_cli_round_trip(cp):
    from conftest import run_cli

    trust = cp.tmp / "trust-app"

    def run(*args):
        out = run_cli(["copilot", *args, "--project", str(cp.project), "--json"], trust)
        return out.returncode, json.loads(out.stdout)

    open_req = cp.tmp / "cli-open.json"
    open_req.write_text(
        json.dumps(
            {
                "schema": "ai-secure-code-toolkit/copilot-open/v1",
                "scope_id": cp.scope,
                "stage": "bug_fix",
                "task": "Fix escaping",
                "artifacts": [{"path": "src/register.py", "change": "modified"}],
            }
        )
    )
    code, opened = run("open", "--request", str(open_req))
    assert code == 0 and opened["command"] == "copilot open"
    cid = opened["data"]["collaboration_id"]
    art = cp.tmp / "cli-art.json"
    art.write_text(
        json.dumps(
            {
                "schema": "ai-secure-code-toolkit/copilot-artifacts/v1",
                "artifacts": [{"path": "src/util.py", "change": "added"}],
            }
        )
    )
    assert run("artifacts", "--id", cid, "--request", str(art))[0] == 0
    s = cp.tmp / "cli-s.json"
    s.write_text(json.dumps({"schema": S_SUG, "suggestions": [sug("S1")]}))
    assert run("suggest", "--id", cid, "--request", str(s))[0] == 0
    r = cp.tmp / "cli-r.json"
    r.write_text(
        json.dumps(
            {
                "schema": S_REV,
                "invocation": {"host": "h", "agent": "a", "read_only": True, "invoked_at": "t"},
                "requirement": "check",
                "subjects": [adoption("S1")],
                "reviewed_targets": [{"path": "src/register.py", "digest": cp.digest("src/register.py")}],
            }
        )
    )
    assert run("review", "--id", cid, "--request", str(r))[0] == 0
    code, reported = run("report", "--id", cid)
    assert code == 0 and reported["data"]["round"] == 1
    code, shown = run("show", "--id", cid)
    assert code == 0 and shown["data"]["latest_round"] == 1
    code, closed = run("close", "--id", cid)
    assert code == 0 and closed["data"]["status"] == "closed"
    code, refused = run("suggest", "--id", cid, "--request", str(s))
    assert code == 1 and refused["problems"][0]["code"] == "COLLAB_CLOSED"
    text = run_cli(["copilot", "show", "--project", str(cp.project), "--id", cid], trust)
    assert text.returncode == 0 and text.stdout.startswith("copilot show: OK")


# ---------- edge cases from the design


def test_removed_latest_markdown_is_repaired_from_its_json(cp):
    first = cp.report(cp.cid)
    md = cp.project / first.data["report"]
    text = md.read_text(encoding="utf-8")
    md.unlink()
    shown = cp.show(cp.cid)
    assert shown.data["reports"][0]["md_exists"] is False
    again = cp.report(cp.cid)
    assert again.data["round"] == 1 and again.data["published"] is False
    assert md.read_text(encoding="utf-8") == text and again.data["report_exists"] is True


def test_removed_latest_json_is_reported_not_recreated(cp):
    first = cp.report(cp.cid)
    (cp.project / first.data["result"]).unlink()
    again = cp.report(cp.cid)
    assert again.data["round"] == 1 and again.data["result_exists"] is False
    assert not (cp.project / first.data["result"]).exists()


def test_corrupt_state_refused(cp):
    (cp.project / PRIVATE / cp.cid / "state.json").write_text("{not json")
    for result in (cp.show(cp.cid), cp.report(cp.cid), cp.suggest(cp.cid, [sug("S9")])):
        assert result.problems[0].code == "COLLAB_INVALID" and "copilot open" in result.next_steps[0]


def test_lock_held_refuses_with_retry(cp, monkeypatch):
    from x_ipe_secure_code.atomic import ProcessLock

    monkeypatch.setattr(copilot, "LOCK_TIMEOUT", 0.2)
    with ProcessLock(cp.project / ".x-ipe/private/secure-code/locks/copilot.lock"):
        result = cp.report(cp.cid)
    assert result.problems[0].code == "LOCKED" and "Retry" in result.next_steps[0]


@pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() == 0,
    reason="needs POSIX permissions as non-root",
)
def test_unreadable_bound_file_is_stale_and_named(cp):
    import os

    assert cp.review(cp.cid, [adoption("S1")]).ok
    path = cp.project / "src" / "register.py"
    os.chmod(path, 0)
    try:
        result = cp.report(cp.cid)
        s1 = by_id(cp.result_json(cp.cid, result.data["round"]))["S1"]
    finally:
        os.chmod(path, 0o644)
    assert s1["state"] == "stale" and s1["changed"] == [{"path": "src/register.py", "change": "unreadable"}]
