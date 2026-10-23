"""Black-box acceptance scenarios for FEATURE-002-A Guard verification (test-only artifact, TASK-024).

Calls the real CLI: `uvx --from <framework>/scripts secure-code ...`. Never imports toolkit code.

  python3 blackbox.py host                         # never-authorized User path (no trust writes)
  FAT_ISOLATED=1 python3 blackbox.py container     # Maintainer-prepared scenarios (disposable HOME only!)

Fixture note: evidence ageing for the 30-day cleanup (AC-002A-01e/01f) edits `ended_at` in the run
state and structured result of a concluded verification; the real clock cannot be advanced.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

TOOLKIT = (Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ
           else Path(__file__).resolve().parents[5] / "ai-secure-code-toolkit")
SCRIPTS = TOOLKIT / "x-ipe-secure-code-toolkit-framework" / "scripts"
GUARD_SKILL = TOOLKIT / "x-ipe-secure-code-toolkit-guard"
GUARD = ".x-ipe/private/secure-code/guard"
REPORTS = "x-ipe-docs/secure-code/reports/guard"
GLOCK = ".x-ipe/private/secure-code/locks/guard.lock"
PASS = "acceptance passphrase 42"
R1, R2 = "CWE/4.14/CWE-79", "CWE/4.14/CWE-89"
TOKEN = "ghp_" + "K" * 36
RESULTS: list[dict] = []


# ---------------------------------------------------------------- CLI helpers
def sc(*args: str):
    proc = subprocess.run(["uvx", "--from", str(SCRIPTS), "secure-code", *args], capture_output=True,
                          text=True, env=dict(os.environ), stdin=subprocess.DEVNULL, timeout=300)
    try:
        data = json.loads(proc.stdout) if "--json" in args else None
    except json.JSONDecodeError:
        data = None
    return proc.returncode, data, proc.stdout, proc.stderr


def sc_pty(answers: list[tuple[bytes, str]], *args: str) -> tuple[int, str]:
    """Run under a pseudo-terminal; answer each (prompt marker, text) in order."""
    import pty

    cmd = ["uvx", "--from", str(SCRIPTS), "secure-code", *args]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, dict(os.environ))
    out, sent, end = b"", 0, time.time() + 120
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if sent < len(answers) and out.lower().count(answers[sent][0]) > sum(
                1 for a in answers[:sent] if a[0] == answers[sent][0]):
            os.write(fd, answers[sent][1].encode() + b"\n")
            sent += 1
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


def esc(text: str) -> str:
    """Markdown source form of report cells (the report escapes `_`)."""
    return text.replace("_", "\\_")


def code_of(out: dict | None) -> str | None:
    return out["problems"][0]["code"] if out and out.get("problems") else None


def case(tc: str, acs: list[str], fn) -> None:
    try:
        checks = fn()
        failed = [n for n, ok in checks if not ok]
        detail = {"status": "Pass" if not failed else "Fail", "checks": [n for n, _ in checks], "failed": failed}
    except Exception as exc:  # noqa: BLE001 - every unexpected error is a failed case
        detail = {"status": "Fail", "error": f"{type(exc).__name__}: {exc}"}
    RESULTS.append({"tc": tc, "acs": acs, **detail})
    print(json.dumps(RESULTS[-1]), flush=True)


def tree(root: Path, skip: tuple[str, ...] = ()) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if any(rel == s or rel.startswith(s + "/") for s in skip):
            continue
        out[rel] = "link" if p.is_symlink() else ("dir" if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest())
    return out


def jfile(project: Path, doc: dict) -> str:
    path = Path(tempfile.mkstemp(suffix=".json", dir=project.parent)[1])
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------- fixtures
def item(rule: str, body: str = "Rule body.\n") -> dict:
    ns, ver, rid = rule.split("/")
    return {"namespace": ns, "version": ver, "rule_id": rid, "content": body,
            "source_location": f"https://example.org/{rid}"}


def new_project(rules=(R1, R2)) -> Path:
    root = Path(tempfile.mkdtemp(prefix="fat-ga-")) / "proj ü"
    root.mkdir()
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    if rules:
        batch = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": [item(r) for r in rules]}
        code, out, _, _ = sc("knowledge", "import", "--project", str(root), "--batch", jfile(root, batch), "--json")
        assert code == 0, out
    (root / "src").mkdir()
    (root / "src" / "login.py").write_text("def login(u):\n    return '<p>' + u\n")
    (root / "src" / "util.py").write_text("def helper():\n    return 1\n")
    (root / "README.md").write_text("# readme\n")
    (root / "cp.md").write_text("Copilot: looks fine\n")
    return root


def save_scope(p: Path, rules=(R1, R2), apply_all=False) -> str:
    args = ["policy", "resolve", "--project", str(p), "--json"]
    args += ["--all"] if apply_all else [x for r in rules for x in ("--rule", r)]
    code, prop, _, _ = sc(*args)
    assert code == 0, prop
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": "apply_all" if apply_all else "clues",
           "proposal_digest": prop["data"]["proposal_digest"], "clues": "login change",
           "language_context": ["python"], "confirmation_note": "user confirmed",
           "decisions": [{"ref": e["requested"], "decision": "adopted",
                          "state_digest": e["source_evidence"]["state_digest"]} for e in prop["data"]["entries"]]}
    if not apply_all:
        doc["considered"] = list(rules)
    code, out, _, _ = sc("scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed",
                         "--json")
    assert code == 0, out
    return out["data"]["scope_id"]


def change_rule(p: Path, rule: str, body: str) -> None:
    code, prop, _, _ = sc("policy", "resolve", "--project", str(p), "--rule", rule, "--json")
    base = prop["data"]["entries"][0]["source_evidence"]["state_digest"]
    upd = {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": body}
    code, out, _, _ = sc("knowledge", "update", "--project", str(p), "--rule", rule, "--base-state", base,
                         "--input", jfile(p, upd), "--json")
    assert code == 0, out


def _g(p: Path, cmd: str, vid: str | None = None, doc: dict | None = None, *extra: str):
    args = ["guard", cmd, "--project", str(p)]
    if vid:
        args += ["--run", vid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    return sc(*args, *extra, "--json")

def _extend(p: Path, vid: str) -> None:
    """The user extends the budget at a (pseudo) terminal when a scenario retries more than the default."""
    sc_pty([(b"verification id", vid)], "guard", "extend", "--project", str(p), "--run", vid, "--attempts", "10",
           "--reason", "acceptance scenario retries")


# FEATURE-002-C: records and Reviewer records cite an attempt registered before the work (call sequence only)
ATTEMPT = "ai-secure-code-toolkit/guard-attempt/v1"


def _covers(p: Path, vid: str, cmd: str, doc: dict):
    try:
        if cmd == "review":
            subjects = [s for s in doc.get("subjects") or [] if isinstance(s, dict)]
            findings = sorted({s["id"] for s in subjects if s.get("type") == "finding"})
            na = sorted({s["id"] for s in subjects if s.get("type") == "na_decision"})
            return ("reviewer", {"findings": findings, "na": na}) if findings or na else None
        if not (doc.get("evidence") or doc.get("findings")):
            return None
        plan = json.loads((p / GUARD / vid / "state.json").read_text()).get("plan") or {}
        methods = {c["id"]: [m["name"] for m in c["methods"]] for c in plan.get("checks", [])}
        pairs = {(c, e["method"]) for e in doc.get("evidence") or [] for c in e.get("checks") or []}
        for f in doc.get("findings") or []:
            if f.get("check") in methods and not any(x[0] == f["check"] for x in pairs):
                pairs.add((f["check"], methods[f["check"]][0]))
        if not pairs and methods:
            first = sorted(methods)[0]
            pairs.add((first, methods[first][0]))
        return "semantic_review", {"pairs": [{"check": c, "method": m} for c, m in sorted(pairs)]}
    except (TypeError, KeyError, AttributeError, ValueError, OSError):
        return None


def _with_attempt(p: Path, vid: str, cmd: str, doc: dict) -> dict:
    needed = None if "attempt" in doc else _covers(p, vid, cmd, doc)
    if needed is None:
        return doc
    req = {"schema": ATTEMPT, "kind": needed[0], "covers": needed[1]}
    code, out, _, _ = _g(p, "attempt", vid, req)
    if code != 0 and out and out["problems"][0]["code"] == "ATTEMPTS_EXHAUSTED":
        _extend(p, vid)
        code, out, _, _ = _g(p, "attempt", vid, req)
    return {**doc, "attempt": out["data"]["attempt"]} if code == 0 else doc


def g(p: Path, cmd: str, vid: str | None = None, doc: dict | None = None, *extra: str):
    if cmd in ("record", "review") and vid and isinstance(doc, dict):
        side = ("conflicts", "method_changes")
        if cmd == "record" and (doc.get("evidence") or doc.get("findings")) and any(doc.get(k) for k in side):
            first = _g(p, cmd, vid, {k: v for k, v in doc.items() if k == "schema" or k in side}, *extra)
            if first[0] != 0:
                return first
            doc = {k: v for k, v in doc.items() if k not in side}
        doc = _with_attempt(p, vid, cmd, doc)
    return _g(p, cmd, vid, doc, *extra)



def open_doc(scope: str, **over) -> dict:
    doc = {"schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope,
           "targets": [{"path": "src/login.py", "change": "modified"}], "context": [{"path": "README.md"}]}
    doc.update(over)
    return doc


def opened(p: Path, scope: str, **over) -> tuple[str, dict]:
    code, out, _, err = g(p, "open", doc=open_doc(scope, **over))
    assert code == 0, (out, err)
    return out["data"]["verification_id"], {t["path"]: t["digest"] for t in out["data"]["targets"]}


C1 = {"id": "C1", "rule": R1, "object": ["src/login.py"],
      "methods": [{"name": "semantic-review", "kind": "reading", "required": True}], "minimum_evidence": ["reading"]}


def with_choice(check: dict) -> dict:
    """FEATURE-002-B: checks with several methods record a method choice (all methods selected here)."""
    if len(check.get("methods", [])) > 1 and "method_choice" not in check:
        names = [m["name"] for m in check["methods"]]
        check = {**check, "method_choice": {"considered": names, "selected": names, "reason": "acceptance fixture"}}
    return check


def plan_doc(**over) -> dict:
    doc = {"schema": "ai-secure-code-toolkit/guard-plan/v1", "checks": [C1],
           "not_applicable": [{"rule": R2, "reason": "no database access in the target"}]}
    doc.update(over)
    doc["checks"] = [with_choice(c) for c in doc["checks"]]
    return doc


def rec(**parts) -> dict:
    return {"schema": "ai-secure-code-toolkit/guard-record/v1", **parts}


def ev(eid="E1", **over) -> dict:
    e = {"id": eid, "kind": "reading", "method": "semantic-review", "method_status": "ok", "checks": ["C1"],
         "paths": ["src/login.py"], "summary": "read login()"}
    e.update(over)
    return e


def fnd(fid="F1", **over) -> dict:
    f = {"id": fid, "rule": R1, "check": "C1", "location": {"path": "src/login.py", "line": 2}, "cwe": "CWE-79",
         "title": "Unescaped user input in HTML", "source": "semantic", "severity": "high", "evidence": ["E1"]}
    f.update(over)
    return f


def review_doc(digests: dict, subjects: list, paths=("src/login.py",), **over) -> dict:
    doc = {"schema": "ai-secure-code-toolkit/reviewer-record/v1",
           "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
           "requirement": "Re-check verdict-affecting findings and N/A decisions",
           "reviewed_targets": [{"path": x, "digest": digests[x]} for x in paths], "subjects": subjects}
    doc.update(over)
    return doc


NA_OK = {"type": "na_decision", "id": f"policy:{R2}", "result": "confirmed", "basis": "no SQL"}


def confirm(fid="F1", **over) -> dict:
    return {"type": "finding", "id": fid, "result": "confirmed", "basis": "input reaches HTML", **over}


def run(p: Path, scope: str, record: dict, subjects: list, plan: dict | None = None, **open_over):
    """open → plan → record → review → conclude; returns (vid, conclude output, digests)."""
    vid, digests = opened(p, scope, **open_over)
    assert g(p, "plan", vid, plan or plan_doc())[0] == 0
    code, out, _, _ = g(p, "record", vid, record)
    assert code == 0, out
    if subjects:
        code, out, _, _ = g(p, "review", vid, review_doc(digests, subjects))
        assert code == 0, out
    code, out, _, err = g(p, "conclude", vid)
    assert code == 0, (out, err)
    return vid, out, digests


def result(p: Path, vid: str) -> dict:
    return json.loads((p / REPORTS / f"{vid}.json").read_text())


def md(p: Path, vid: str) -> str:
    return (p / REPORTS / f"{vid}.md").read_text()


def reasons(out: dict) -> list[str]:
    return [r["code"] for r in out["data"]["reasons"]]


def row(res: dict, check: str) -> dict:
    return next(r for r in res["ledger"] if r["check"] == check)


FAIL_RECORD = rec(evidence=[ev()], findings=[fnd()],
                  ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}])
MET_RECORD = rec(evidence=[ev()], ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])


# ---------------------------------------------------------------- container cases
def tc_fail_report():
    p = new_project()
    scope = save_scope(p)
    allowed = (GUARD, REPORTS, ".x-ipe/private/secure-code/locks")
    before = tree(p, allowed)
    vid, out, digests = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    res, text = result(p, vid), md(p, vid)
    return [
        ("01a md and json named by id beside each other", (p / REPORTS / f"{vid}.md").is_file()),
        ("01a same verdict", out["data"]["verdict"] == res["verdict"] == "fail" and "**Verdict: Fail**" in text),
        ("01a/01b findings, ledger, targets, Policies identical in md",
         all(f["id"] in text and f["final_severity"] in text for f in res["findings"])
         and all(r["check"] in text for r in res["ledger"])
         and all(t["path"] in text and t["digest_at_open"] in text for t in res["artifact"]["targets"])
         and all(a["rule"] in text for a in res["scope"]["adopted"]) and scope in text),
        ("01a each ledger state and finding severity/review identical in md rows",
         all(any(line.startswith(f"| {r['check']} |") and f"| {esc(r['state'])} |" in line for line in text.splitlines())
             for r in res["ledger"])
         and all(any(line.startswith(f"| {f['id']} |") and f"| {f['final_severity']} |" in line
                     and f"| {esc(f['review'])}" in line for line in text.splitlines()) for f in res["findings"])),
        ("01b id, context, plan, reviews validity, reasons, acceptances, retention in report",
         vid in text and "README.md" in text and "## Check Plan" in text and "## Reviewer Records" in text
         and "CONFIRMED_FINDING" in text and "## Risk Acceptances" in text and "30 days" in text
         and res["evidence_retention"]["location"] in text),
        ("01c run state under private run folder", (p / GUARD / vid / "state.json").is_file()),
        ("02a opened without any Copilot report", res["artifact"]["copilot_reports"] == []),
        ("03c scope id, rules, confirmed digests recorded",
         res["scope"]["scope_id"] == scope and [a["rule"] for a in res["scope"]["adopted"]] == [R1, R2]
         and all(a["state_digest"].startswith("sha256:") for a in res["scope"]["adopted"])),
        ("04c one state per check, no percentage", all(r["state"] for r in res["ledger"])
         and "%" not in json.dumps(res) and "score" not in json.dumps(res).lower()),
        ("05c confirmed with original source and Reviewer basis kept",
         res["findings"][0]["review"] == "confirmed" and res["findings"][0]["source"] == "semantic"
         and res["findings"][0]["review_basis"] == ["input reaches HTML"]),
        ("06a confirmed High → Fail", out["data"]["verdict"] == "fail"),
        ("06g reasons listed", reasons(out) == ["CONFIRMED_FINDING"]),
        ("08a targets/context byte-identical; only run folder, reports, locks written", tree(p, allowed) == before),
        ("NFR exit 0 for a Fail conclusion; next step leaves fixing to executor",
         "does not fix" in out["next_steps"][0]),
    ]


def tc_masking():
    p = new_project()
    scope = save_scope(p)
    vid, _ = opened(p, scope, request=f"verify {TOKEN}")
    g(p, "plan", vid, plan_doc())
    out_file = p / ".x-ipe/private/secure-code/tmp/scan.txt"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(f"tool output\n-----BEGIN PRIVATE KEY-----\nMIIEsecret\n-----END PRIVATE KEY-----\n{TOKEN}\n")
    code, out, _, _ = g(p, "record", vid, rec(evidence=[ev(content_file=".x-ipe/private/secure-code/tmp/scan.txt",
                                                       summary=f"token {TOKEN} seen")],
                                          ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]))
    g(p, "conclude", vid)
    stored = (p / GUARD / vid / "evidence" / "E1.txt").read_text()
    texts = [stored, (p / GUARD / vid / "state.json").read_text(), json.dumps(result(p, vid)), md(p, vid)]
    return [
        ("01d recorded", code == 0 and out["data"]["masked"] == ["E1"]),
        ("01d token and key masked everywhere", all(TOKEN not in t and "MIIEsecret" not in t for t in texts)),
        ("01d stored evidence carries markers", "[masked:credential.token]" in stored
         and "[masked:credential.private_key]" in stored),
        ("01d labelled masked in result and report", result(p, vid)["evidence"][0]["masked"] is True
         and "masked (credential.private\\_key, credential.token)" in md(p, vid)),  # Markdown-escaped "_"
        ("01c report refers to evidence location, not raw content", "evidence/E1.txt" in md(p, vid)
         and "tool output" not in md(p, vid)),
    ]


def _age(p: Path, vid: str, days: int) -> None:
    ended = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for path in (p / GUARD / vid / "state.json", p / REPORTS / f"{vid}.json"):
        doc = json.loads(path.read_text())
        doc["ended_at"] = ended
        path.write_text(json.dumps(doc))


def tc_retention():
    p = new_project()
    scope = save_scope(p)
    old, _, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    recent, _, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    kept_one, _, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    running, _ = opened(p, scope)
    _age(p, old, 31)
    _age(p, recent, 29)
    _age(p, kept_one, 40)
    g(p, "show", old)  # reading never extends retention
    ck, keep_out, _, _ = sc("guard", "keep", "--project", str(p), "--run", kept_one, "--reason", "pending release",
                            "--json")
    c1, first, _, _ = g(p, "cleanup")
    _, shown, _, _ = g(p, "show", old)
    reports_ok = all((p / REPORTS / f"{v}.{s}").is_file() for v in (old, recent, kept_one) for s in ("json", "md"))
    cr, rel, _, _ = g(p, "release", kept_one)
    _, second, _, _ = g(p, "cleanup")
    kept = {k["verification_id"]: k["reason"] for k in first["data"]["kept"]}
    return [
        ("01e only the 31-day run removed", c1 == 0
         and [r["verification_id"] for r in first["data"]["removed"]] == [old]),
        ("01e running untouched", "running" in kept[running] and (p / GUARD / running).is_dir()),
        ("01e 29-day run retained", "retained until" in kept[recent] and (p / GUARD / recent).is_dir()),
        ("01e all reports remain", reports_ok),
        ("01f keep marker named with reason", ck == 0 and kept[kept_one] == "keep marker: pending release"),
        ("01f released then removed", cr == 0 and rel["data"]["released"] is True
         and [r["verification_id"] for r in second["data"]["removed"]] == [kept_one]),
        ("01g show without evidence keeps findings and verdict", shown["data"]["evidence_available"] is False
         and shown["data"]["verdict"] == "fail" and "no longer available" in shown["data"]["evidence"]
         and shown["data"]["findings"][0]["id"] == "F1" and "**Verdict: Fail**" in md(p, old)),
    ]


def tc_two_versions():
    p = new_project()
    scope = save_scope(p)
    first, _, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    (p / "src" / "login.py").write_text("def login(u):\n    return '<p>' + escape(u)\n")
    second, out2, _ = run(p, scope, MET_RECORD, [NA_OK])
    _, s1, _, _ = g(p, "show", first)
    _, s2, _, _ = g(p, "show", second)
    return [
        ("01h each verification has its own report", first != second and (p / REPORTS / f"{first}.md").is_file()
         and (p / REPORTS / f"{second}.md").is_file()),
        ("01h older report flagged for changed target", s1["data"]["targets_now"] == "changed"
         and any("does not describe the current version" in s for s in s1["next_steps"])),
        ("01h newer report current", s2["data"]["targets_now"] == "unchanged" and out2["data"]["verdict"] == "pass"),
    ]


def tc_copilot_context():
    p = new_project()
    scope = save_scope(p)
    vid, out, _ = run(p, scope, rec(evidence=[ev(paths=["cp.md"])],
                                    ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]),
                      [NA_OK], copilot_reports=[{"path": "cp.md"}])
    res = result(p, vid)
    return [
        ("02b check not met by Copilot report", row(res, "C1")["state"] == "unconfirmed"
         and out["data"]["verdict"] == "cannot_confirm_pass"),
        ("02b Copilot report listed as context", res["artifact"]["copilot_reports"][0]["path"] == "cp.md"
         and "never evidence of a pass" in md(p, vid)),
    ]


def tc_unlisted_toolkit_data():
    p = new_project()
    scope = save_scope(p)
    report = p / "x-ipe-docs/secure-code/reports/copilot/c-1.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("Copilot: all fine\n")
    scratch = p / ".x-ipe/private/secure-code/tmp/notes.txt"
    scratch.parent.mkdir(parents=True, exist_ok=True)
    scratch.write_text("agent notes\n")
    vid, _ = opened(p, scope, targets=[], whole_project=True, context=[])
    g(p, "plan", vid, plan_doc(checks=[{**C1, "object": ["."]}]))
    outs = {x: g(p, "record", vid, rec(evidence=[ev(paths=[x])],
                                       ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]))
            for x in ("x-ipe-docs/secure-code/reports/copilot/c-1.md", ".x-ipe/private/secure-code/tmp/notes.txt")}
    g(p, "record", vid, rec(evidence=[ev(paths=["src/login.py"])]))
    _, out, _, _ = g(p, "conclude", vid)
    return [
        ("02b/BR-02 unlisted Copilot report in whole-project run is not target evidence",
         all(o[0] == 1 and code_of(o[1]) == "RECORD_INVALID" for o in outs.values())),
        ("02b/BR-02 no Pass from toolkit data", out["data"]["verdict"] != "pass"
         and row(result(p, vid), "C1")["state"] == "unconfirmed"),
    ]


def tc_artifact_scope():
    p = new_project()
    scope = save_scope(p, apply_all=True)
    c1, o1, _, _ = g(p, "open", doc=open_doc(scope, targets=[{"path": "src/login.py"}, {"path": "src/util.py"}],
                                             context=[]))
    c2, o2, _, _ = g(p, "open", doc=open_doc(scope, targets=[{"path": "."}]))
    c3, o3, _, _ = g(p, "open", doc=open_doc(scope, targets=[], whole_project=True, context=[]))
    return [
        ("02c Apply All + two files → exactly two targets", c1 == 0
         and [t["path"] for t in o1["data"]["targets"]] == ["src/login.py", "src/util.py"]),
        ("02c whole project without explicit choice refused", c2 == 1
         and code_of(o2) == "WHOLE_PROJECT_NOT_EXPLICIT" and o2["next_steps"]),
        ("02c explicit whole project accepted", c3 == 0 and [t["path"] for t in o3["data"]["targets"]] == ["."]
         and o3["data"]["whole_project"] is True),
    ]


def tc_roles():
    p = new_project()
    scope = save_scope(p)
    c1, o1, _, _ = g(p, "open", doc=open_doc(scope, context=[{"path": "src/login.py"}]))
    vid, out, _ = run(p, scope, rec(evidence=[ev(paths=["README.md"])],
                                    ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]), [NA_OK],
                      suggested=[{"path": "src/util.py", "reason": "called by login"}])
    res, text = result(p, vid), md(p, vid)
    return [
        ("02d same path in two roles refused", c1 == 1 and code_of(o1) == "ROLE_CONFLICT"),
        ("02d roles kept separate", [c["path"] for c in res["artifact"]["context"]] == ["README.md"]
         and res["artifact"]["suggested"] == [{"path": "src/util.py", "reason": "called by login"}]
         and [t["path"] for t in res["artifact"]["targets"]] == ["src/login.py"]),
        ("02d context and suggested reported as not verified", "Read-only context (not verified)" in text
         and "Suggested files (not verified)" in text),
        ("02d context-only evidence cannot meet a target check", row(res, "C1")["state"] == "unconfirmed"),
    ]


def tc_change_meaning():
    p = new_project()
    scope = save_scope(p)
    (p / "src" / "new.py").write_text("x = 1\n")
    vid, _ = opened(p, scope, targets=[{"path": "src/new.py", "change": "added"},
                                       {"path": "src/old.py", "change": "deleted"},
                                       {"path": "src/util.py", "change": "renamed", "old_path": "src/helpers.py"}])
    plan = plan_doc(checks=[{**C1, "object": ["src/old.py", "src/new.py"]}])
    g(p, "plan", vid, plan)
    g(p, "record", vid, rec(evidence=[ev(paths=["src/old.py", "src/new.py"])],
                            ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]))
    g(p, "conclude", vid)
    t = {x["path"]: x for x in result(p, vid)["artifact"]["targets"]}
    return [
        ("02e added file is a target with digest", t["src/new.py"]["change"] == "added"
         and t["src/new.py"]["digest_at_open"].startswith("sha256:")),
        ("02e deleted recorded without digest, usable for impact checks", t["src/old.py"]["digest_at_open"] is None
         and t["src/old.py"]["change"] == "deleted" and row(result(p, vid), "C1")["object"][0] == "src/old.py"),
        ("02e rename keeps old and new path", t["src/util.py"]["old_path"] == "src/helpers.py"),
    ]


def tc_invalid_targets():
    p = new_project()
    scope = save_scope(p)
    os.symlink(p / "src" / "login.py", p / "link.py")
    outs = [g(p, "open", doc=open_doc(scope, targets=[{"path": x}])) for x in ("missing.py", "../x.py", "link.py")]
    return [(f"02f {x} refused with path and next step", o[0] == 1 and code_of(o[1]) == "TARGET_INVALID"
             and o[1]["next_steps"] and "Traceback" not in o[3])
            for x, o in zip(("missing.py", "../x.py", "link.py"), outs, strict=True)] + [
        ("02f nothing opened", not (p / GUARD).exists() or not any((p / GUARD).iterdir()))]


def tc_maintenance():
    p = new_project()
    scope = save_scope(p, rules=(R1,))
    c1, o1, _, _ = g(p, "open", doc=open_doc(""))
    change_rule(p, R1, "Changed body.\n")
    c2, o2, t2, _ = g(p, "open", doc=open_doc(scope))
    return [
        ("03a no scope → maintenance needed with Framework next step", c1 == 1
         and code_of(o1) == "MAINTENANCE_NEEDED" and "Framework" in o1["next_steps"][0]),
        ("03a all adopted changed → maintenance needed", c2 == 1 and code_of(o2) == "MAINTENANCE_NEEDED"),
        ("03a no verification opened, no report, no Pass/100%",
         (not (p / GUARD).exists() or not any((p / GUARD).iterdir()))
         and (not (p / REPORTS).exists() or not any((p / REPORTS).iterdir()))
         and "verdict" not in o2["data"] and "100%" not in t2),
    ]


def tc_partial():
    p = new_project()
    scope = save_scope(p)
    change_rule(p, R2, "Changed body.\n")
    code, out, _, _ = g(p, "open", doc=open_doc(scope))
    return [("03b partial refused listing available/changed/missing", code == 1 and code_of(out) == "SCOPE_PARTIAL"
             and out["data"]["adopted"] == [R1] and out["data"]["needs_reconfirmation"] == [R2]
             and out["data"]["missing"] == []),
            ("03b next step: confirm a new scope", "scope save" in out["next_steps"][0])]


def tc_plan_rules():
    p = new_project()
    scope = save_scope(p)
    vid, _ = opened(p, scope)
    outside = g(p, "plan", vid, plan_doc(checks=[{**C1, "rule": "CWE/4.14/CWE-22"}]))
    no_method = g(p, "plan", vid, plan_doc(checks=[{**C1, "methods": []}]))
    no_object = g(p, "plan", vid, plan_doc(checks=[{k: v for k, v in C1.items() if k != "object"}]))
    no_minimum = g(p, "plan", vid, plan_doc(checks=[{k: v for k, v in C1.items() if k != "minimum_evidence"}]))
    no_reason = g(p, "plan", vid, plan_doc(not_applicable=[{"rule": R2, "reason": ""}]))
    uncovered = g(p, "plan", vid, plan_doc(not_applicable=[]))
    ok = g(p, "plan", vid, plan_doc())
    return [
        ("03d rule outside adopted scope refused", outside[0] == 1 and code_of(outside[1]) == "PLAN_INVALID"
         and "adopted scope" in outside[1]["problems"][0]["message"]),
        ("04a missing method/object/minimum evidence refused",
         all(o[0] == 1 and code_of(o[1]) == "PLAN_INVALID" for o in (no_method, no_object, no_minimum))),
        ("04b N/A needs factual reason", no_reason[0] == 1 and code_of(no_reason[1]) == "PLAN_INVALID"),
        ("04b uncovered adopted rule refused, one check per rule suffices",
         code_of(uncovered[1]) == "PLAN_INCOMPLETE" and ok[0] == 0 and ok[1]["data"]["checks"] == ["C1"]),
    ]


def tc_ledger_rules():
    p = new_project()
    scope = save_scope(p)
    vid, _ = opened(p, scope)
    g(p, "plan", vid, plan_doc())
    na_refused = g(p, "record", vid, rec(ledger=[{"check": "C1", "state": "n/a", "reason_type": "method_unavailable",
                                                  "reason": "no tool"}]))
    # runtime minimum with reading only (04d); auxiliary vs required failure (04j); unexecuted check (04g)
    methods = [{"name": "semantic-review", "kind": "reading", "required": True},
               {"name": "custom-scan", "kind": "runtime", "required": False}]
    plan = plan_doc(checks=[{**C1, "id": "C1", "minimum_evidence": ["runtime"]},
                            {**C1, "id": "C2", "methods": methods, "minimum_evidence": ["reading", "runtime"]},
                            {**C1, "id": "C3", "methods": [dict(m, required=True) for m in methods],
                             "minimum_evidence": ["reading", "runtime"]},
                            {**C1, "id": "C4"}])
    p2 = new_project()
    scope2 = save_scope(p2)
    record = rec(evidence=[ev(checks=["C1", "C2", "C3"]),
                           ev("E2", kind="runtime", method="custom-scan", method_status="failed", checks=["C2", "C3"],
                              summary="custom-scan unavailable")],
                 ledger=[{"check": c, "state": "met", "evidence": ["E1", "E2"] if c != "C1" else ["E1"]}
                         for c in ("C1", "C2", "C3")])
    vid2, out2, _ = run(p2, scope2, record, [NA_OK], plan=plan)
    res = result(p2, vid2)
    return [
        ("04e N/A for unavailable method refused, must be unconfirmed", na_refused[0] == 1
         and code_of(na_refused[1]) == "NA_NOT_OBJECTIVE" and "unconfirmed" in na_refused[1]["next_steps"][0]),
        ("04d runtime minimum not met by reading", row(res, "C1")["state"] == "unconfirmed"
         and "runtime" in row(res, "C1")["reason"]),
        ("04j auxiliary failure substituted, shown", row(res, "C2")["state"] == "met"
         and row(res, "C2")["substitution"] == [{"method": "custom-scan", "status": "failed"}]),
        ("04j required failure stays unconfirmed", row(res, "C3")["state"] == "unconfirmed"
         and "custom-scan" in row(res, "C3")["reason"]),
        ("04g planned check without state → unconfirmed not executed", row(res, "C4")["state"] == "unconfirmed"
         and "not executed" in row(res, "C4")["reason"]),
        ("06d zero findings + unconfirmed → Cannot confirm pass", out2["data"]["verdict"] == "cannot_confirm_pass"
         and res["findings"] == []),
    ]


def tc_exclusion():
    p = new_project()
    scope = save_scope(p)
    plan = plan_doc(checks=[C1, {**C1, "id": "C2"}], exclusions=[{"check": "C2", "reason": "user: later"}])
    vid, out, _ = run(p, scope, MET_RECORD, [NA_OK], plan=plan)
    vid2, out2, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK], plan=plan)
    res = result(p, vid)
    return [
        ("04f exclusion separate from N/A and met", row(res, "C2")["state"] == "excluded"
         and "User scope exclusions" in md(p, vid)),
        ("06i exclusion + otherwise Pass → Cannot confirm pass", out["data"]["verdict"] == "cannot_confirm_pass"
         and reasons(out) == ["SCOPE_EXCLUSION"]),
        ("06i + confirmed High → Fail", out2["data"]["verdict"] == "fail"
         and "SCOPE_EXCLUSION" in [r["code"] for r in out2["data"]["other_blockers"]]),
    ]


def tc_na_review():
    p = new_project()
    scope = save_scope(p)
    unreviewed, o1, _ = run(p, scope, MET_RECORD, [])
    check_na = rec(evidence=[ev()], ledger=[{"check": "C1", "state": "n/a", "reason_type": "objective",
                                             "reason": "login() renders no HTML"}])
    confirmed, o2, _ = run(p, scope, check_na,
                           [NA_OK, {"type": "na_decision", "id": "C1", "result": "confirmed", "basis": "no HTML"}])
    rejected, o3, _ = run(p, scope, check_na,
                          [NA_OK, {"type": "na_decision", "id": "C1", "result": "rejected", "basis": "it does"}])
    return [
        ("04h unreviewed policy N/A → unconfirmed", row(result(p, unreviewed), f"policy:{R2}")["state"]
         == "unconfirmed" and o1["data"]["verdict"] == "cannot_confirm_pass"),
        ("04h reviewed check and policy N/A count", row(result(p, confirmed), "C1")["state"] == "n/a"
         and o2["data"]["verdict"] == "pass"),
        ("04h rejected N/A → unconfirmed with reason", row(result(p, rejected), "C1")["state"] == "unconfirmed"
         and "rejected" in row(result(p, rejected), "C1")["reason"]),
    ]


def tc_kinds():
    p = new_project()
    scope = save_scope(p)
    methods = [{"name": "semantic-review", "kind": "reading", "required": True},
               {"name": "design-doc", "kind": "document", "required": False}]
    record = rec(evidence=[ev(), ev("E2", kind="document", method="design-doc", summary="design says escaped")],
                 ledger=[{"check": "C1", "state": "met", "evidence": ["E1", "E2"]}])
    vid, _, _ = run(p, scope, record, [NA_OK], plan=plan_doc(checks=[{**C1, "methods": methods}]))
    res = result(p, vid)
    bad = new_project()
    bscope = save_scope(bad)
    bvid, _ = opened(bad, bscope)
    g(bad, "plan", bvid, plan_doc(checks=[{**C1, "methods": methods + [
        {"name": "custom-scan", "kind": "runtime", "required": False}]}]))
    mislabeled = g(bad, "record", bvid, rec(evidence=[ev(method="custom-scan", summary="reasoning about a tool")]))
    return [
        ("04i kinds kept separate", row(res, "C1")["evidence_by_kind"] == {"document": ["E2"], "reading": ["E1"]}
         and "document: E2" in md(p, vid) and "reading: E1" in md(p, vid)),
        ("04i reading cannot be recorded as runtime method evidence", mislabeled[0] == 1
         and code_of(mislabeled[1]) == "RECORD_INVALID"),
    ]


def tc_merge():
    p = new_project()
    scope = save_scope(p)
    vid, _ = opened(p, scope)
    g(p, "plan", vid, plan_doc())
    two = g(p, "record", vid, rec(evidence=[ev(), ev("E2", summary="second report")],
                                  findings=[fnd(), fnd("F2", evidence=["E2"], source="custom-scan")]))
    no_ev = g(p, "record", vid, rec(findings=[fnd("F3", merged_from=["F1", "F2"])]))
    merged = g(p, "record", vid, rec(findings=[fnd("F3", merged_from=["F1", "F2"], merge_evidence=["E1"])]))
    g(p, "conclude", vid)
    res = result(p, vid)
    ids = [f["id"] for f in res["findings"]]
    return [
        ("05a same location/CWE, different evidence stay separate", two[0] == 0 and {"F1", "F2"} <= set(ids)),
        ("05a merge without evidence refused", no_ev[0] == 1 and "merge_evidence" in no_ev[1]["problems"][0]["message"]),
        ("05a merge records its evidence; sources kept", merged[0] == 0 and ids == ["F1", "F2", "F3"]
         and next(f for f in res["findings"] if f["id"] == "F3")["merge_evidence"] == ["E1"]
         and next(f for f in res["findings"] if f["id"] == "F1")["merged_into"] == "F3"),
    ]


def tc_review_states():
    p = new_project()
    scope = save_scope(p)
    unreviewed, o1, _ = run(p, scope, FAIL_RECORD, [NA_OK])
    disputed_low = rec(evidence=[ev()], findings=[fnd(severity="low", disputed=True)],
                       ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])
    _, o2, _ = run(p, scope, disputed_low, [NA_OK])
    could_not, o3, _ = run(p, scope, FAIL_RECORD,
                           [NA_OK, {"type": "finding", "id": "F1", "result": "unconfirmed", "basis": "unclear"}])
    f3 = result(p, could_not)["findings"][0]
    return [
        ("05b unreviewed High stays unconfirmed, no Pass", result(p, unreviewed)["findings"][0]["review"]
         == "unconfirmed" and o1["data"]["verdict"] == "cannot_confirm_pass"
         and "FINDING_UNCONFIRMED" in reasons(o1)),
        ("05b disputed Low needs review", "FINDING_UNCONFIRMED" in reasons(o2)),
        ("05d Reviewer could not confirm → unconfirmed, kept, not false positive", f3["review"] == "unconfirmed"
         and f3["id"] == "F1" and o3["data"]["verdict"] == "cannot_confirm_pass"),
    ]


def tc_review_validity():
    p = new_project()
    scope = save_scope(p)
    vid, digests = opened(p, scope)
    g(p, "plan", vid, plan_doc())
    g(p, "record", vid, FAIL_RECORD)
    c_inc, inc, _, _ = g(p, "review", vid, review_doc(digests, [confirm(), NA_OK], requirement="",
                                                        invocation={"agent": "x", "read_only": True}))
    g(p, "review", vid, review_doc(digests, [confirm(), NA_OK]))
    (p / "src" / "login.py").write_text("changed after review\n")
    _, out, _, _ = g(p, "conclude", vid)
    res = result(p, vid)
    p2 = new_project()
    s2 = save_scope(p2)
    v2, d2 = opened(p2, s2)
    g(p2, "plan", v2, plan_doc())
    g(p2, "record", v2, FAIL_RECORD)
    authority = g(p2, "review", v2, review_doc(d2, [confirm()], risk_acceptances=[{"finding": "F1"}],
                                               targets=["src/util.py"]))
    ledger_try = g(p2, "review", v2, review_doc(d2, [confirm()], ledger=[{"check": "C1", "state": "met"}]))
    return [
        ("05e incomplete record stored with warnings", c_inc == 0 and "requirement is missing"
         in inc["data"]["completeness"] and "invocation.host is missing" in inc["data"]["completeness"]),
        ("05e incomplete → not valid, report says why", res["reviews"][0]["valid"] is False
         and "requirement is missing" in res["reviews"][0]["invalid_reasons"]
         and "requirement is missing" in md(p, vid)),
        ("05f stale review invalid; finding back to unconfirmed", res["reviews"][1]["valid"] is False
         and any("stale" in r for r in res["reviews"][1]["invalid_reasons"])
         and res["findings"][0]["review"] == "unconfirmed" and out["data"]["verdict"] == "cannot_confirm_pass"),
        ("05g extra authority refused, nothing stored", authority[0] == 1 and code_of(authority[1])
         == "REVIEW_AUTHORITY" and code_of(ledger_try[1]) == "REVIEW_AUTHORITY"
         and json.loads((p2 / GUARD / v2 / "state.json").read_text())["reviews"] == []),
    ]


def tc_verdicts():
    p = new_project()
    scope = save_scope(p)
    low = rec(evidence=[ev()], findings=[fnd(severity="low"), fnd("F2", severity="info")],
              ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])
    v_pass, o_pass, _ = run(p, scope, low, [NA_OK])
    unknown = rec(evidence=[ev()], findings=[fnd(severity="unknown")],
                  ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])
    _, o_unknown, _ = run(p, scope, unknown, [NA_OK, confirm()])
    v_c1, o_c1, _ = run(p, scope, FAIL_RECORD, [NA_OK, confirm(severity_opinion={"severity": "low"})])
    v_c2, o_c2, _ = run(p, scope, FAIL_RECORD,
                        [NA_OK, confirm(severity_opinion={"severity": "low", "evidence": ["E1"]})])
    conflict = rec(evidence=[ev()], ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}],
                   conflicts=[{"id": "K1", "kind": "requirement", "description": "design wants raw HTML",
                               "verdict_affecting": True, "resolved": False}])
    _, o_conf, _ = run(p, scope, conflict, [NA_OK])
    fp = rec(evidence=[ev()], findings=[fnd(), fnd("F2", severity="info")],
             ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])
    v_fp, o_fp, _ = run(p, scope, fp, [NA_OK, {"type": "finding", "id": "F1", "result": "false_positive",
                                               "basis": "escaped by template", "evidence": ["E1"]}])
    f1, f2 = result(p, v_c1)["findings"][0], result(p, v_c2)["findings"][0]
    return [
        ("06b only Low/Info, all met → Pass, Low reported", o_pass["data"]["verdict"] == "pass"
         and "F1" in md(p, v_pass) and "low" in md(p, v_pass)),
        ("06c confirmed unknown severity → Cannot confirm pass", o_unknown["data"]["verdict"] == "cannot_confirm_pass"
         and "SEVERITY_UNKNOWN" in reasons(o_unknown)),
        ("06e unevidenced lower opinion: higher stands, conflict shown", f1["final_severity"] == "high"
         and f1["severity_conflict"] and o_c1["data"]["verdict"] == "fail"),
        ("06e evidenced lower opinion used, originals kept", f2["final_severity"] == "low"
         and f2["original_severity"] == "high" and f2["severity_opinion"]["severity"] == "low"
         and o_c2["data"]["verdict"] != "fail"),
        ("06f unresolved conflict prevents Pass, listed", o_conf["data"]["verdict"] == "cannot_confirm_pass"
         and reasons(o_conf) == ["CONFLICT_UNRESOLVED"]),
        ("06k false positive and Info never fail, kept with evidence", o_fp["data"]["verdict"] == "pass"
         and result(p, v_fp)["findings"][0]["review"] == "false_positive"
         and result(p, v_fp)["findings"][0]["evidence"] == ["E1"] and "F2" in md(p, v_fp)),
        ("06g Pass lists its reason", reasons(o_pass) == ["ALL_CHECKS_SATISFIED"]),
    ]


def tc_determinism():
    p = new_project()
    scope = save_scope(p)
    vid, first, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    j1, m1 = (p / REPORTS / f"{vid}.json").read_bytes(), md(p, vid)
    _, second, _, _ = g(p, "conclude", vid)
    (p / REPORTS / f"{vid}.md").unlink()
    _, third, _, _ = g(p, "conclude", vid)
    return [
        ("06h conclude twice: same result and files", first == second
         and (p / REPORTS / f"{vid}.json").read_bytes() == j1),
        ("NFR-3 missing report repaired identically", md(p, vid) == m1 and third == first),
    ]


def tc_changes():
    p = new_project()
    scope = save_scope(p)
    vid, digests = opened(p, scope)
    g(p, "plan", vid, plan_doc())
    g(p, "record", vid, MET_RECORD)
    g(p, "review", vid, review_doc(digests, [NA_OK]))
    (p / "src" / "login.py").write_text("changed\n")
    _, o1, _, _ = g(p, "conclude", vid)
    (p / "src" / "login.py").write_text("def login(u):\n    return '<p>' + u\n")
    vid2, d2 = opened(p, scope)
    g(p, "plan", vid2, plan_doc())
    g(p, "record", vid2, MET_RECORD)
    g(p, "review", vid2, review_doc(d2, [NA_OK]))
    change_rule(p, R1, "Changed after open.\n")
    _, o2, _, _ = g(p, "conclude", vid2)
    return [
        ("06j changed target → not Pass, listed", o1["data"]["verdict"] == "cannot_confirm_pass"
         and any(r["code"] == "TARGET_CHANGED" and r["subject"] == "src/login.py" for r in o1["data"]["reasons"])),
        ("06j changed Policy → not Pass, listed", o2["data"]["verdict"] == "cannot_confirm_pass"
         and any(r["code"] == "POLICY_CHANGED" and r["subject"] == R1 for r in o2["data"]["reasons"])),
    ]


def tc_risk_acceptance():
    p = new_project()
    scope = save_scope(p)
    vid, _, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    before = (p / REPORTS / f"{vid}.json").read_bytes()
    base = ["guard", "accept-risk", "--project", str(p), "--run", vid, "--finding", "F1", "--reason"]
    c_agent, o_agent, _, _ = sc(*base, "agent decided", "--json")
    c_bad, t_bad = sc_pty([(b"to confirm:", "F2")], *base, "typo")
    unchanged = (p / REPORTS / f"{vid}.json").read_bytes() == before
    c_ok, t_ok = sc_pty([(b"to confirm:", "F1")], *base, "accepted until Q3 rewrite")
    res = result(p, vid)
    other, _, _ = run(p, scope, FAIL_RECORD, [confirm(), NA_OK])
    _, auth, _, _ = sc("auth", "status", "--json")
    return [
        ("07d agent (no terminal) refused even with Maintainer authorization", c_agent == 1
         and code_of(o_agent) == "INTERACTIVE_REQUIRED" and auth["data"].get("role") == "maintainer"),
        ("07d mismatched typed id refused", c_bad == 1 and "CONFIRMATION_MISMATCH" in t_bad),
        ("07d nothing recorded by refusals", unchanged),
        ("07a acceptance recorded separately with role, time, reason", c_ok == 0
         and res["risk_acceptances"][0]["role"] == "user" and res["risk_acceptances"][0]["recorded_at"]
         and res["risk_acceptances"][0]["reason"] == "accepted until Q3 rewrite"),
        ("07a finding, severity, verdict unchanged in result and report", res["verdict"] == "fail"
         and res["findings"][0]["final_severity"] == "high" and "**Verdict: Fail**" in md(p, vid)
         and "accepted until Q3 rewrite" in md(p, vid)),
        ("07b not applied to another verification", result(p, other)["risk_acceptances"] == []),
    ]


def tc_lock():
    import fcntl

    p = new_project()
    scope = save_scope(p)
    vid, _ = opened(p, scope)
    fd = os.open(p / GLOCK, os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        code, out, _, err = g(p, "conclude", vid)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return [("NFR-3 concurrent command → LOCKED envelope", code == 1 and code_of(out) == "LOCKED"
             and out["next_steps"] and "Traceback" not in err)]


def tc_skill_package():
    text = " ".join((GUARD_SKILL / "SKILL.md").read_text(encoding="utf-8").lower().split())
    ref = (GUARD_SKILL / "references" / "guard-records.md").read_text(encoding="utf-8")
    examples = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", ref, re.S)]
    return [
        ("02g ask only for unclear project/baseline/targets; no re-confirm; whole project explicit",
         "ask the user only when the project, baseline or targets are unclear" in text
         and "do not ask again to confirm an explicit scope" in text
         and "whole project only on an explicit user choice" in text),
        ("05h one independent read-only Reviewer per batch, bounded context, reviewed digests",
         "one independent read-only reviewer per batch" in text
         and "only the relevant summaries and evidence locations" in text
         and "with the reviewed target digests" in text),
        ("07c no acceptance on user's behalf; Maintainer authorization is not consent",
         "never record a risk acceptance on the user's behalf" in text and "maintainer authorization is not consent" in text),
        ("08b never edit, no remediation/re-scan loops, fixes to executor",
         "guard and its reviewer never edit business artifacts" in text
         and "never start remediation or automatic re-scan loops" in text
         and "fixes belong to the current task executor" in text),
        ("reference examples cover all four request schemas",
         {"ai-secure-code-toolkit/guard-open/v1", "ai-secure-code-toolkit/guard-plan/v1",
          "ai-secure-code-toolkit/guard-record/v1", "ai-secure-code-toolkit/reviewer-record/v1"}
         <= {e.get("schema") for e in examples}),
    ]


# ---------------------------------------------------------------- host case (never-authorized User)
def tc_host_user():
    p = new_project(rules=())
    _, auth, _, _ = sc("auth", "status", "--json")
    c1, o1, _, _ = g(p, "open", doc=open_doc(""))
    c2, o2, _, _ = g(p, "open", doc=open_doc("sha256:" + "0" * 64))
    c3, o3, _, _ = sc("guard", "accept-risk", "--project", str(p), "--run", "gv-20261019T000000Z-00000000",
                      "--finding", "F1", "--reason", "r", "--json")
    return [
        ("host User role", auth["data"].get("role") == "user"),
        ("03a no scope → MAINTENANCE_NEEDED", c1 == 1 and code_of(o1) == "MAINTENANCE_NEEDED"),
        ("unknown scope → SCOPE_NOT_FOUND", c2 == 1 and code_of(o2) == "SCOPE_NOT_FOUND"),
        ("07d non-interactive accept-risk refused", c3 == 1 and code_of(o3) == "INTERACTIVE_REQUIRED"),
        ("nothing written", not (p / GUARD).exists() or not any((p / GUARD).iterdir())),
    ]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        assert sc_pty([(b"passphrase", PASS), (b"passphrase", PASS)], "auth", "init")[0] == 0
        case("TC-A-01", ["AC-002A-01a", "AC-002A-01b", "AC-002A-01c", "AC-002A-02a", "AC-002A-03c", "AC-002A-04c",
                         "AC-002A-05c", "AC-002A-06a", "AC-002A-06g", "AC-002A-08a"], tc_fail_report)
        case("TC-A-02", ["AC-002A-01c", "AC-002A-01d"], tc_masking)
        case("TC-A-03", ["AC-002A-01e", "AC-002A-01f", "AC-002A-01g"], tc_retention)
        case("TC-A-04", ["AC-002A-01h"], tc_two_versions)
        case("TC-A-05", ["AC-002A-02b"], tc_copilot_context)
        case("TC-A-06", ["AC-002A-02c"], tc_artifact_scope)
        case("TC-A-07", ["AC-002A-02d"], tc_roles)
        case("TC-A-08", ["AC-002A-02e"], tc_change_meaning)
        case("TC-A-09", ["AC-002A-02f"], tc_invalid_targets)
        case("TC-A-10", ["AC-002A-03a"], tc_maintenance)
        case("TC-A-11", ["AC-002A-03b"], tc_partial)
        case("TC-A-12", ["AC-002A-03d", "AC-002A-04a", "AC-002A-04b"], tc_plan_rules)
        case("TC-A-13", ["AC-002A-04d", "AC-002A-04e", "AC-002A-04g", "AC-002A-04j", "AC-002A-06d"], tc_ledger_rules)
        case("TC-A-14", ["AC-002A-04f", "AC-002A-06i"], tc_exclusion)
        case("TC-A-15", ["AC-002A-04h"], tc_na_review)
        case("TC-A-16", ["AC-002A-04i"], tc_kinds)
        case("TC-A-17", ["AC-002A-05a"], tc_merge)
        case("TC-A-18", ["AC-002A-05b", "AC-002A-05d"], tc_review_states)
        case("TC-A-19", ["AC-002A-05e", "AC-002A-05f", "AC-002A-05g"], tc_review_validity)
        case("TC-A-20", ["AC-002A-06b", "AC-002A-06c", "AC-002A-06e", "AC-002A-06f", "AC-002A-06g", "AC-002A-06k"],
             tc_verdicts)
        case("TC-A-21", ["AC-002A-06h", "NFR-002A-3"], tc_determinism)
        case("TC-A-22", ["AC-002A-06j"], tc_changes)
        case("TC-A-23", ["AC-002A-07a", "AC-002A-07b", "AC-002A-07d"], tc_risk_acceptance)
        case("TC-A-24", ["NFR-002A-3"], tc_lock)
        case("TC-A-25", ["AC-002A-02g", "AC-002A-05h", "AC-002A-07c", "AC-002A-08b"], tc_skill_package)
        case("TC-A-27", ["AC-002A-02b"], tc_unlisted_toolkit_data)
    else:
        case("TC-A-26", ["AC-002A-03a", "AC-002A-07d"], tc_host_user)
        case("TC-A-25", ["AC-002A-02g", "AC-002A-05h", "AC-002A-07c", "AC-002A-08b"], tc_skill_package)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
