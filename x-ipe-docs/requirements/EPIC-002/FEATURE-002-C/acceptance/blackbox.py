"""Black-box acceptance scenarios for FEATURE-002-C Verification Budget, Cancel & Data-Egress Control (TASK-038).

Calls the real CLI (`uvx --from <framework>/scripts secure-code ...`) and the real Opengrep v1.31.0
binary. Never imports toolkit code. Helpers are copied from the FEATURE-002-B runner.
Fixture notes: TC-C-07 writes a stale `tool-active.json` (dead pid) to simulate a crashed tool owner;
TC-C-10 removes the budget keys from a run state to simulate a verification opened before 002-C.

  python3 blackbox.py host                         # never-authorized User path (no trust writes)
  FAT_ISOLATED=1 OPENGREP=/og/opengrep python3 blackbox.py container
      # disposable HOME only; offline container with git; real binary mounted read-only
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
import threading
import time
from pathlib import Path

TOOLKIT = (Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ
           else Path(__file__).resolve().parents[5] / "ai-secure-code-toolkit")
SCRIPTS = TOOLKIT / "x-ipe-secure-code-toolkit-framework" / "scripts"
GUARD_SKILL = TOOLKIT / "x-ipe-secure-code-toolkit-guard"
SAMPLES = Path(os.environ.get("SAMPLES", "/samples"))
GUARD = ".x-ipe/private/secure-code/guard"
REPORTS = "x-ipe-docs/secure-code/reports/guard"
PASS = "acceptance passphrase 42"
R1, R2 = "CWE/4.14/CWE-89", "CWE/4.14/CWE-79"
TOKEN = "ghp_" + "Q" * 36
OFFICIAL = "sha256:2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d"
RESULTS: list[dict] = []


# ---------------------------------------------------------------- helpers
def sc(*args: str):
    proc = subprocess.run(["uvx", "--from", str(SCRIPTS), "secure-code", *args], capture_output=True, text=True,
                          env=dict(os.environ), stdin=subprocess.DEVNULL, timeout=900)
    try:
        data = json.loads(proc.stdout) if "--json" in args else None
    except json.JSONDecodeError:
        data = None
    return proc.returncode, data, proc.stdout, proc.stderr


def sc_pty(answers: list[str], *args: str, marker: bytes = b"passphrase") -> int:
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
        if sent < len(answers) and out.lower().count(marker) > sent:
            os.write(fd, answers[sent].encode() + b"\n")
            sent += 1
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status)


def code_of(out):
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


def item(rule: str) -> dict:
    ns, ver, rid = rule.split("/")
    return {"namespace": ns, "version": ver, "rule_id": rid, "content": "Rule body.\n",
            "source_location": f"https://example.org/{rid}"}


PY_RULE = {"id": "py-sql-fstring", "languages": ["python"], "severity": "ERROR",
           "message": "SQL text built with an f-string is executed (CWE-89)", "metadata": {"cwe": "CWE-89"},
           "pattern": '$C.execute(f"...", ...)'}
JAVA_RULE = {"id": "java-sql-concat", "languages": ["java"], "severity": "ERROR",
             "message": "SQL text concatenated with variables is executed (CWE-89)", "metadata": {"cwe": "CWE-89"},
             "pattern-either": [{"pattern": '$S.executeQuery("..." + $X + ...)'},
                                {"pattern": '(java.sql.Statement $S).executeQuery("..." + $X)'}]}


def new_project(git: bool = False) -> Path:
    root = Path(tempfile.mkdtemp(prefix="fat-gc-")) / "proj ü"
    root.mkdir()
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    batch = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": [item(R1), item(R2)]}
    code, out, _, _ = sc("knowledge", "import", "--project", str(root), "--batch", jfile(root, batch), "--json")
    assert code == 0, out
    shutil.copytree(SAMPLES / "m", root / "app", ignore=shutil.ignore_patterns("__pycache__", "data"))
    kid = SAMPLES / "w/src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java"
    (root / "java").mkdir()
    shutil.copy(kid, root / "java" / "JWTHeaderKIDEndpoint.java")
    (root / "py").mkdir()
    (root / "py" / "orders.py").write_text(
        f'def find(c, name):\n    return c.execute(f"SELECT * FROM o WHERE n = {{name}} -- {TOKEN}")\n')
    (root / "py" / "safe.py").write_text('def find(c, name):\n    return c.execute("SELECT 1 WHERE n = ?", (name,))\n')
    rules = root / "x-ipe-docs" / "tool-rules"
    rules.mkdir(parents=True)
    (rules / "py-sql.yaml").write_text(json.dumps({"rules": [PY_RULE]}))
    (rules / "py-sql-2.yaml").write_text(json.dumps({"rules": [{**PY_RULE, "id": "py-sql-two"}]}))
    (rules / "java-sql.yaml").write_text(json.dumps({"rules": [JAVA_RULE]}))
    (rules / "taint.yaml").write_text("rules:\n  - id: t\n    languages: [python]\n    mode: taint\n    message: m\n")
    if git:
        (root / ".gitignore").write_text(".x-ipe/private/\n")
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "x"]):
            subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    return root


def save_scope(p: Path) -> str:
    code, prop, _, _ = sc("policy", "resolve", "--project", str(p), "--rule", R1, "--rule", R2, "--json")
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": "clues", "considered": [R1, R2],
           "proposal_digest": prop["data"]["proposal_digest"], "clues": "sql", "language_context": ["python"],
           "confirmation_note": "user confirmed",
           "decisions": [{"ref": e["requested"], "decision": "adopted",
                          "state_digest": e["source_evidence"]["state_digest"]} for e in prop["data"]["entries"]]}
    code, out, _, _ = sc("scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed", "--json")
    assert code == 0, out
    return out["data"]["scope_id"]


def _g(p: Path, cmd: str, vid: str | None = None, doc: dict | None = None, *extra: str):
    args = ["guard", cmd, "--project", str(p)]
    if vid:
        args += ["--run", vid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    return sc(*args, *extra, "--json")

def _extend(p: Path, vid: str) -> None:
    """The user extends the budget at a (pseudo) terminal when a scenario retries more than the default."""
    sc_pty([vid], "guard", "extend", "--project", str(p), "--run", vid, "--attempts", "10",
           "--reason", "acceptance scenario retries", marker=b"verification id")


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



def register(p: Path, path: str):
    return sc("tools", "register", "--project", str(p), "--tool", "opengrep", "--path", path, "--json")


TOOL = {"name": "opengrep", "kind": "runtime", "required": True}
READ = {"name": "semantic-review", "kind": "reading", "required": True}


def chk(cid, obj, methods=(TOOL,), selected=("opengrep",), minimum=("runtime",), rule=R1):
    c = {"id": cid, "rule": rule, "object": list(obj), "methods": list(methods), "minimum_evidence": list(minimum)}
    if selected is not None:
        c["method_choice"] = {"considered": ["semantic-review", "opengrep"], "cost": "opengrep ~1 s per rule",
                              "selected": list(selected), "reason": "pattern rule exists for this sink"}
    return c


def setup(p: Path, scope: str, targets: list[str], checks: list[dict]):
    code, out, _, err = g(p, "open", doc={"schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope,
                                          "targets": [{"path": t} for t in targets]})
    assert code == 0, (out, err)
    vid = out["data"]["verification_id"]
    digests = {t["path"]: t["digest"] for t in out["data"]["targets"]}
    covered = {c["rule"] for c in checks}
    plan = {"schema": "ai-secure-code-toolkit/guard-plan/v1", "checks": checks,
            "not_applicable": [{"rule": r, "reason": "not in this change"} for r in (R1, R2) if r not in covered]}
    code, out, _, _ = g(p, "plan", vid, plan)
    assert code == 0, out
    return vid, digests


def tool(p: Path, vid: str, checks: list[dict], **over):
    doc = {"schema": "ai-secure-code-toolkit/guard-tool/v1", "adapter": "opengrep", "include_ignored": False,
           "time_limit_seconds": 300, "checks": checks}
    doc.update(over)
    return g(p, "tool", vid, doc)


def tc_(cid, rules, targets):
    return {"check": cid, "rules": list(rules), "targets": list(targets)}


def state(p: Path, vid: str) -> dict:
    return json.loads((p / GUARD / vid / "state.json").read_text())


def ev_of(p: Path, vid: str, cid: str) -> dict:
    return [e for e in state(p, vid)["evidence"] if cid in e["checks"] and e["method"] == "opengrep"][-1]


def stored(p: Path, vid: str, run: dict) -> tuple[dict, dict]:
    """The retained manifest and sanitized output of a run, read independently of the product's status."""
    base = p / GUARD / vid
    raw = (base / run["manifest"]["path"]).read_bytes()
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == run["manifest"]["digest"], "manifest digest"
    n = run["n"]
    return json.loads(raw), json.loads((base / f"evidence/opengrep-{n}-output.json").read_text())


def complete_clean(p: Path, vid: str, cid: str, expected: list[str]) -> bool:
    """Independent clean-scan proof from the retained tool output and manifest (not the product's `ok`)."""
    run = [r for r in state(p, vid)["adapter_runs"] if cid in (r.get("checks") or {})][-1]
    manifest, output = stored(p, vid, run)
    docs = output[cid]
    acc = manifest["checks"][cid]["accounting"]
    return (
        bool(docs)
        and all(isinstance(d, dict) and "results" in d and not d.get("incomplete") for d in docs.values())
        and all(d.get("errors") == [] and not d.get("skipped_rules") for d in docs.values())
        and all(d["results"] == [] for d in docs.values())
        and all(sorted(d["paths"]["scanned"]) == sorted(expected) for d in docs.values())
        and all(not d["paths"].get("skipped") for d in docs.values())
        and sorted(acc["scanned"]) == sorted(expected)
        and acc["skipped"] == [] and acc["unaccounted"] == [] and acc["syntax_errors"] == []
        and all(r["status"] == "completed" and r["exit"] == 0 for r in manifest["checks"][cid]["rules"])
    )


class HomeWatch:
    """Observe the tool's disposable home in a dedicated, ASCII-only system temporary folder."""

    def __init__(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="fat-systmp-"))
        self.seen: set[str] = set()
        self.with_cache: set[str] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            for h in self.tmp.glob("secure-code-tool-home-*"):
                self.seen.add(h.name)
                if (h / ".cache" / "opengrep").exists():
                    self.with_cache.add(h.name)
            time.sleep(0.005)

    def __enter__(self) -> "HomeWatch":
        self._old = os.environ.get("TMPDIR")
        os.environ["TMPDIR"] = str(self.tmp)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join()
        if self._old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = self._old

    def left(self) -> list[str]:
        return sorted(h.name for h in self.tmp.glob("secure-code-tool-home-*"))


def _registered(git=False):
    p = new_project(git=git)
    code, out, _, _ = register(p, os.environ["OPENGREP"])
    assert code == 0, out
    return p, save_scope(p)


# ---------------------------------------------------------------- FEATURE-002-C helpers
RECORD = "ai-secure-code-toolkit/guard-record/v1"
REVIEW = "ai-secure-code-toolkit/reviewer-record/v1"
EGRESS = "ai-secure-code-toolkit/guard-egress/v1"
API = "https://api.example.com"


def sem(cid, obj, rule):
    return {"id": cid, "rule": rule, "object": list(obj), "methods": [READ], "minimum_evidence": ["reading"]}


def ev(eid, cid, path, method="semantic-review", **over):
    e = {"id": eid, "kind": "reading", "method": method, "method_status": "ok", "checks": [cid], "paths": [path],
         "summary": "read the query construction"}
    e.update(over)
    return e


def attempt(p: Path, vid: str, kind="semantic_review", pairs=(), findings=(), na=()):
    covers = ({"findings": list(findings), "na": list(na)} if kind == "reviewer"
              else {"pairs": [{"check": c, "method": m} for c, m in pairs]})
    return _g(p, "attempt", vid, {"schema": ATTEMPT, "kind": kind, "covers": covers})


def rec(p: Path, vid: str, **parts):
    return _g(p, "record", vid, {"schema": RECORD, **parts})


def result_of(p: Path, vid: str) -> dict:
    return json.loads((p / REPORTS / f"{vid}.json").read_text())


def report_of(p: Path, vid: str) -> str:
    return (p / REPORTS / f"{vid}.md").read_text()


def open_run(p: Path, scope: str, targets, budget=None):
    doc = {"schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope, "targets": [{"path": t} for t in targets]}
    if budget is not None:
        doc["budget"] = budget
    return _g(p, "open", doc=doc)


def plan(p: Path, vid: str, checks, na=()):
    return _g(p, "plan", vid, {"schema": "ai-secure-code-toolkit/guard-plan/v1", "checks": checks,
                               "not_applicable": [{"rule": r, "reason": "not in this change"} for r in na]})


def semantic_run(p: Path, scope: str, budget=None):
    code, out, _, err = open_run(p, scope, ["py/orders.py", "py/safe.py"], budget)
    assert code == 0, (out, err)
    vid = out["data"]["verification_id"]
    code, out, _, _ = plan(p, vid, [sem("C1", ["py/orders.py"], R1), sem("C2", ["py/safe.py"], R2)])
    assert code == 0, out
    return vid


def pty_confirm(answer: str, *args: str) -> int:
    return sc_pty([answer], *args, marker=b"verification id")


def show(p: Path, vid: str):
    return _g(p, "show", vid)


def consumed(out) -> float:
    return out["data"]["budget"]["consumed_seconds"]


# ---------------------------------------------------------------- container cases
def tc_open_budget():
    p, scope = _registered()
    c1, o1, _, _ = open_run(p, scope, ["py/orders.py"])
    c2, o2, _, _ = open_run(p, scope, ["py/orders.py"], {"minutes": 20, "extra_attempts": 1})
    runs_before = sorted(x.name for x in (p / GUARD).iterdir())
    c3, o3, _, _ = open_run(p, scope, ["py/orders.py"], {"minutes": 61})
    c4, o4, _, _ = open_run(p, scope, ["py/orders.py"], {"extra_attempts": 4})
    vid = o1["data"]["verification_id"]
    s1 = show(p, vid)
    time.sleep(1.5)
    s2 = show(p, vid)
    b1 = o1["data"]["budget"]
    return [
        ("01a defaults recorded and marked", c1 == 0 and b1["total_seconds"] == 3600 and b1["extra_attempts"] == 3
         and b1["defaulted"] is True),
        ("01a lower budget recorded", c2 == 0 and o2["data"]["budget"]["total_seconds"] == 1200
         and o2["data"]["budget"]["extra_attempts"] == 1 and o2["data"]["budget"]["defaulted"] is False),
        ("01a above defaults refused, nothing created, next step names extension", c3 == 1 and c4 == 1
         and code_of(o3) == code_of(o4) == "BUDGET_INVALID" and "extend" in o3["next_steps"][0]
         and sorted(x.name for x in (p / GUARD).iterdir()) == runs_before),
        ("01b show on an open run: NOT_CONCLUDED with budget, consumed and remaining", s1[0] == 1
         and code_of(s1[1]) == "NOT_CONCLUDED" and s1[1]["data"]["budget"]["remaining_seconds"]
         == 3600 - consumed(s1[1])),
        ("01b consumed time never decreases between commands", consumed(s2[1]) >= consumed(s1[1])),
    ]


def tc_attempts():
    p, scope = _registered()
    vid = semantic_run(p, scope)
    no_attempt = rec(p, vid, evidence=[ev("E1", "C1", "py/orders.py")])
    a1 = attempt(p, vid, pairs=[("C1", "semantic-review"), ("C2", "semantic-review")])
    a1_id = a1[1]["data"]["attempt"]
    other_vid = semantic_run(p, scope)
    foreign = attempt(p, other_vid, pairs=[("C1", "semantic-review")])[1]["data"]["attempt"]
    from_other = rec(p, vid, attempt=foreign, evidence=[ev("E1", "C1", "py/orders.py")])
    outside = rec(p, vid, attempt=a1_id, evidence=[ev("E1", "C1", "py/orders.py", method="other")])
    unknown = rec(p, vid, attempt="a-9", evidence=[ev("E1", "C1", "py/orders.py")])
    ok = rec(p, vid, attempt=a1_id, evidence=[ev("E1", "C1", "py/orders.py"), ev("E2", "C2", "py/safe.py")],
             usage={"requests": 2, "input_tokens": 1500, "output_tokens": 120})
    reused = rec(p, vid, attempt=a1_id, evidence=[ev("E3", "C1", "py/orders.py")])
    retry = attempt(p, vid, pairs=[("C1", "semantic-review"), ("C2", "semantic-review")])
    change = rec(p, vid, method_changes=[{"check": "C1", "change": "supplement", "reason": "second view",
                                          "method": {"name": "manual-trace", "kind": "reading"}}])
    added = attempt(p, vid, kind="helper", pairs=[("C1", "manual-trace")])
    cited_change = rec(p, vid, attempt=added[1]["data"]["attempt"], evidence=[ev("E4", "C1", "py/orders.py",
                       method="manual-trace")], conflicts=[{"id": "K1", "kind": "evidence", "description": "x",
                                                            "verdict_affecting": False, "resolved": False}])
    rv = attempt(p, vid, kind="reviewer", na=["C2"])
    review_no_attempt = _g(p, "review", vid, {"schema": REVIEW, "requirement": "x", "subjects": []})
    _g(p, "conclude", vid)
    res = result_of(p, vid)
    usage = res["budget"]["model_usage"]
    return [
        ("01c evidence without a registered attempt refused", code_of(no_attempt[1]) == "ATTEMPT_REQUIRED"),
        ("01c attempt registered: run-bound id, deadline, planned pairs free", a1[0] == 0
         and a1_id == f"a-1-{vid[-8:]}"
         and a1[1]["data"]["extra"] == 0 and a1[1]["data"]["deadline_consumed"] == 3600),
        ("01c records outside coverage or citing unknown attempts refused, nothing stored",
         outside[0] == 1 and unknown[0] == 1 and code_of(unknown[1]) == "ATTEMPT_INVALID"),
        ("01c an attempt of another verification is refused", code_of(from_other[1]) == "ATTEMPT_INVALID"
         and "another verification" in from_other[1]["problems"][0]["message"]),
        ("01b refusals of a run carry its budget status", "budget" in unknown[1]["data"]
         and "budget" in reused[1]["data"]),
        ("01e first citing record finishes the attempt; second citation refused", ok[0] == 0 and reused[0] == 1
         and code_of(reused[1]) == "ATTEMPT_INVALID"),
        ("01d re-covering two pairs costs two extra attempts", retry[1]["data"]["extra"] == 2
         and retry[1]["data"]["budget"]["extra_used"] == 2),
        ("01d method added later costs one extra attempt", change[0] == 0 and added[1]["data"]["extra"] == 1),
        ("01e cited record cannot carry conflicts", code_of(cited_change[1]) == "ATTEMPT_INVALID"),
        ("01c Reviewer record without attempt refused", rv[0] == 0 and code_of(review_no_attempt[1]) in
         ("ATTEMPT_REQUIRED", "REVIEW_INVALID")),
        ("01f usage summed; model attempts without usage unknown; no price", usage["requests"] == 2
         and usage["input_tokens"] == 1500 and usage["unknown_attempts"] >= 2
         and "price" not in json.dumps(res["budget"]).lower()),
    ]


def tc_exhaustion():
    p, scope = _registered()
    code, out, _, _ = open_run(p, scope, ["py/orders.py", "py/safe.py"], {"minutes": 1, "extra_attempts": 0})
    vid = out["data"]["verification_id"]
    plan(p, vid, [chk("C1", ["py/orders.py"]), sem("C2", ["py/safe.py"], R2)])
    a = attempt(p, vid, pairs=[("C2", "semantic-review")])
    retry = attempt(p, vid, pairs=[("C2", "semantic-review")])
    c_run, run, _, _ = tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    entry = state(p, vid)["adapter_runs"][0]
    while consumed(show(p, vid)[1]) < 62:
        time.sleep(2)
    late_attempt = attempt(p, vid, pairs=[("C1", "opengrep")])
    late_tool = tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    late_record = rec(p, vid, attempt=a[1]["data"]["attempt"], evidence=[ev("E1", "C2", "py/safe.py")])
    ledger = rec(p, vid, ledger=[{"check": "C2", "state": "met", "evidence": ["E1"]}])
    conflict = rec(p, vid, conflicts=[{"id": "K1", "kind": "evidence", "description": "x",
                                       "verdict_affecting": False, "resolved": False}])
    c_con, con, _, _ = _g(p, "conclude", vid)
    res, md = result_of(p, vid), report_of(p, vid)
    line = next((x for x in md.splitlines() if x.startswith("**Budget exhausted")), "")
    late = next(x for x in res["attempts"] if x["id"] == a[1]["data"]["attempt"])
    return [
        ("03b extra attempts used up: retry refused naming the limit", code_of(retry[1]) == "ATTEMPTS_EXHAUSTED"),
        ("01g tool limit capped at the remaining time and recorded", c_run == 0 and entry["time_limit"] <= 60
         and entry["time_limit_capped"] is True and entry["requested_time_limit"] == 300),
        ("03a time exhausted: new attempt and tool run refused", code_of(late_attempt[1]) == "BUDGET_TIME_EXHAUSTED"
         and code_of(late_tool[1]) == "BUDGET_TIME_EXHAUSTED"),
        ("03a started attempt still records (overrun shown); ledger-only accepted; other changes refused",
         late_record[0] == 0 and late["overrun_seconds"] > 0 and ledger[0] == 0
         and code_of(conflict[1]) == "BUDGET_TIME_EXHAUSTED"),
        ("03c conclusion: never Pass; exhaustion stated; only unconfirmed checks listed",
         c_con == 0 and con["data"]["verdict"] != "pass" and res["budget"]["exhausted"] == "time"
         and "(time)" in line and "C1" in line and "C2" not in line),
    ]


def tc_pause():
    p, scope = _registered()
    vid = semantic_run(p, scope)
    c_p, paused, _, _ = _g(p, "pause", vid, None, "--reason", "asking the user which config is deployed")
    blocked = [attempt(p, vid, pairs=[("C1", "semantic-review")]),
               rec(p, vid, ledger=[{"check": "C1", "state": "unconfirmed", "reason": "x"}]),
               _g(p, "egress", vid, {"schema": EGRESS, "purpose": "submission", "recipient": API,
                                     "data": ["findings"], "scope": ["py/orders.py"]})]
    again = _g(p, "pause", vid, None, "--reason", "again")
    plan_paused = plan(p, vid, [sem("C1", ["py/orders.py"], R1)])
    review_paused = _g(p, "review", vid, {"schema": REVIEW, "attempt": "a-1", "requirement": "x", "subjects": []})
    code, out, _, _ = open_run(p, scope, ["py/orders.py"])
    tvid = out["data"]["verification_id"]
    plan(p, tvid, [chk("C1", ["py/orders.py"])], na=[R2])
    _g(p, "pause", tvid, None, "--reason", "waiting")
    tool_paused = tool(p, tvid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    c_conc, conc, _, _ = _g(p, "conclude", tvid)
    t_pauses = result_of(p, tvid)["budget"]["pauses"]
    cvid = semantic_run(p, scope)
    _g(p, "pause", cvid, None, "--reason", "waiting")
    c_can, can, _, _ = _g(p, "cancel", cvid)
    before = consumed(show(p, vid)[1])
    time.sleep(4)
    during = consumed(show(p, vid)[1])
    c_r, resumed, _, _ = _g(p, "resume", vid)
    _g(p, "conclude", vid)
    pauses = result_of(p, vid)["budget"]["pauses"]
    return [
        ("02a pause recorded with reason", c_p == 0 and paused["data"]["budget"]["paused"] is True),
        ("02a attempt, record and egress declaration refused while paused",
         all(code_of(b[1]) == "RUN_PAUSED" for b in blocked)),
        ("02a show works; second pause refused", code_of(again[1]) == "ALREADY_PAUSED"),
        ("02a plan, Reviewer record and tool run refused while paused", code_of(plan_paused[1]) == "RUN_PAUSED"
         and code_of(review_paused[1]) == "RUN_PAUSED" and code_of(tool_paused[1]) == "RUN_PAUSED"
         and "budget" in tool_paused[1]["data"]),
        ("02a/02b conclude and cancel still work while paused; the pause is closed", c_conc == 0
         and t_pauses[0]["end"] == conc["data"]["ended_at"] and c_can == 0 and can["data"]["cancellation"]),
        ("02b clock frozen while paused; resumed without the pause time", during - before < 1
         and c_r == 0 and consumed(resumed) - before < 2),
        ("02b pause listed with start, end and reason", len(pauses) == 1 and pauses[0]["end"]
         and pauses[0]["reason"].startswith("asking")
         and "asking the user which config is deployed" in report_of(p, vid)),
    ]


def tc_extend():
    p, scope = _registered()
    vid = semantic_run(p, scope)
    before = consumed(show(p, vid)[1])
    t0 = time.monotonic()
    c_ok = pty_confirm(vid, "guard", "extend", "--project", str(p), "--run", vid, "--minutes", "30", "--attempts",
                       "2", "--reason", "WebGoat needs a second pass")
    b = state(p, vid)["budget"]
    after_consumed = consumed(show(p, vid)[1])
    elapsed = time.monotonic() - t0
    c_agent, agent, _, _ = sc("guard", "extend", "--project", str(p), "--run", vid, "--minutes", "30",
                              "--reason", "agent tries", "--json")
    c_bad = pty_confirm("wrong-id", "guard", "extend", "--project", str(p), "--run", vid, "--minutes", "30",
                        "--reason", "typo")
    c_file, by_file, _, _ = rec(p, vid, budget={"minutes": 999})
    after = state(p, vid)["budget"]
    _g(p, "conclude", vid)
    section = report_of(p, vid).split("## Budget", 1)[1].split("\n## ", 1)[0]
    return [
        ("03d user at a terminal extends; consumption unchanged; extension recorded", c_ok == 0
         and before <= after_consumed <= before + elapsed + 1
         and (b["total_seconds"], b["extra_attempts"]) == (5400, 5) and b["extensions"][0]["role"] == "user"
         and b["extensions"][0]["reason"] == "WebGoat needs a second pass"),
        ("03e agent (no terminal), mismatching id and request files cannot change the budget",
         c_agent == 1 and code_of(agent) == "INTERACTIVE_REQUIRED" and c_bad == 1 and c_file == 1
         and (after["total_seconds"], after["extra_attempts"]) == (5400, 5)),
        ("06b Budget section: limits, extension with reason", "90.0 min" in section
         and "WebGoat needs a second pass" in section),
    ]


def _big_project():
    p, scope = _registered()
    shutil.copytree(SAMPLES / "w" / "src", p / "webgoat")
    rules = [{**JAVA_RULE, "id": f"java-sql-{i}"} for i in range(12)]
    (p / "x-ipe-docs" / "tool-rules" / "java-many.yaml").write_text(json.dumps({"rules": rules}))
    return p, scope


def _long_tool_run(p, scope):
    code, out, _, _ = open_run(p, scope, ["webgoat"])
    vid = out["data"]["verification_id"]
    plan(p, vid, [chk("C1", ["webgoat"])], na=[R2])
    holder = {}
    runner = threading.Thread(target=lambda: holder.setdefault(
        "r", tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/java-many.yaml"], ["webgoat"])])))
    runner.start()
    active = p / GUARD / vid / "tool-active.json"
    end = time.monotonic() + 120
    while not active.exists() and time.monotonic() < end:
        time.sleep(0.1)
    return vid, runner, holder


def _opengrep_processes() -> int:
    n = 0
    for d in Path("/proc").iterdir():
        if d.name.isdigit():
            try:
                cmd = (d / "cmdline").read_bytes()
            except OSError:
                continue
            if b"opengrep" in cmd and b"scan" in cmd:
                n += 1
    return n


def tc_cancel_running_tool():
    p, scope = _big_project()
    code, out, _, _ = open_run(p, scope, ["py/orders.py"])  # opened first: a running tool holds the Guard lock
    idle = out["data"]["verification_id"]
    plan(p, idle, [sem("C1", ["py/orders.py"], R1)], na=[R2])
    busy, runner, holder = _long_tool_run(p, scope)
    t0 = time.monotonic()
    c_idle, o_idle, _, _ = _g(p, "cancel", idle, None, "--reason", "user stopped the other one")
    idle_seconds = time.monotonic() - t0
    still_running = runner.is_alive()
    runner.join(600)
    other_ok = holder["r"][0] == 0 and holder["r"][1]["data"]["status"] == "completed"
    victim, runner2, holder2 = _long_tool_run(p, scope)
    time.sleep(2)
    c_cancel, cancelled, _, _ = _g(p, "cancel", victim, None, "--reason", "user stopped")
    runner2.join(120)
    res = result_of(p, victim)
    term = cancelled["data"]["cancellation"]["tool_termination"]
    later = rec(p, victim, ledger=[{"check": "C1", "state": "unconfirmed", "reason": "x"}])
    return [
        ("04a cancel of an idle verification is not blocked by another verification's running tool",
         c_idle == 0 and still_running and idle_seconds < 10 and o_idle["data"]["cancellation"]),
        ("04a the other verification's tool run completes and is recorded", other_ok
         and runs_of(p, busy) == 1),
        ("04b running Opengrep stopped by its owner; termination confirmed", c_cancel == 0
         and term["tool"] == "confirmed" and code_of(holder2["r"][1]) == "RUN_CANCELLED"
         and _opengrep_processes() == 0),
        ("04b tool attempt listed cancelled without new evidence; staging removed", res["adapter_runs"] == []
         and [a["status"] for a in res["attempts"]] == ["cancelled"]
         and not list((p / GUARD / victim / "adapter").glob("stage-*"))),
        ("04a later changes refused; verdict never pass", code_of(later[1]) == "RUN_CANCELLED"
         and res["verdict"] != "pass" and state(p, victim)["status"] == "cancelled"),
    ]


def runs_of(p: Path, vid: str) -> int:
    return len(state(p, vid).get("adapter_runs", []))


def tc_cancel_results():
    p, scope = _registered()
    code, out, _, _ = open_run(p, scope, ["py/orders.py"])
    vid, digests = out["data"]["verification_id"], {t["path"]: t["digest"] for t in out["data"]["targets"]}
    plan(p, vid, [sem("C1", ["py/orders.py"], R1)], na=[R2])
    first_id = attempt(p, vid, pairs=[("C1", "semantic-review")])[1]["data"]["attempt"]
    finding = {"id": "F1", "rule": R1, "check": "C1", "location": {"path": "py/orders.py", "line": 2},
               "cwe": "CWE-89", "title": "SQL built with an f-string", "source": "semantic", "severity": "high",
               "evidence": ["E1"]}
    rec(p, vid, attempt=first_id, evidence=[ev("E1", "C1", "py/orders.py")], findings=[finding],
        ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}])
    review_id = attempt(p, vid, kind="reviewer", findings=["F1"], na=[f"policy:{R2}"])[1]["data"]["attempt"]
    _g(p, "review", vid, {"schema": REVIEW, "attempt": review_id,
                          "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
                          "requirement": "re-check F1", "reviewed_targets": [{"path": "py/orders.py",
                                                                              "digest": digests["py/orders.py"]}],
                          "subjects": [{"type": "finding", "id": "F1", "result": "confirmed", "basis": "f-string"},
                                       {"type": "na_decision", "id": f"policy:{R2}", "result": "confirmed",
                                        "basis": "no HTML"}]})
    pending = attempt(p, vid, kind="helper", pairs=[("C1", "semantic-review")])
    c1, first, _, _ = _g(p, "cancel", vid, None, "--reason", "user stopped")
    c2, second, _, _ = _g(p, "cancel", vid, None, "--reason", "again")
    md_path = p / REPORTS / f"{vid}.md"
    before = result_of(p, vid)
    md_path.unlink()
    c3, _, _, _ = _g(p, "conclude", vid)
    accept = sc_pty(["F1"], "guard", "accept-risk", "--project", str(p), "--run", vid, "--finding", "F1",
                    "--reason", "x", marker=b"finding id")
    res, md = result_of(p, vid), report_of(p, vid)
    c = res["cancellation"]
    # crashed tool owner (fixture: stale tool-active.json with a dead pid)
    code, out, _, _ = open_run(p, scope, ["py/orders.py"])
    vid2 = out["data"]["verification_id"]
    plan(p, vid2, [sem("C1", ["py/orders.py"], R1)], na=[R2])
    dead = subprocess.Popen(["true"])
    dead.wait()
    (p / GUARD / vid2 / "tool-active.json").write_text(json.dumps({"pid": dead.pid, "attempt": "a-9", "at": "t"}))
    t0 = time.monotonic()
    c4, crashed, _, _ = _g(p, "cancel", vid2)
    took = time.monotonic() - t0
    done_vid = semantic_run(p, scope)
    _g(p, "conclude", done_vid)
    c5, finished, _, _ = _g(p, "cancel", done_vid)
    return [
        ("04e confirmed High kept: verdict Fail; results recorded before cancel kept", c1 == 0
         and first["data"]["verdict"] == "fail" and res["findings"][0]["id"] == "F1" and len(res["reviews"]) == 1),
        ("04e unfinished agent attempt listed: stop requested, not confirmed; remote billing stated",
         c["agent_attempts"] == [pending[1]["data"]["attempt"]] and "not confirmed" in c["agent_note"]
         and "billed" in c["remote_note"] and "## Cancellation" in md),
        ("04f cancel again returns the same result", c2 == 0 and second["data"]["cancellation"] == first["data"][
            "cancellation"]),
        ("04f report regenerated only from the stored result", c3 == 0 and md_path.exists()
         and result_of(p, vid) == before),
        ("04d cancelled result is final: risk acceptance refused", accept == 1 and result_of(p, vid) == before),
        ("04c crashed owner: cancelled at once, termination not confirmed (process named)", c4 == 0 and took < 20
         and crashed["data"]["cancellation"]["tool_termination"]["tool"] == "not_confirmed"
         and crashed["data"]["cancellation"]["tool_termination"]["pid"] == dead.pid),
        ("04f finished verification cannot be cancelled", c5 == 1 and code_of(finished) == "RUN_FINISHED"),
    ]


def tc_egress():
    p, scope = _registered()
    vid = semantic_run(p, scope)
    empty = state(p, vid)["egress"]
    nothing = _g(p, "egress", vid, {"schema": EGRESS, "purpose": "submission", "recipient": API,
                                    "data": ["findings"], "scope": ["py/orders.py"]})

    def allow(*extra, answer=None):
        args = ("guard", "allow-egress", "--project", str(p), "--run", vid, *extra)
        return pty_confirm(answer or vid, *args)

    c_ok = allow("--purpose", "submission", "--recipient", API, "--data", "findings", "--scope", "py/orders.py",
                 "--reason", f"second opinion {TOKEN}")
    c_agent, agent, _, _ = sc("guard", "allow-egress", "--project", str(p), "--run", vid, "--purpose", "submission",
                              "--recipient", API, "--data", "findings", "--scope", "py/orders.py", "--reason", "x",
                              "--json")
    refusals = [
        allow("--purpose", "submission", "--recipient", "https://api.example.com/?token=abc", "--data", "findings",
              "--scope", "py/orders.py", "--reason", "x"),
        allow("--purpose", "submission", "--recipient", API, "--data", "credentials", "--scope", "py/orders.py",
              "--reason", "x"),
        allow("--purpose", "target_requests", "--recipient", "http://localhost:8080", "--data", "findings",
              "--scope", "http://localhost:8080/app", "--reason", "x"),
    ]
    c_target = allow("--purpose", "target_requests", "--recipient", "http://localhost:8080", "--data",
                     "target_traffic", "--scope", "http://localhost:8080/app", "--reason", "probe the app")
    grants = state(p, vid)["egress"]["grants"]
    allowed = _g(p, "egress", vid, {"schema": EGRESS, "purpose": "submission", "recipient": API,
                                    "data": ["findings"], "items": [f"F1 summary {TOKEN}"], "scope": ["py/orders.py"]})
    second = _g(p, "egress", vid, {"schema": EGRESS, "purpose": "submission", "recipient": API,
                                   "data": ["findings"], "items": ["F2 summary"], "scope": ["py/orders.py"]})
    wrong_data = _g(p, "egress", vid, {"schema": EGRESS, "purpose": "submission", "recipient": API,
                                       "data": ["source_excerpts"], "scope": ["py/orders.py"]})
    via_target = _g(p, "egress", vid, {"schema": EGRESS, "purpose": "submission", "recipient": "http://localhost:8080",
                                       "data": ["findings"], "scope": ["py/orders.py"]})
    target_src = _g(p, "egress", vid, {"schema": EGRESS, "purpose": "target_requests",
                                       "recipient": "http://localhost:8080", "data": ["source_excerpts"],
                                       "scope": ["http://localhost:8080/app/login"]})
    raw_state = (p / GUARD / vid / "state.json").read_text()
    _g(p, "conclude", vid)
    md = report_of(p, vid)
    section = md.split("## Outbound Calls (Egress)", 1)[1].split("\n## ", 1)[0]
    return [
        ("05a nothing granted by default; undeclared purpose refused", empty == {"grants": [], "declarations": []}
         and code_of(nothing[1]) == "EGRESS_NOT_AUTHORIZED"),
        ("05b user grants at a terminal; agent (no terminal) refused", c_ok == 0 and c_agent == 1
         and code_of(agent) == "INTERACTIVE_REQUIRED" and grants[0]["purpose"] == "submission"
         and grants[0]["role"] == "user"),
        ("05b credential URL, prohibited data and findings for a non-submission purpose refused",
         all(r == 1 for r in refusals) and c_target == 0 and len(grants) == 2),
        ("05c covered declaration allowed; each call gets its own declaration id", allowed[0] == 0
         and allowed[1]["data"]["decision"] == "allowed" and allowed[1]["data"]["declaration"].startswith("eg-")
         and second[1]["data"]["declaration"] != allowed[1]["data"]["declaration"]
         and "budget" in allowed[1]["data"]),
        ("05c refusal names the missing element", wrong_data[0] == 1 and wrong_data[1]["data"]["missing"] == "data"),
        ("05d target or network grants never authorize sending findings or source",
         via_target[1]["data"]["missing"] in ("purpose", "recipient") and target_src[1]["data"]["missing"] == "data"),
        ("05e every stored field masked", TOKEN not in raw_state and "[masked:" in raw_state),
        ("05g report lists grants and declarations with decisions and limits", API in section
         and "refused (missing data)" in section and "audit record" in section and "not OS-enforced" in section),
    ]


def tc_skill_and_legacy():
    text = " ".join((GUARD_SKILL / "SKILL.md").read_text(encoding="utf-8").lower().split())
    phrases = ["open with the defaults or less", "ask the user to extend", "never extend the budget yourself",
               "register an attempt before every unit of work", "pause only while waiting for the user",
               "do no work while paused", "stop new attempts and conclude when the budget is exhausted",
               "cancel on the user's request", "stop your own reviewer and helper work",
               "declare every outbound call before making it", "send only the declared, minimized and masked data",
               "never send source, findings or credentials to another model or service without a submission grant",
               "the host session and its reviewer sub-agent are not egress"]
    ref = (GUARD_SKILL / "references" / "guard-records.md").read_text(encoding="utf-8")
    schemas = {json.loads(b).get("schema") for b in re.findall(r"```json\n(.*?)```", ref, re.S)}
    checks = [("06a skill instructions (budget, pause, cancel, egress)", all(x in text for x in phrases)),
              ("06a reference documents attempt and egress requests", {ATTEMPT, EGRESS} <= schemas)]
    if os.environ.get("FAT_ISOLATED") != "1":
        return checks
    p, scope = _registered()
    vid = semantic_run(p, scope)
    path = p / GUARD / vid / "state.json"
    legacy = json.loads(path.read_text())
    for key in ("budget", "attempts", "egress", "revision"):
        legacy.pop(key, None)
    legacy["evidence"] = [{**ev("E0", "C1", "py/orders.py"), "stored": None, "masked": False, "masked_types": [],
                           "stored_bytes": 0, "lines": None, "content": None}]
    path.write_text(json.dumps(legacy))
    retry = attempt(p, vid, pairs=[("C1", "semantic-review")])
    fresh = attempt(p, vid, pairs=[("C2", "semantic-review")])
    st = state(p, vid)
    _g(p, "conclude", vid)
    section = report_of(p, vid).split("## Budget", 1)[1].split("\n## ", 1)[0]
    return checks + [
        ("06c legacy run gets the defaults from its opening; earlier work counts as seen", retry[0] == 0
         and retry[1]["data"]["extra"] == 1 and fresh[1]["data"]["extra"] == 0 and st["budget"]["legacy"] is True
         and st["egress"] == {"grants": [], "declarations": []}),
        ("06c report states the budget was defaulted", "toolkit default" in section and "| yes |" in section),
    ]


# ---------------------------------------------------------------- host case (never-authorized User)
def tc_host_user():
    root = Path(tempfile.mkdtemp(prefix="fat-gc-host-")) / "proj"
    root.mkdir()
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    fake = "gv-20261021T000000Z-00000000"
    c1, o1, _, _ = sc("guard", "extend", "--project", str(root), "--run", fake, "--minutes", "5", "--reason", "x",
                      "--json")
    c2, o2, _, _ = sc("guard", "allow-egress", "--project", str(root), "--run", fake, "--purpose", "submission",
                      "--recipient", API, "--data", "findings", "--scope", "src", "--reason", "x", "--json")
    c3, o3, _, _ = sc("guard", "cancel", "--project", str(root), "--run", fake, "--json")
    return [
        ("03e/05b user-only commands refused without an interactive terminal, before anything is read",
         c1 == c2 == 1 and code_of(o1) == code_of(o2) == "INTERACTIVE_REQUIRED"),
        ("04a cancel of an unknown verification refused with a next step", c3 == 1 and code_of(o3) == "RUN_NOT_FOUND"
         and bool(o3["next_steps"])),
        ("nothing written", not (root / GUARD).exists()),
    ]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        assert sc_pty([PASS, PASS], "auth", "init") == 0
        case("TC-C-01", ["AC-002C-01a", "AC-002C-01b"], tc_open_budget)
        case("TC-C-02", ["AC-002C-01c", "AC-002C-01d", "AC-002C-01e", "AC-002C-01f"], tc_attempts)
        case("TC-C-03", ["AC-002C-01g", "AC-002C-03a", "AC-002C-03b", "AC-002C-03c"], tc_exhaustion)
        case("TC-C-04", ["AC-002C-02a", "AC-002C-02b"], tc_pause)
        case("TC-C-05", ["AC-002C-03d", "AC-002C-03e", "AC-002C-06b"], tc_extend)
        case("TC-C-06", ["AC-002C-04a", "AC-002C-04b"], tc_cancel_running_tool)
        case("TC-C-07", ["AC-002C-04c", "AC-002C-04d", "AC-002C-04e", "AC-002C-04f"], tc_cancel_results)
        case("TC-C-08", ["AC-002C-05a", "AC-002C-05b", "AC-002C-05c", "AC-002C-05d", "AC-002C-05e", "AC-002C-05g"],
             tc_egress)
        case("TC-C-09", ["AC-002C-06a", "AC-002C-06c"], tc_skill_and_legacy)
    else:
        case("TC-C-10", ["AC-002C-03e", "AC-002C-05b", "AC-002C-04a"], tc_host_user)
        case("TC-C-09", ["AC-002C-06a"], tc_skill_and_legacy)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
