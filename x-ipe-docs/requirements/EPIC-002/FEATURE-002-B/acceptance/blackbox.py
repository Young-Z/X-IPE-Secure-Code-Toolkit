"""Black-box acceptance scenarios for FEATURE-002-B Adapter contract & Opengrep Adapter (TASK-031).

Calls the real CLI (`uvx --from <framework>/scripts secure-code ...`) and the real Opengrep v1.31.0
binary. Never imports toolkit code.

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
    root = Path(tempfile.mkdtemp(prefix="fat-gb-")) / "proj ü"
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


# ---------------------------------------------------------------- container cases
def tc_registration():
    p = new_project()
    binary = os.environ["OPENGREP"]
    tools = Path(tempfile.mkdtemp(prefix="tools-"))
    marker = tools / "executed"
    fake = tools / "fake-opengrep"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\necho 1.31.0\n")
    fake.chmod(0o755)
    modified = tools / "modified-opengrep"
    shutil.copy(binary, modified)
    with open(modified, "ab") as f:
        f.write(b"\0")
    link = tools / "link-opengrep"
    os.symlink(binary, link)
    c_fake, o_fake, _, _ = register(p, str(fake))
    c_mod, o_mod, _, _ = register(p, str(modified))
    _, o_link, _, _ = register(p, str(link))
    _, o_rel, _, _ = register(p, "opengrep")
    c_ok, o_ok, _, _ = register(p, binary)
    record = json.loads((p / ".x-ipe/private/secure-code/tools/opengrep.json").read_text())
    _, st, _, _ = sc("status", "--project", str(p), "--json")
    t = st["data"]["tools"]
    return [
        ("01c fake binary printing 1.31.0 refused, never executed", c_fake == 1
         and code_of(o_fake) == "TOOL_DIGEST_UNKNOWN" and not marker.exists()),
        ("01c modified official binary refused", c_mod == 1 and code_of(o_mod) == "TOOL_DIGEST_UNKNOWN"),
        ("01c symlink and relative path refused", code_of(o_link) == "TOOL_PATH_INVALID"
         and code_of(o_rel) == "TOOL_PATH_INVALID"),
        ("01a official binary registered with digest, version, platform, validation state", c_ok == 0
         and record["digest"] == OFFICIAL and record["version"] == "1.31.0"
         and record["platform"] == {"os": "linux", "arch": "aarch64", "libc": "glibc"}
         and record["platform_validated"] is True and o_ok["data"]["asset"] == "opengrep_manylinux_aarch64"),
        ("06a status: provided, registered, digest ok, validated", t["opengrep"]["state"] == "provided"
         and t["opengrep"]["registered"] is True and t["opengrep"]["check"] == "ok"
         and t["opengrep"]["platform_validated"] is True),
        ("06b trivy/strix not provided", t["trivy"]["state"] == t["strix"]["state"]
         == "adapter not provided by this toolkit version"),
    ]


def tc_run_findings():
    p, scope = _registered()
    home_before = set(os.listdir(Path.home()))
    before = tree(p, (".x-ipe/private", "x-ipe-docs/secure-code"))
    vid, digests = setup(p, scope, ["java/JWTHeaderKIDEndpoint.java", "py"],
                         [chk("C1", ["java/JWTHeaderKIDEndpoint.java"]), chk("C2", ["py"])])
    with HomeWatch() as watch:
        code, out, _, _ = tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/java-sql.yaml"],
                                            ["java/JWTHeaderKIDEndpoint.java"]),
                                        tc_("C2", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py"])])
    st = state(p, vid)
    f_java = [f for f in st["findings"] if f["check"] == "C1"]
    f_py = [f for f in st["findings"] if f["check"] == "C2"]
    run = st["adapter_runs"][0]
    e1, e2 = ev_of(p, vid, "C1"), ev_of(p, vid, "C2")
    adapter_dir = p / GUARD / vid / "adapter"
    stage_left = list(adapter_dir.glob("stage-*")) if adapter_dir.exists() else []
    texts = [x.read_text(errors="replace") for x in (p / GUARD / vid).rglob("*") if x.is_file()]
    return [
        ("tool run recorded and completed", code == 0 and out["data"]["status"] == "completed"),
        ("03c real CWE-89 finding on WebGoat with provenance", len(f_java) == 1
         and f_java[0]["location"] == {"path": "java/JWTHeaderKIDEndpoint.java", "line": 73}
         and f_java[0]["severity"] == "high" and f_java[0]["cwe"] == "CWE-89" and f_java[0]["source"] == "opengrep"
         and f_java[0]["tool"]["tool_severity"] == "ERROR" and f_java[0]["tool"]["rule_id"] == "java-sql-concat"
         and f_java[0]["tool"]["rule_file"] == "x-ipe-docs/tool-rules/java-sql.yaml" and f_java[0]["rule"] == R1),
        ("03c Python finding attributed to C2 only", [f["location"]["path"] for f in f_py] == ["py/orders.py"]),
        ("03d per-check runtime evidence with provenance", e1["kind"] == e2["kind"] == "runtime"
         and e1["method_status"] == e2["method_status"] == "ok" and e1["paths"] == ["java/JWTHeaderKIDEndpoint.java"]
         and run["version"] == "1.31.0" and run["platform_validated"] is True and run["binary_digest"] == OFFICIAL
         and run["manifest"]["path"].endswith("manifest.json")
         and run["staged_digests"]["py"] == digests["py"]),
        ("02d rule digests recorded and equal to the original rule files", len(run["rules"]) == 2
         and all(r["digest"] == "sha256:" + hashlib.sha256((p / r["path"]).read_bytes()).hexdigest()
                 for r in run["rules"])),
        ("02d executed single-rule config digest recorded per rule id (run entry = manifest)",
         all(set(r["config_digests"]) == set(r["ids"]) for r in run["rules"])
         and {(m["rule_id"], m["config_digest"]) for c in stored(p, vid, run)[0]["checks"].values()
              for m in c["rules"]}
         == {(i, d) for r in run["rules"] for i, d in r["config_digests"].items()}),
        ("03a disposable tool home created in the system temporary folder (Opengrep cache inside) and "
         "removed after the run", len(watch.seen) >= 1 and watch.with_cache == watch.seen
         and watch.left() == []),
        ("03a originals byte-identical; staging removed; real HOME untouched",
         tree(p, (".x-ipe/private", "x-ipe-docs/secure-code")) == before and stage_left == []
         and set(os.listdir(Path.home())) == home_before),
        ("03i token in matched line never stored; matched source removed", all(TOKEN not in t for t in texts)
         and "[removed: matched source]" in (p / GUARD / vid / "evidence/opengrep-1-output.json").read_text()),
        ("03i no tool logs retained", not list((p / GUARD / vid).rglob("semgrep.log"))),
    ]


def tc_accounting():
    p, scope = _registered()
    (p / "app" / "broken.py").write_text("def broken(:\n    pass\n")
    vid, _ = setup(p, scope, ["app", "py/safe.py"], [chk("C1", ["app"]), chk("C2", ["py/safe.py"])])
    tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["app"]),
                  tc_("C2", ["x-ipe-docs/tool-rules/py-sql-2.yaml"], ["py/safe.py"])])
    e1, e2 = ev_of(p, vid, "C1"), ev_of(p, vid, "C2")
    vid2, _ = setup(p, scope, ["app/tests"], [chk("C1", ["app/tests"])])
    tool(p, vid2, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["app/tests"])])
    tool(p, vid2, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql-2.yaml"], ["app/tests"])], include_ignored=True)
    evs = [e for e in state(p, vid2)["evidence"] if e["method"] == "opengrep"]
    return [
        ("03e mixed-language folder: unreported files → failed with hint", e1["method_status"] == "failed"
         and "not reported by the tool" in e1["summary"]),
        ("03e Python syntax error → not analysable gap", "syntax error" in e1["summary"]),
        ("03e other check of the same run unaffected; 03h clean zero results ok", e2["method_status"] == "ok"
         and "0 findings" in e2["summary"]),
        ("03h clean ok backed by the retained tool output and manifest (file scanned, nothing skipped, "
         "unaccounted or in error)", complete_clean(p, vid, "C2", ["py/safe.py"])),
        ("03e ignored tests/ folder → skipped gap by default", evs[0]["method_status"] == "failed"
         and "skipped by the tool" in evs[0]["summary"]),
        ("02a scan mode include_ignored scans it → ok", evs[1]["method_status"] == "ok"
         and "3 scanned" in evs[1]["summary"]),
    ]


def tc_git_worktree():
    p, scope = _registered(git=True)
    vid, _ = setup(p, scope, ["py"], [chk("C1", ["py/orders.py", "py/safe.py"])])
    code, _, _, _ = tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py", "py/safe.py"])])
    e = ev_of(p, vid, "C1")
    return [("git work tree ignoring .x-ipe/private: staged files still scanned", code == 0
             and e["method_status"] == "ok" and "2 scanned" in e["summary"]
             and len([f for f in state(p, vid)["findings"] if f["check"] == "C1"]) == 1)]


def tc_request_refusals():
    p, scope = _registered()
    vid, _ = setup(p, scope, ["py"], [chk("C1", ["py/orders.py"]),
                                      chk("C2", ["py/safe.py"], methods=(READ, dict(TOOL, required=False)),
                                          selected=("semantic-review",), minimum=("reading",))])
    rules_dir = p / "x-ipe-docs/tool-rules"
    os.symlink(rules_dir / "py-sql.yaml", rules_dir / "link.yaml")
    good = [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])]
    cases = {
        "p/default": [tc_("C1", ["p/default"], ["py/orders.py"])],
        "url": [tc_("C1", ["https://semgrep.dev/r/x"], ["py/orders.py"])],
        "folder": [tc_("C1", ["x-ipe-docs/tool-rules"], ["py/orders.py"])],
        "symlink": [tc_("C1", ["x-ipe-docs/tool-rules/link.yaml"], ["py/orders.py"])],
        "taint": [tc_("C1", ["x-ipe-docs/tool-rules/taint.yaml"], ["py/orders.py"])],
        "wider": [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py"])],
        "unselected": [tc_("C2", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/safe.py"])],
    }
    outs = {k: tool(p, vid, v) for k, v in cases.items()}
    bad_limit = tool(p, vid, good, time_limit_seconds=0)
    too_long = tool(p, vid, good, time_limit_seconds=1801)
    unknown = tool(p, vid, good, shell="rm -rf /")
    codes = {k: code_of(o[1]) for k, o in outs.items()}
    nothing = state(p, vid)["evidence"] == [] and state(p, vid).get("adapter_runs", []) == []
    return [
        ("02b registry name, URL, folder, symlink refused", all(outs[k][0] == 1 and codes[k] == "TOOL_REQUEST_INVALID"
                                                             for k in ("p/default", "url", "folder", "symlink"))),
        ("02b unsupported rule feature refused", codes["taint"] == "RULE_FILE_INVALID"),
        ("02c targets wider than the check object refused", codes["wider"] == "TARGETS_MISMATCH"),
        ("04b/04d unselected tool method refused", codes["unselected"] == "METHOD_NOT_SELECTED"),
        ("02e time limit 0 and 1801 refused", code_of(bad_limit[1]) == code_of(too_long[1]) == "TOOL_REQUEST_INVALID"),
        ("02a unknown field (shell text) refused", code_of(unknown[1]) == "TOOL_REQUEST_INVALID"),
        ("nothing executed or recorded by refusals", nothing),
    ]


def tc_precheck_gaps():
    p = new_project()
    tools = Path(tempfile.mkdtemp(prefix="tools-"))
    copy = tools / "opengrep"
    shutil.copy(os.environ["OPENGREP"], copy)
    code, out, _, _ = register(p, str(copy))
    assert code == 0, out
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["py"], [chk("C1", ["py/orders.py"])])
    with open(copy, "ab") as f:
        f.write(b"\0")
    c1, o1, _, _ = tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    _, st, _, _ = sc("status", "--project", str(p), "--json")
    e = ev_of(p, vid, "C1")
    p2 = new_project()
    scope2 = save_scope(p2)
    vid2, _ = setup(p2, scope2, ["py"], [chk("C1", ["py/orders.py"])])
    c2, o2, _, _ = tool(p2, vid2, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    return [
        ("01d swapped binary: precheck_failed, failed method, no findings", c1 == 0
         and o1["data"]["status"] == "precheck_failed" and e["method_status"] == "failed"
         and code_of(o1) == "TOOL_DIGEST_MISMATCH" and state(p, vid)["findings"] == []),
        ("01e next step names Maintainer registration; nothing downloaded or re-registered",
         "tools register" in " ".join(o1["next_steps"])
         and json.loads((p / ".x-ipe/private/secure-code/tools/opengrep.json").read_text())["digest"] == OFFICIAL),
        ("06a status reports the failing digest check", st["data"]["tools"]["opengrep"]["check"] != "ok"),
        ("01d unregistered tool: precheck gap recorded", c2 == 0 and code_of(o2) == "TOOL_NOT_REGISTERED"
         and ev_of(p2, vid2, "C1")["method_status"] == "failed"),
    ]


def tc_target_changed_and_timeout():
    p, scope = _registered()
    vid, _ = setup(p, scope, ["py"], [chk("C1", ["py/orders.py"])])
    (p / "py" / "orders.py").write_text("changed = 1\n")
    tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    e = ev_of(p, vid, "C1")
    p2, scope2 = _registered()
    many = {"rules": [{**PY_RULE, "id": f"r{i}"} for i in range(4)]}
    (p2 / "x-ipe-docs/tool-rules/many.yaml").write_text(json.dumps(many))
    vid2, _ = setup(p2, scope2, ["py"], [chk("C1", ["py"])])
    _, out2, _, _ = tool(p2, vid2, [tc_("C1", ["x-ipe-docs/tool-rules/many.yaml"], ["py"])], time_limit_seconds=1)
    return [
        ("03k changed target: not run, failed evidence", e["method_status"] == "failed"
         and "changed since the verification opened" in e["summary"]),
        ("03g time limit reached → timed_out, failed method", out2["data"]["checks"]["C1"]["status"] == "timed_out"
         and ev_of(p2, vid2, "C1")["method_status"] == "failed"),
    ]


def tc_guard_integration():
    p, scope = _registered()
    vid, digests = setup(p, scope, ["py/orders.py"],
                         [chk("C1", ["py/orders.py"], methods=(READ,), selected=("semantic-review",),
                              minimum=("reading", "runtime"))])
    fake = {"schema": "ai-secure-code-toolkit/guard-record/v1",
            "evidence": [{"id": "E9", "kind": "runtime", "method": "opengrep", "method_status": "ok", "checks": ["C1"],
                          "paths": ["py/orders.py"], "summary": "I ran it"}]}
    c_fake, o_fake, _, _ = g(p, "record", vid, fake)
    change = {"schema": "ai-secure-code-toolkit/guard-record/v1",
              "evidence": [{"id": "E1", "kind": "reading", "method": "semantic-review", "method_status": "ok",
                            "checks": ["C1"], "paths": ["py/orders.py"], "summary": "f-string reaches execute"}],
              "method_changes": [{"check": "C1", "change": "supplement",
                                  "method": {"name": "opengrep", "kind": "runtime"},
                                  "reason": "confirm the sink with a rule"}]}
    c_ch, _, _, _ = g(p, "record", vid, change)
    c_run, _, _, _ = tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/orders.py"])])
    (fid,) = [f["id"] for f in state(p, vid)["findings"]]
    g(p, "record", vid, {"schema": "ai-secure-code-toolkit/guard-record/v1",
                         "ledger": [{"check": "C1", "state": "not_met", "evidence": ["E1", "opengrep-1-1"],
                                     "findings": [fid]}]})
    review = {"schema": "ai-secure-code-toolkit/reviewer-record/v1",
              "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
              "requirement": "re-check the tool finding",
              "reviewed_targets": [{"path": "py/orders.py", "digest": digests["py/orders.py"]}],
              "subjects": [{"type": "finding", "id": fid, "result": "confirmed", "basis": "f-string SQL"},
                           {"type": "na_decision", "id": f"policy:{R2}", "result": "confirmed", "basis": "no HTML"}]}
    g(p, "review", vid, review)
    _, concl, _, _ = g(p, "conclude", vid)
    md = (p / REPORTS / f"{vid}.md").read_text()
    res = json.loads((p / REPORTS / f"{vid}.json").read_text())
    return [
        ("04c agent cannot record opengrep evidence", c_fake == 1 and code_of(o_fake) == "RECORD_INVALID"),
        ("04e supplement recorded and activates the tool", c_ch == 0 and c_run == 0
         and state(p, vid)["plan"]["method_changes"][0]["reason"] == "confirm the sink with a rule"),
        ("04c reviewed high tool finding → Fail by 002-A rules", concl["data"]["verdict"] == "fail"
         and [r["code"] for r in concl["data"]["reasons"]] == ["CONFIRMED_FINDING"]),
        ("04e report shows method choices, changes and Adapter runs", "## Method Choices and Changes" in md
         and "confirm the sink with a rule" in md and "## Adapter Runs" in md and "1.31.0" in md
         and res["adapter_runs"][0]["n"] == 1),
    ]


def tc_clean_not_pass():
    p, scope = _registered()
    vid, _ = setup(p, scope, ["py/safe.py"], [chk("C1", ["py/safe.py"])])
    tool(p, vid, [tc_("C1", ["x-ipe-docs/tool-rules/py-sql.yaml"], ["py/safe.py"])])
    _, concl, _, _ = g(p, "conclude", vid)
    e = ev_of(p, vid, "C1")
    return [("03h complete clean scan proven from the retained tool output and manifest",
             complete_clean(p, vid, "C1", ["py/safe.py"])),
            ("01f/03h clean ok tool evidence alone is not a pass (ledger still needs a state)",
             e["method_status"] == "ok" and concl["data"]["verdict"] == "cannot_confirm_pass")]


def tc_skill_package():
    text = " ".join((GUARD_SKILL / "SKILL.md").read_text(encoding="utf-8").lower().split())
    ref = (GUARD_SKILL / "references" / "guard-records.md").read_text(encoding="utf-8")
    schemas = {json.loads(b).get("schema") for b in re.findall(r"```json\n(.*?)```", ref, re.S)}
    return [
        ("04f cheapest sufficient, no all-tools default, ask before more, record choice/changes",
         "prefer the cheapest sufficient method" in text and "never run every tool by default" in text
         and "ask the user before adding a new tool, wider targets, extra permissions or budget" in text
         and "record the method choice" in text and "switch or supplement" in text),
        ("tool run instructions: local rules only, never record opengrep yourself",
         "only local rule files" in text and "never record opengrep evidence or findings yourself" in text),
        ("reference documents the tool request", "ai-secure-code-toolkit/guard-tool/v1" in schemas),
    ]


# ---------------------------------------------------------------- host case (never-authorized User)
def tc_host_user():
    root = Path(tempfile.mkdtemp(prefix="fat-gb-host-")) / "proj"
    root.mkdir()
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    binary = root.parent / "opengrep"
    binary.write_bytes(b"#!/bin/sh\necho 1.31.0\n")
    binary.chmod(0o755)
    _, auth, _, _ = sc("auth", "status", "--json")
    c, out, _, _ = register(root, str(binary))
    _, st, _, _ = sc("status", "--project", str(root), "--json")
    return [
        ("host User role", auth["data"].get("role") == "user"),
        ("01b registration refused without Maintainer authorization", c == 1 and code_of(out) == "NOT_AUTHORIZED"
         and bool(out["next_steps"])),
        ("06a status: provided, not registered, with next step", st["data"]["tools"]["opengrep"]["state"] == "provided"
         and st["data"]["tools"]["opengrep"]["registered"] is False
         and "tools register" in st["data"]["tools"]["opengrep"]["next_step"]),
        ("nothing recorded", not (root / ".x-ipe/private/secure-code/tools").exists()),
    ]


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        assert sc_pty([PASS, PASS], "auth", "init") == 0
        case("TC-B-01", ["AC-002B-01a", "AC-002B-01c", "AC-002B-06a", "AC-002B-06b"], tc_registration)
        case("TC-B-02", ["AC-002B-02d", "AC-002B-03a", "AC-002B-03b", "AC-002B-03c", "AC-002B-03d", "AC-002B-03i",
                         "AC-002B-04a"], tc_run_findings)
        case("TC-B-03", ["AC-002B-02a", "AC-002B-03e", "AC-002B-03h"], tc_accounting)
        case("TC-B-04", ["AC-002B-03e"], tc_git_worktree)
        case("TC-B-05", ["AC-002B-02a", "AC-002B-02b", "AC-002B-02c", "AC-002B-02e", "AC-002B-04b", "AC-002B-04d"],
             tc_request_refusals)
        case("TC-B-06", ["AC-002B-01d", "AC-002B-01e", "AC-002B-06a"], tc_precheck_gaps)
        case("TC-B-07", ["AC-002B-03g", "AC-002B-03k"], tc_target_changed_and_timeout)
        case("TC-B-08", ["AC-002B-04c", "AC-002B-04e"], tc_guard_integration)
        case("TC-B-09", ["AC-002B-01f", "AC-002B-03h"], tc_clean_not_pass)
        case("TC-B-10", ["AC-002B-04f"], tc_skill_package)
    else:
        case("TC-B-11", ["AC-002B-01b", "AC-002B-06a"], tc_host_user)
        case("TC-B-10", ["AC-002B-04f"], tc_skill_package)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
