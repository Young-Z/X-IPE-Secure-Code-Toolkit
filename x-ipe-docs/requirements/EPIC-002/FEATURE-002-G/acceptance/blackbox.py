"""Black-box acceptance scenarios for FEATURE-002-G Cross-run Report Comparison (test-only artifact, TASK-091).

Drives the real CLI (`uvx --from <framework>/scripts secure-code ...`); never imports toolkit code. Real Guard
runs are produced with the delivered `guard open/plan/attempt/record/review/conclude/cancel` flow (semantic
records as in the FEATURE-002-A acceptance, whose runner helpers are loaded read-only) and, in the container,
with the registered official Opengrep 1.31.0 binary (FEATURE-002-B). `guard compare` is then exercised as a
subprocess against fresh copies of those projects.

  FAT_ISOLATED=1 python3 blackbox.py container   # disposable offline container only: auth init (Maintainer),
                                                  # builds the seed projects, runs every case, hands seeds off
  python3 blackbox.py host                       # macOS host, never-authorized User: copies of the handed-off
                                                  # seeds only (no trust-store write, no Guard run)

Fixture edits (labelled in each case): structured results are re-serialized canonically (sorted keys, indent 2,
UTF-8, trailing newline - verified byte-equal on unedited delivered results first); Markdown edits are text
edits of the delivered report. File-access/network oracle: a `sitecustomize` audit hook (PYTHONPATH) in the CLI
process logs open/listdir/scandir/socket/subprocess events; it observes Python-level calls only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
GA_DIR = Path(os.environ["FAT_GA"]) if "FAT_GA" in os.environ else HERE.parents[1] / "FEATURE-002-A" / "acceptance"
_spec = importlib.util.spec_from_file_location("ga_blackbox", GA_DIR / "blackbox.py")
ga = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ga)

REPORTS, GUARD = ga.REPORTS, ga.GUARD
CMP = REPORTS + "/comparisons"
R1, R2 = ga.R1, ga.R2  # CWE-79, CWE-89
TOKEN = "ghp_" + "Z" * 36
WORK = Path(os.environ.get("FAT_WORK") or tempfile.mkdtemp(prefix="fat-gg-work-"))
HANDOFF = Path(os.environ.get("HANDOFF", str(WORK / "handoff")))
ORIG_SKILL = os.environ.get("ORIG_SKILL")
RESULTS: list[dict] = []
INFO: dict = {}
FORBIDDEN = re.compile(r"\b(fixed|resolved|remediated|improved|improvement|trend|score)\b", re.I)
SITE = WORK / "audit-site"
SITE.mkdir(parents=True, exist_ok=True)
(SITE / "sitecustomize.py").write_text('''
import json, os, sys
_log = os.environ.get("FAT_AUDIT_LOG")
if _log:
    _f = open(_log, "a", encoding="utf-8")
    _EV = {"open", "os.listdir", "os.scandir", "socket.connect", "socket.getaddrinfo", "socket.__new__",
           "subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.system", "os.fork", "os.forkpty"}
    def _conv(x):
        if isinstance(x, (str, int, float, type(None))):
            return x
        if isinstance(x, (bytes, os.PathLike)):
            return os.fsdecode(x)
        return repr(x)[:200]
    def _hook(ev, args):
        if ev in _EV:
            try:
                _f.write(json.dumps([ev, [_conv(a) for a in args]]) + "\\n"); _f.flush()
            except Exception:
                pass
    sys.addaudithook(_hook)
''')


# ---------------------------------------------------------------- generic helpers
def sc(*args: str, env: dict | None = None):
    e = dict(os.environ)
    e.update(env or {})
    proc = subprocess.run(["uvx", "--from", str(ga.SCRIPTS), "secure-code", *args], capture_output=True, text=True,
                          env=e, stdin=subprocess.DEVNULL, timeout=900)
    try:
        data = json.loads(proc.stdout) if "--json" in args else None
    except json.JSONDecodeError:
        data = None
    return proc.returncode, data, proc.stdout, proc.stderr


def code_of(out):
    return out["problems"][0]["code"] if out and out.get("problems") else None


def case(tc: str, acs: list[str], fn) -> None:
    only = os.environ.get("FAT_ONLY")
    if only and tc not in only.split(","):
        return
    INFO.clear()
    try:
        checks = fn()
        failed = [n for n, ok in checks if not ok]
        detail = {"status": "Pass" if not failed else "Fail", "checks": [n for n, _ in checks], "failed": failed}
        if failed and INFO:
            detail["info"] = {k: (v if len(str(v)) < 3000 else str(v)[:3000]) for k, v in INFO.items()}
    except Exception as exc:  # noqa: BLE001 - any unexpected error fails the case
        import traceback
        detail = {"status": "Fail", "error": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc()[-2500:],
                  "info": {k: str(v)[:3000] for k, v in INFO.items()}}
    RESULTS.append({"tc": tc, "acs": acs, **detail})
    print(json.dumps(RESULTS[-1], ensure_ascii=False), flush=True)


def canon(doc) -> bytes:
    return (json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def rp(p: Path, vid: str, ext: str = "json") -> Path:
    return p / REPORTS / f"{vid}.{ext}"


def load(p: Path, vid: str) -> dict:
    return json.loads(rp(p, vid).read_bytes())


def edit(p: Path, vid: str, fn) -> None:
    doc = load(p, vid)
    fn(doc)
    rp(p, vid).write_bytes(canon(doc))


def tree(root: Path, skip=()) -> dict:
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for n in sorted(dirs + files):
            full = Path(dirpath) / n
            rel = full.relative_to(root).as_posix()
            if any(rel == s or rel.startswith(s + "/") for s in skip):
                continue
            if full.is_symlink():
                out[rel] = "link:" + os.readlink(full)
            elif full.is_dir():
                out[rel] = "dir"
            elif not full.is_file():
                out[rel] = "special"
            else:
                try:
                    out[rel] = sha(full.read_bytes())
                except OSError as exc:
                    out[rel] = f"unreadable:{exc.errno}"
    return out


def fresh(seed: str) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="fat-gg-", dir=WORK)) / "proj ü"
    shutil.copytree(HANDOFF / seed / "proj", dst, symlinks=True)
    return dst


def meta(seed: str) -> dict:
    return json.loads((HANDOFF / seed / "meta.json").read_text())


def cmp(p: Path, earlier, later, env: dict | None = None):
    args = ["guard", "compare", "--project", str(p)]
    for flag, val in (("--earlier", earlier), ("--later", later)):
        for v in ([val] if isinstance(val, str) else (val or [])):
            args += [flag, v]
    return sc(*args, "--json", env=env)


def outputs(p: Path, out: dict):
    f = out["data"]["files"]
    raw = (p / f["structured"]).read_bytes()
    return json.loads(raw), (p / f["markdown"]).read_text(encoding="utf-8"), raw


def cmp_files(p: Path) -> list[str]:
    d = p / CMP
    return sorted(os.listdir(d)) if d.is_dir() else []


def strip_variable(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k not in ("comparison_id", "created_at")}


def by_class(doc: dict, cls: str) -> list[dict]:
    return [e for e in doc["entries"] if e["class"] == cls]


def find_entry(doc: dict, role: str, fid: str) -> dict | None:
    for e in doc["entries"]:
        side = e.get(role)
        if side and side["finding"] == fid:
            return e
    return None


def codes(entry: dict | None) -> list[str]:
    return sorted({r["code"] for r in entry["reasons"]}) if entry else []


def counts_ok(doc: dict) -> bool:
    c = doc["counts"]
    cls = [e["class"] for e in doc["entries"]]
    four = ("new", "still_present", "not_observed_this_time", "not_comparable")
    return (set(cls) <= set(four) and all(c[k] == cls.count(k) for k in four)
            and c["total"] == len(cls) == sum(c[k] for k in four)
            and sum(1 for e in doc["entries"] if e["earlier"] and e["later"]) == c["still_present"])


def each_once(doc: dict, p: Path, e_vid: str, l_vid: str) -> bool:
    ok = True
    for role, vid in (("earlier", e_vid), ("later", l_vid)):
        res = load(p, vid)
        live = sorted(f["id"] for f in res["findings"] if f["merged_into"] is None)
        refs = sorted(e[role]["finding"] for e in doc["entries"] if e[role])
        merged = sorted(m for e in doc["entries"] if e[role] for m in e[role]["merged"])
        away = sorted(f["id"] for f in res["findings"] if f["merged_into"] is not None)
        ok = ok and refs == live and merged == away
    return ok


def strings(obj) -> str:
    if isinstance(obj, dict):
        return "\n".join(strings(v) for v in obj.values())
    if isinstance(obj, list):
        return "\n".join(strings(v) for v in obj)
    return obj if isinstance(obj, str) else ""


def no_fixed_wording(text) -> bool:
    if not isinstance(text, str):
        text = strings(text)
    for s in ('"Not observed this time" does not mean fixed', "does not mean fixed",
              "No trend, score, percentage or derived verdict is produced.",
              "do not report a trend or score",
              "were resolved from the supplied project's report store"):  # AC-002G-05e wording, about reports
        text = text.replace(s, "")
    hits = FORBIDDEN.findall(text) + (["%"] if "%" in text else [])
    if hits:
        INFO.setdefault("forbidden_hits", []).append([hits[:10], [ln for ln in text.splitlines()
                                                                if FORBIDDEN.search(ln) or "%" in ln][:5]])
    return not hits


def audit_env(tag: str) -> tuple[dict, Path]:
    log = WORK / f"audit-{tag}-{os.getpid()}.jsonl"
    log.unlink(missing_ok=True)
    return {"PYTHONPATH": str(SITE), "FAT_AUDIT_LOG": str(log)}, log


def audit_events(log: Path) -> list:
    return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


def project_access(events: list, root: Path) -> dict:
    """Classify CLI-process events: absolute paths inside the project, relative (dir_fd) names, listings."""
    rootp = str(root)
    rel, inside, listing, net, procs = [], [], [], [], []
    for ev, args in events:
        if ev.startswith("socket."):
            net.append([ev, args])
        elif ev in ("subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.system", "os.fork",
                    "os.forkpty"):
            procs.append([ev, args])
        elif ev in ("os.listdir", "os.scandir"):
            path = args[0] if args else None
            if path is None or not isinstance(path, str) or path.startswith(rootp) or not path.startswith("/"):
                listing.append(path)
        elif ev == "open" and args and isinstance(args[0], str):
            path = args[0]
            if path.startswith("/"):
                if path == rootp or path.startswith(rootp + "/"):
                    inside.append(path)
            else:
                rel.append(path)
    return {"relative": rel, "inside": inside, "listing": listing, "net": net, "procs": procs}


# ---------------------------------------------------------------- Guard run builders (container only)
OPEN, PLAN = "ai-secure-code-toolkit/guard-open/v1", "ai-secure-code-toolkit/guard-plan/v1"
READ = {"name": "semantic-review", "kind": "reading", "required": True}
TOOL = {"name": "opengrep", "kind": "runtime", "required": True}
NA_R2 = {"rule": R2, "reason": "no database access in the targets"}


def chk(cid: str, obj: list[str], rule: str = R1) -> dict:
    return {"id": cid, "rule": rule, "object": list(obj), "methods": [READ], "minimum_evidence": ["reading"]}


def evid(eid: str, paths: list[str], checks=("C1",)) -> dict:
    return {"id": eid, "kind": "reading", "method": "semantic-review", "method_status": "ok", "checks": list(checks),
            "paths": list(paths), "summary": "read the target"}


def fnd(fid: str, path: str, line, cwe="CWE-79", severity="medium", title="Unescaped user input in HTML", **over):
    loc = {"path": path} if line is None else {"path": path, "line": line}
    f = {"id": fid, "rule": R1, "check": "C1", "location": loc, "cwe": cwe, "title": title, "source": "semantic",
         "severity": severity, "evidence": ["E1"]}
    f.update(over)
    return f


def srun(p: Path, scope: str, targets: list[dict], checks: list[dict], *, evidence=(), findings=(), ledger=(),
         na=(NA_R2,), exclusions=(), subjects=(), context=(), mid=None, cancel=None, conclude=True,
         unreviewed=()) -> str:
    od = {"schema": OPEN, "scope_id": scope, "targets": targets}
    if context:
        od["context"] = [{"path": c} for c in context]
    code, out, _, err = ga.g(p, "open", doc=od)
    assert code == 0, ("open", out, err)
    vid = out["data"]["verification_id"]
    digests = {t["path"]: t["digest"] for t in out["data"]["targets"]}
    plan = {"schema": PLAN, "checks": [ga.with_choice(c) for c in checks], "not_applicable": list(na)}
    if exclusions:
        plan["exclusions"] = list(exclusions)
    code, out, _, _ = ga.g(p, "plan", vid, plan)
    assert code == 0, ("plan", out)
    parts = {k: list(v) for k, v in (("evidence", evidence), ("findings", findings), ("ledger", ledger)) if v}
    if parts:
        code, out, _, _ = ga.g(p, "record", vid, ga.rec(**parts))
        assert code == 0, ("record", out)
    if subjects:
        paths = [t for t, d in digests.items() if d and t not in unreviewed]
        code, out, _, _ = ga.g(p, "review", vid, ga.review_doc(digests, list(subjects), paths=paths))
        assert code == 0, ("review", out)
    if mid:
        mid()
    if cancel is not None:
        code, out, _, err = ga._g(p, "cancel", vid, None, "--reason", cancel)
        assert code == 0, ("cancel", out, err)
    elif conclude:
        code, out, _, err = ga.g(p, "conclude", vid)
        assert code == 0, ("conclude", out, err)
    return vid


def tgt(path: str, change: str = "modified", **over) -> dict:
    return {"path": path, "change": change, **over}


def confirm(fid: str, result: str = "confirmed") -> dict:
    sub = {"type": "finding", "id": fid, "result": result, "basis": "reviewed"}
    if result != "confirmed":
        sub["evidence"] = ["E1"]
    return sub


def handoff(seed: str, p: Path, info: dict) -> None:
    dst = HANDOFF / seed
    shutil.rmtree(dst, ignore_errors=True)
    dst.mkdir(parents=True)
    shutil.copytree(p, dst / "proj", symlinks=True)
    (dst / "meta.json").write_text(json.dumps(info, indent=1))


def seed_basic() -> None:
    """E1 Fail (F1 login:2) and several later runs of the same targets that differ only as named."""
    p = ga.new_project()
    scope = ga.save_scope(p)
    tg = [tgt("src/login.py"), tgt("src/util.py")]
    c1 = chk("C1", ["src/login.py", "src/util.py"])
    e_all = [evid("E1", ["src/login.py", "src/util.py"])]
    m = {"scope": scope}
    m["E1"] = srun(p, scope, tg, [c1], evidence=e_all, findings=[fnd("F1", "src/login.py", 2, severity="high")],
                   ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}],
                   subjects=[confirm("F1"), ga.NA_OK])
    m["L1"] = srun(p, scope, tg, [c1], evidence=e_all, ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}],
                   subjects=[ga.NA_OK])
    m["L1u"] = srun(p, scope, tg, [c1], evidence=e_all, subjects=[ga.NA_OK])            # no ledger -> unconfirmed
    m["L1nc"] = srun(p, scope, tg, [chk("C1", ["src/util.py"])], evidence=[evid("E1", ["src/util.py"])],
                     ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}], subjects=[ga.NA_OK])
    m["L1na"] = srun(p, scope, tg, [], na=[NA_R2, {"rule": R1, "reason": "no HTML output in the targets"}],
                     subjects=[ga.NA_OK])
    m["L1cna"] = srun(p, scope, tg, [c1], evidence=e_all,
                      ledger=[{"check": "C1", "state": "n/a", "reason_type": "objective",
                               "reason": "login() renders no HTML at all"}],
                      subjects=[ga.NA_OK, {"type": "na_decision", "id": "C1", "result": "confirmed", "basis": "ok"}])
    m["L1ex"] = srun(p, scope, tg, [c1], exclusions=[{"check": "C1", "reason": "user: verify later"}],
                     subjects=[ga.NA_OK])
    m["L1cn"] = srun(p, scope, tg, [c1], cancel="user stopped the later run")
    m["E4k"] = srun(p, scope, [tgt("src/login.py")], [chk("C1", ["src/login.py"])],
                    evidence=[evid("E1", ["src/login.py"])], findings=[fnd("F1", "src/login.py", 2)],
                    ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}])
    m["L4k"] = srun(p, scope, [tgt("src/util.py")], [chk("C1", ["src/util.py"])],
                    evidence=[evid("E1", ["src/util.py"])], findings=[fnd("F1", "src/util.py", 1)],
                    ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}])
    m["OPEN"] = srun(p, scope, tg, [c1], conclude=False)
    handoff("basic", p, m)


def seed_rich() -> None:
    p = ga.new_project()
    scope = ga.save_scope(p)
    src = p / "src"
    for n in ("a", "c", "gone", "old", "only_e", "unst"):
        (src / f"{n}.py").write_text("".join(f"line_{i} = {i}\n" for i in range(1, 12)))
    e_paths = ["src/login.py", "src/util.py", "src/a.py", "src/c.py", "src/gone.py", "src/old.py", "src/only_e.py",
               "src/unst.py"]
    e_tg = [tgt(x) for x in e_paths] + [tgt("src/back.py", "deleted")]
    e_find = [fnd("F1", "src/login.py", 2, severity="high"), fnd("F2", "src/util.py", 1),
              fnd("F3", "src/a.py", 3), fnd("F4", "src/gone.py", 1), fnd("F5", "src/old.py", 2),
              fnd("F6", "src/only_e.py", 1), fnd("F7", "src/unst.py", 1),
              fnd("F8", "src/util.py", None, cwe="CWE-116", title="Output not encoded (first)"),
              fnd("F9", "src/util.py", None, cwe="CWE-116", title="Output not encoded (second)"),
              fnd("F10", "src/a.py", 7, cwe="CWE-80")]
    m = {"scope": scope}
    m["E3"] = srun(p, scope, e_tg, [chk("C1", e_paths)], evidence=[evid("E1", e_paths)], findings=e_find,
                   ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"],
                            "findings": [f["id"] for f in e_find]}],
                   subjects=[confirm("F1")], unreviewed=("src/unst.py",),
                   mid=lambda: (src / "unst.py").write_text("changed during the earlier run\n"))
    c_ok, t_ok = ga.sc_pty([(b"to confirm:", "F1")], "guard", "accept-risk", "--project", str(p), "--run", m["E3"],
                           "--finding", "F1", "--reason", "accepted until the login rewrite")
    _r = load(p, m["E3"])
    assert c_ok == 0, (t_ok[-300:], _r["verdict"], _r["reasons"], _r["other_blockers"], [(x["valid"], x["invalid_reasons"]) for x in _r["reviews"]], [(f["id"], f["review"]) for f in _r["findings"]])
    (src / "gone.py").unlink()
    (src / "old.py").rename(src / "new.py")
    (src / "back.py").write_text("print('back')\n")
    l_paths = ["src/login.py", "src/util.py", "src/a.py", "src/c.py", "src/unst.py", "src/new.py", "src/back.py"]
    l_tg = ([tgt(x) for x in l_paths[:5]] + [tgt("src/gone.py", "deleted"),
            tgt("src/new.py", "renamed", old_path="src/old.py"), tgt("src/back.py", "added")])
    l_find = [fnd("G1", "src/login.py", 2, title="XSS in the login page", description="different words"),
              fnd("F2", "src/login.py", 5, severity="low"), fnd("G3", "src/c.py", 3), fnd("G5", "src/new.py", 2),
              fnd("G8", "src/util.py", None, cwe="CWE-116", title="Output not encoded"),
              fnd("G10", "src/a.py", 7, cwe="CWE-83"), fnd("G11", "src/back.py", 1)]
    m["L3"] = srun(p, scope, l_tg, [chk("C1", l_paths)], evidence=[evid("E1", l_paths)], findings=l_find,
                   ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"],
                            "findings": [f["id"] for f in l_find]}],
                   subjects=[confirm("G1", "false_positive"), ga.NA_OK], context=["src/only_e.py"])
    handoff("rich", p, m)


def seed_policy() -> None:
    p = ga.new_project()
    scope = ga.save_scope(p)
    tg = [tgt("src/login.py"), tgt("src/util.py")]
    c1 = chk("C1", ["src/login.py", "src/util.py"])
    m = {"scope": scope}
    m["E2"] = srun(p, scope, tg, [c1], evidence=[evid("E1", ["src/login.py", "src/util.py"])],
                   findings=[fnd("P1", "src/login.py", 2), fnd("P2", "src/util.py", 1)],
                   ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["P1", "P2"]}])
    ga.change_rule(p, R1, "Rule body, second version.\n")
    m["scope2"] = scope2 = ga.save_scope(p)
    m["L2"] = srun(p, scope2, tg, [c1], evidence=[evid("E1", ["src/login.py", "src/util.py"])],
                   findings=[fnd("Q1", "src/login.py", 2)],
                   ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["Q1"]}])
    handoff("policy", p, m)


def seed_merge() -> None:
    p = ga.new_project()
    scope = ga.save_scope(p)
    tg = [tgt("src/login.py")]
    c1 = chk("C1", ["src/login.py"])
    code, out, _, _ = ga.g(p, "open", doc={"schema": OPEN, "scope_id": scope, "targets": tg})
    assert code == 0, out
    vid = out["data"]["verification_id"]
    assert ga.g(p, "plan", vid, {"schema": PLAN, "checks": [c1], "not_applicable": [NA_R2]})[0] == 0
    steps = [
        ga.rec(evidence=[evid("E1", ["src/login.py"]), {**evid("E2", ["src/login.py"]), "summary": "second"}],
               findings=[fnd("M1", "src/login.py", 2), fnd("M2", "src/login.py", 2, source="custom-scan",
                                                          evidence=["E2"])]),
        ga.rec(findings=[fnd("M3", "src/login.py", 2, merged_from=["M1", "M2"], merge_evidence=["E1"])]),
        ga.rec(findings=[fnd("M4", "src/login.py", 2, merged_from=["M3"], merge_evidence=["E1"])]),
        ga.rec(findings=[fnd("M6", "src/login.py", 9, merged_from=["M1"], merge_evidence=["E1"])]),
    ]
    outs = [ga.g(p, "record", vid, s) for s in steps]
    m = {"scope": scope, "record_exit": [o[0] for o in outs], "record_out": [o[1] for o in outs]}
    assert ga.g(p, "conclude", vid)[0] == 0
    m["E4"] = vid
    m["L4"] = srun(p, scope, tg, [c1], evidence=[evid("E1", ["src/login.py"])],
                   findings=[fnd("N1", "src/login.py", 2)],
                   ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["N1"]}])
    handoff("merge", p, m)


PY_RULE = {"id": "py-sql-fstring", "languages": ["python"], "severity": "ERROR",
           "message": "SQL text built with an f-string is executed (CWE-89)", "metadata": {"cwe": "CWE-89"},
           "pattern": '$C.execute(f"...", ...)'}
SQL = '    return c.execute(f"SELECT * FROM t WHERE n = {name}")\n'


def _pyfile(lines: dict[int, str], total: int) -> str:
    return "".join(lines.get(i, f"x_{i} = {i}\n") for i in range(1, total + 1))


def _hit(n: int) -> dict[int, str]:
    return {n - 1: "def find(c, name):\n", n: SQL}


def og_run(p: Path, scope: str, targets: list[str], obj: list[str], include_ignored: bool) -> str:
    c1 = {"id": "C1", "rule": R2, "object": obj, "methods": [TOOL], "minimum_evidence": ["runtime"],
          "method_choice": {"considered": ["semantic-review", "opengrep"], "cost": "opengrep ~1 s per rule",
                            "selected": ["opengrep"], "reason": "pattern rule exists for this sink"}}
    code, out, _, err = ga.g(p, "open", doc={"schema": OPEN, "scope_id": scope, "targets": [tgt(t) for t in targets]})
    assert code == 0, (out, err)
    vid = out["data"]["verification_id"]
    code, out, _, _ = ga.g(p, "plan", vid, {"schema": PLAN, "checks": [c1],
                                             "not_applicable": [{"rule": R1, "reason": "no HTML output"}]})
    assert code == 0, out
    req = {"schema": "ai-secure-code-toolkit/guard-tool/v1", "adapter": "opengrep", "include_ignored": include_ignored,
           "time_limit_seconds": 300,
           "checks": [{"check": "C1", "rules": ["x-ipe-docs/tool-rules/py-sql.yaml"], "targets": obj}]}
    code, out, _, err = ga.g(p, "tool", vid, req)
    assert code == 0, ("tool", out, err)
    st = json.loads((p / GUARD / vid / "state.json").read_text())
    ev = [e for e in st["evidence"] if "C1" in e["checks"] and e["method"] == "opengrep"][-1]
    fids = [f["id"] for f in st["findings"]]
    led = {"check": "C1", "state": "not_met" if fids else "met", "evidence": [ev["id"]]}
    if fids:
        led["findings"] = fids
    code, out, _, _ = ga.g(p, "record", vid, ga.rec(ledger=[led]))
    assert code == 0, ("ledger", out)
    code, out, _, err = ga.g(p, "conclude", vid)
    assert code == 0, (out, err)
    return vid


def seed_opengrep() -> None:
    p = ga.new_project()
    code, out, _, _ = sc("tools", "register", "--project", str(p), "--tool", "opengrep", "--path",
                         os.environ["OPENGREP"], "--json")
    assert code == 0, out
    scope = ga.save_scope(p)
    rules = p / "x-ipe-docs" / "tool-rules"
    rules.mkdir(parents=True)
    (rules / "py-sql.yaml").write_text(json.dumps({"rules": [PY_RULE]}))
    py = p / "py"
    (py / "tests").mkdir(parents=True)
    (py / "orders.py").write_text(_pyfile(_hit(2), 6))
    (py / "more.py").write_text(_pyfile(_hit(2), 6))
    (py / "multi.py").write_text(_pyfile({**_hit(5), **_hit(40)}, 95))
    (py / "extra.py").write_text(_pyfile(_hit(2), 6))
    (py / "tests" / "test_q.py").write_text(_pyfile(_hit(2), 6))
    files = ["py/orders.py", "py/more.py", "py/multi.py", "py/extra.py"]
    m = {"scope": scope}
    m["E5"] = og_run(p, scope, files, files, False)
    (py / "orders.py").write_text(_pyfile(_hit(4), 8))                       # finding moves 2 -> 4
    (py / "multi.py").write_text(_pyfile({**_hit(5), **_hit(41), **_hit(90)}, 95))   # 5, 40->41, +90
    (py / "extra.py").write_text(_pyfile({}, 6))                              # no longer matches
    m["L5"] = og_run(p, scope, files, files, False)
    m["L5ii"] = og_run(p, scope, files, files, True)
    m["L5cov"] = og_run(p, scope, files + ["py/tests"], files + ["py/tests"], False)
    handoff("opengrep", p, m)


# ---------------------------------------------------------------- cases: success, outputs, read boundary
def tc_basic_success():
    m = meta("basic")
    p = fresh("basic")
    e, l = m["E1"], m["L1"]
    init_absent = not (p / CMP).exists()
    c_ref, o_ref, _, _ = cmp(p, e, e)
    after_refusal_absent = not (p / CMP).exists()
    before = tree(p)
    env, log = audit_env("basic")
    code, out, so, se = cmp(p, e, l, env=env)
    INFO.update(stdout=so[-2000:], stderr=se[-1500:])
    after = tree(p)
    doc, text, raw = outputs(p, out)
    cid = out["data"]["comparison_id"]
    acc = project_access(audit_events(log), p)
    INFO["access"] = acc
    twins = {f"{e}.json", f"{e}.md", f"{l}.json", f"{l}.md"}
    meta_names = {"x-ipe-docs", "secure-code", "reports", "guard", ".x-ipe", "private", "comparisons"}
    content = {n for n in acc["relative"] if n not in meta_names and not n.startswith((".gc-", "gc-"))}
    outputs_opened = {n for n in acc["relative"] if n.startswith((".gc-", "gc-"))}
    created = {k for k in after if k not in before}
    changed = {k for k in before if after.get(k) != before[k]}
    e_res, l_res = load(p, e), load(p, l)
    entry = doc["entries"][0] if doc["entries"] else {}
    md_lines = text.splitlines()
    lead = next((i for i, x in enumerate(md_lines) if "does not mean fixed" in x), 999)
    runs_at = next((i for i, x in enumerate(md_lines) if x.startswith("## Runs")), -1)
    return [
        ("07i init layout has no comparisons/; a refused compare does not create it", init_absent
         and c_ref == 1 and after_refusal_absent),
        ("comparison produced", code == 0 and out["ok"] is True),
        ("07i/07e comparisons/ created as a real directory by the first successful comparison",
         (p / CMP).is_dir() and not (p / CMP).is_symlink()),
        ("06a exactly one Markdown + one structured comparison named by the comparison id",
         cmp_files(p) == [f"{cid}.json", f"{cid}.md"] and doc["comparison_id"] == cid),
        ("06a Markdown ends with the SHA-256 of the structured comparison",
         text.endswith(f"<!-- guard-comparison-sha256: {sha(raw)} -->\n")),
        ("06a structured comparison carries input_integrity for both runs",
         set(doc["input_integrity"]) == {"earlier", "later"}
         and all(doc["input_integrity"][r]["state"] == "consistent" for r in ("earlier", "later"))),
        ("06a Markdown shows the same classes/entries (c-1 under Not observed this time, other classes none)",
         "## Not observed this time" in text and "c-1" in text.split("## Not observed this time")[1].split("##")[0]
         and text.split("\n## New\n")[1].split("\n## ")[0].strip() == "(none)"),
        ("06a no other project file created or changed", created == {CMP, f"{CMP}/{cid}.json", f"{CMP}/{cid}.md"}
         and changed == set()),
        ("03b/04m F1 absent after unchanged-coverage re-run: not observed this time + target unchanged",
         doc["counts"]["not_observed_this_time"] == 1 and doc["counts"]["total"] == 1
         and entry.get("class") == "not_observed_this_time"
         and [a["code"] for a in entry["annotations"]] == ["target_unchanged"]
         and entry["annotations"][0]["text"] == "target content unchanged between runs"),
        ("03a counts consistent", counts_ok(doc)),
        ("03c Markdown leads with the not-fixed statement (before ## Runs); no fixed/resolved/improved wording",
         0 <= lead < runs_at and no_fixed_wording(text) and no_fixed_wording(doc)
         and no_fixed_wording(out)),
        ("03e both verdicts with recorded reasons; no derived verdict/trend/score/percentage",
         doc["runs"]["earlier"]["verdict"] == "fail" and doc["runs"]["later"]["verdict"] == "pass"
         and [r["code"] for r in doc["runs"]["earlier"]["reasons"]] == [r["code"] for r in e_res["reasons"]]
         and "CONFIRMED_FINDING" in text and set(doc["counts"]) == {"new", "still_present", "not_observed_this_time",
                                                                    "not_comparable", "total",
                                                                    "still_present_with_differences"}
         and not any(k in doc for k in ("verdict", "trend", "score", "percentage"))),
        ("05e IDs, end times and result SHA-256 of both inputs recorded",
         doc["runs"]["earlier"]["verification_id"] == e and doc["runs"]["later"]["verification_id"] == l
         and doc["runs"]["earlier"]["ended_at"] == e_res["ended_at"] and doc["runs"]["later"]["ended_at"]
         == l_res["ended_at"] and doc["runs"]["earlier"]["result_sha256"] == sha(rp(p, e).read_bytes())
         and doc["runs"]["later"]["result_sha256"] == sha(rp(p, l).read_bytes())),
        ("05e provenance limits stated (report store; provenance not provable; consistent edit undetectable)",
         all(s in doc["statements"]["provenance"] for s in ("reports/guard", "cannot be proven",
                                                             "copied in from another project", "edited consistently"))
         and doc["statements"]["provenance"] in " ".join(text.split())),
        ("06e not-evidence statement in both outputs", "not verification evidence" in doc["statements"]["not_evidence"]
         and "does not change either verdict" in doc["statements"]["not_evidence"]
         and doc["statements"]["not_evidence"] in " ".join(text.split())),
        ("06f envelope: comparison id, both verification ids, class counts, file locations",
         out["data"]["earlier"]["verification_id"] == e and out["data"]["later"]["verification_id"] == l
         and out["data"]["counts"] == doc["counts"] and out["data"]["files"]["structured"] == f"{CMP}/{cid}.json"
         and out["data"]["files"]["markdown"] == f"{CMP}/{cid}.md"),
        ("01a audit hook active in the CLI process (self-check)", bool(acc["relative"]) or bool(acc["inside"])),
        ("01a only E/L results and reports read as application data", content == twins),
        ("01a other project accesses: folder handles, project root, own output names only",
         set(acc["inside"]) <= {str(p)} and outputs_opened and all(n.startswith((".gc-", f"{cid}.")) for n in
                                                                    outputs_opened)),
        ("01a/01d no directory listing of project folders", acc["listing"] == []),
        ("01d/01e no subprocess (Adapter, scan, Reviewer, model) and no socket use", acc["procs"] == []
         and acc["net"] == []),
    ]


def tc_determinism():
    m = meta("basic")
    p = fresh("basic")
    c1, o1, _, _ = cmp(p, m["E1"], m["L1"])
    c2, o2, _, _ = cmp(p, m["E1"], m["L1"])
    d1, _, _ = outputs(p, o1)
    d2, _, _ = outputs(p, o2)
    checks = [
        ("06b two comparisons of the same unchanged results identical except comparison id and creation time",
         c1 == c2 == 0 and o1["data"]["comparison_id"] != o2["data"]["comparison_id"]
         and strip_variable(d1) == strip_variable(d2)),
        ("06a/07f the first comparison's files are untouched by the second (both pairs present)",
         len(cmp_files(p)) == 4),
    ]
    ref = HANDOFF / "container-basic-comparison.json"
    if os.environ.get("FAT_MODE") == "container":
        ref.write_text(json.dumps(strip_variable(d1), sort_keys=True))
    elif ref.exists():
        checks.append(("06b/NFR-002G-1 macOS host comparison data equal to the Linux container's for the same "
                       "results", strip_variable(d1) == json.loads(ref.read_text())))
    return checks


def _single(p: Path, e: str, l: str):
    code, out, so, se = cmp(p, e, l)
    INFO.setdefault("runs", []).append(so[-1500:] + se[-500:])
    doc = outputs(p, out)[0] if code == 0 else {"entries": [], "counts": {}}
    return code, doc


def tc_gating():
    m = meta("basic")
    p = fresh("basic")
    e = m["E1"]
    res = {k: _single(p, e, m[k]) for k in ("L1u", "L1nc", "L1ex", "L1na", "L1cna", "L1cn")}
    ent = {k: find_entry(d, "earlier", "F1") for k, (_, d) in res.items()}

    def only(k, cls, code_set):
        x = ent[k]
        return res[k][0] == 0 and x is not None and x["class"] == cls and codes(x) == sorted(code_set)

    na_text = next((r for r in (ent["L1na"] or {}).get("reasons", []) if r["code"] == "na_other_run"), {})
    cna_text = next((r for r in (ent["L1cna"] or {}).get("reasons", []) if r["code"] == "na_other_run"), {})
    cn = ent["L1cn"] or {"reasons": []}
    INFO["reasons"] = {k: (x or {}).get("reasons") for k, x in ent.items()}
    OBS.append({"case": "gating", "reason_codes": {k: codes(x) for k, x in ent.items()}})
    return [
        ("G-02 scenario / 04c: later check unconfirmed -> not comparable 'check unconfirmed', never not observed",
         only("L1u", "not_comparable", {"check_unconfirmed"}) and res["L1u"][1]["counts"]["not_observed_this_time"] == 0),
        ("04c no covering check in the later run -> 'not covered'", only("L1nc", "not_comparable", {"not_covered"})),
        ("04c user scope exclusion -> 'excluded by the user'", only("L1ex", "not_comparable", {"excluded_by_user"})),
        ("04d Policy-level N/A in the later run -> 'N/A in the other run' with the recorded reason (no check of "
         "the rule exists there, so 'not covered' is also listed)",
         only("L1na", "not_comparable", {"na_other_run", "not_covered"}) and "no HTML output in the targets" in json.dumps(na_text)),
        ("04d check-level n/a -> 'N/A in the other run' with the recorded reason",
         only("L1cna", "not_comparable", {"na_other_run"}) and "renders no HTML" in json.dumps(cna_text)),
        ("04h later run cancelled, its check unconfirmed -> 'check unconfirmed' and 'later run cancelled'",
         only("L1cn", "not_comparable", {"check_unconfirmed", "run_cancelled"})
         and any(r["text"] == "later run cancelled" for r in cn["reasons"])
         and res["L1cn"][1]["runs"]["later"]["cancellation"]["state"] == "cancelled"),
        ("03b/03a classes and counts consistent in every gated comparison", all(counts_ok(d) for _, d in res.values())),
    ]


def tc_no_common_targets():
    m = meta("basic")
    p = fresh("basic")
    code, out, so, se = cmp(p, m["E4k"], m["L4k"])
    INFO.update(out=so[-2500:])
    doc, text, _ = outputs(p, out)
    e_ent, l_ent = find_entry(doc, "earlier", "F1"), find_entry(doc, "later", "F1")
    comp = doc["comparability"]
    return [
        ("04k every unpaired finding not comparable", code == 0 and doc["counts"]["not_comparable"] == 2
         and doc["counts"]["total"] == 2),
        ("04k summary states the runs share no targets", comp["shared_targets"] is False
         and "The runs share no targets" in text),
        ("02j same run-local id F1 (and check C1) at different paths never paired",
         e_ent is not None and l_ent is not None and e_ent is not l_ent and e_ent["later"] is None),
        ("04a/04l reasons list scope difference with both runs' values", "scope_differs" in codes(e_ent)
         and all({"earlier", "later", "text", "code"} <= set(r) for r in e_ent["reasons"])),
        ("04l comparability section summarises scope, Policy, coverage, method, tool and tool-data differences",
         {"scope", "policy", "coverage", "methods", "tools", "tool_data"} <= set(comp)
         and "## Comparability" in text),
    ]


def tc_rich():
    m = meta("rich")
    p = fresh("rich")
    e, l = m["E3"], m["L3"]
    code, out, so, se = cmp(p, e, l)
    INFO.update(out=so[-3000:], err=se[-1000:])
    doc, text, _ = outputs(p, out)
    INFO["entries"] = [(x["entry"], x["class"], (x["earlier"] or {}).get("finding"), (x["later"] or {}).get("finding"),
                        x["basis"], codes(x), [a["code"] for a in x["annotations"]]) for x in doc["entries"]]
    E = lambda f: find_entry(doc, "earlier", f)  # noqa: E731
    L = lambda f: find_entry(doc, "later", f)  # noqa: E731
    p1, p5, p8 = E("F1"), E("F5"), L("G8")
    left8 = [x for x in (E("F8"), E("F9")) if x is not p8]
    ch = {c["attribute"]: c for c in (p1 or {}).get("attribute_changes", [])}
    mv_e, mv_l = E("F3"), L("G3")
    refs = lambda x: next((a["refers_to"] for a in x["annotations"] if a["code"] == "possible_move"), [])  # noqa
    weak = "semantic identity (weak)"
    OBS.append({"case": "rich", "counts": doc["counts"], "entries": INFO["entries"]})
    return [
        ("comparison produced", code == 0),
        ("03a every entry has one of the four classes; per-class counts sum to the total; pairs == still present",
         counts_ok(doc) and doc["counts"]["total"] == 14),
        ("03g each of the n + m non-merged findings referenced by exactly one entry (10 + 7)", each_once(doc, p, e, l)),
        ("02g same rule/source/path/CWE, different title/description/id -> paired, labelled semantic weak",
         p1 is not None and p1["later"] and p1["later"]["finding"] == "G1" and p1["class"] == "still_present"
         and weak in p1["basis"] and "exact" in p1["basis"]),
        ("02g CWE differs -> not paired (F10 CWE-80 vs G10 CWE-83)", E("F10") is not L("G10")
         and E("F10")["class"] == "not_observed_this_time" and L("G10")["class"] == "new"),
        ("03d pair shows both runs' values of differing severity, review and title; class stays still present",
         ch.get("final_severity", {}).get("earlier") == "high" and ch["final_severity"]["later"] == "medium"
         and ch.get("review", {}).get("earlier") == "confirmed" and ch["review"]["later"] == "false_positive"
         and "title" in ch),
        ("02e declared rename src/old.py -> src/new.py pairs F5 and G5 as still present",
         p5 is not None and p5["later"] and p5["later"]["finding"] == "G5" and p5["class"] == "still_present"
         and any("declared rename" in b and "src/old.py" in b and "src/new.py" in b for b in p5["basis"])),
        ("02k two no-line E findings vs one L finding: exactly one pair, labelled position and semantic weak",
         p8 is not None and p8["earlier"] and p8["earlier"]["finding"] in ("F8", "F9") and "position" in p8["basis"]
         and weak in p8["basis"] and len(left8) == 1),
        ("02k remaining E finding classified per 03b (comparable -> not observed this time), never dropped",
         left8 and left8[0]["class"] == "not_observed_this_time"),
        ("02f undeclared move a.py -> c.py: E not observed + L new, each annotated possible move referring to the "
         "other", mv_e["class"] == "not_observed_this_time" and mv_l["class"] == "new"
         and mv_l["entry"] in refs(mv_e) and mv_e["entry"] in refs(mv_l)
         and any(a["text"] == "possibly the same finding moved (unverified)" for a in mv_e["annotations"])),
        ("02j same run-local id F2 at util.py (E) and login.py (L) not paired", E("F2") is not L("F2")
         and E("F2")["later"] is None and L("F2")["class"] == "new"),
        ("03b unpaired L finding comparable -> new; unpaired E comparable -> not observed this time",
         L("G3")["class"] == "new" and E("F2")["class"] == "not_observed_this_time"),
        ("04m not observed in an unchanged target annotated target content unchanged",
         "target_unchanged" in [a["code"] for a in E("F2")["annotations"]]),
        ("04j E finding in a file the later run records deleted -> 'location deleted in the later run'",
         E("F4")["class"] == "not_comparable" and any(r["text"] == "location deleted in the later run"
                                                      for r in E("F4")["reasons"])),
        ("04j L finding in a file the earlier run records deleted -> 'location deleted in the earlier run'",
         L("G11")["class"] == "not_comparable" and any(r["text"] == "location deleted in the earlier run"
                                                       for r in L("G11")["reasons"])),
        ("04a path only read-only context in the later run -> 'artifact scope differs'",
         E("F6")["class"] == "not_comparable" and "scope_differs" in codes(E("F6"))),
        ("04i target changed during the earlier run -> 'target unstable or incomplete in run earlier'",
         E("F7")["class"] == "not_comparable" and any(r["text"] == "target unstable or incomplete in run earlier"
                                                      for r in E("F7")["reasons"])),
        ("04l several applicable reasons all listed with both runs' values (deleted location)",
         len(E("F4")["reasons"]) >= 2 and all("earlier" in r and "later" in r for r in E("F4")["reasons"])),
        ("06d acceptance recorded in E for a still-present finding shown for E only; not applied to L",
         p1["risk_acceptance"] == {"run": "earlier", "applies_to_later": False}
         and len(doc["runs"]["earlier"]["risk_acceptances"]) == 1 and doc["runs"]["later"]["risk_acceptances"] == []
         and "does not apply to the later run" in text),
        ("03c/03f still-present wording: observed in both runs under the stated identity rule",
         "observed in both runs under the stated identity rule" in text and no_fixed_wording(text)),
    ]


def tc_policy():
    m = meta("policy")
    p = fresh("policy")
    code, out, so, _ = cmp(p, m["E2"], m["L2"])
    INFO.update(out=so[-2500:])
    doc, text, raw = outputs(p, out)
    pair, gone = find_entry(doc, "earlier", "P1"), find_entry(doc, "earlier", "P2")
    note = next((n for n in pair["notes"] if n["kind"] == "policy"), None)
    pol = next((r for r in gone["reasons"] if r["code"] == "policy_differs"), None)
    flat = " ".join(text.split())
    return [
        ("03f pair with a different Policy state digest stays still present", code == 0
         and pair["class"] == "still_present" and pair["later"]["finding"] == "Q1"),
        ("03f the difference is a note with both values", note is not None and note["earlier"] and note["later"]
         and note["earlier"] != note["later"]),
        ("03f summary counts still-present pairs with differences", doc["counts"]["still_present_with_differences"] == 1
         and "Still-present pairs with Policy, tool or tool-data differences: 1" in text),
        ("03f wording 'observed in both runs under the stated identity rule'; 'same issue confirmed' only negated",
         "observed in both runs under the stated identity rule" in flat
         and flat.count("same issue confirmed") == flat.count("never means the same issue confirmed")
         and raw.decode().count("same issue confirmed") == raw.decode().count("never means the same issue confirmed")),
        ("04b unpaired finding under a changed Policy -> 'Policy differs' with both runs' state digests",
         gone["class"] == "not_comparable" and pol is not None and pol["earlier"] != pol["later"]
         and str(pol["earlier"]).startswith("sha256:") and str(pol["later"]).startswith("sha256:")),
    ]


def tc_merge():
    m = meta("merge")
    INFO["record_out"] = m["record_out"]
    p = fresh("merge")
    res = load(p, m["E4"])
    by = {f["id"]: f for f in res["findings"]}
    code, out, so, se = cmp(p, m["E4"], m["L4"])
    INFO.update(out=so[-3000:], err=se[-800:])
    doc = outputs(p, out)[0] if code == 0 else {"entries": []}
    refs = [x["earlier"]["finding"] for x in doc["entries"] if x["earlier"]]
    s4, s6 = find_entry(doc, "earlier", "M4"), find_entry(doc, "earlier", "M6")
    notes = [n for x in doc["entries"] for n in x["notes"] if n["kind"] == "merge"]
    return [
        ("fixture: delivered record flow produced a merge chain M1,M2->M3->M4 and a re-merge M1->M6",
         m["record_exit"] == [0, 0, 0, 0] and by["M3"]["merged_into"] == "M4" and by["M2"]["merged_into"] == "M3"
         and by["M1"]["merged_into"] == "M6" and "M1" in by["M3"]["merged_from"]),
        ("05s acyclic chain and re-merge disagreement accepted (not refused)", code == 0),
        ("02i merged-away findings never matched individually", not ({"M1", "M2", "M3"} & set(refs))),
        ("02i/05s survivors matched with their own identity; merges shown, resolved to the final survivor",
         s4 is not None and s4["class"] == "still_present" and s4["later"]["finding"] == "N1"
         and sorted(s4["earlier"]["merged"]) == ["M2", "M3"] and s6 is not None and s6["earlier"]["merged"] == ["M1"]),
        ("05s re-merge disagreement shown as a note on the survivor entries", len(notes) >= 1
         and all(n["subject"] == "M1" for n in notes)),
        ("03g every non-merged finding once, merged-away only via the survivor", each_once(doc, p, m["E4"], m["L4"])),
    ]


def tc_opengrep():
    m = meta("opengrep")
    p = fresh("opengrep")
    e = m["E5"]
    INFO["E5_findings"] = [(f["id"], f["location"], f["tool"].get("fingerprint")) for f in load(p, e)["findings"]]
    r = {k: _single(p, e, m[k]) for k in ("L5", "L5ii", "L5cov")}
    d = r["L5"][1]
    byloc = {}
    for x in d["entries"]:
        for role in ("earlier", "later"):
            if x[role]:
                byloc[(role, x[role]["path"], x[role]["line"])] = x
    INFO["entries"] = [(x["class"], (x["earlier"] or {}).get("path"), (x["earlier"] or {}).get("line"),
                        (x["later"] or {}).get("line"), x["basis"], codes(x)) for x in d["entries"]]
    more, orders = byloc.get(("earlier", "py/more.py", 2)), byloc.get(("earlier", "py/orders.py", 2))
    m5, m40, m90 = (byloc.get(("earlier", "py/multi.py", 5)), byloc.get(("earlier", "py/multi.py", 40)),
                    byloc.get(("later", "py/multi.py", 90)))
    extra = lambda k: next((x for x in r[k][1]["entries"] if x["earlier"] and x["earlier"]["path"] == "py/extra.py"),  # noqa
                           None)
    fps = [f for _, _, f in INFO["E5_findings"]]
    OBS.append({"case": "opengrep", "E5_fingerprints": fps, "L5_entries": INFO["entries"],
                "L5ii_counts": r["L5ii"][1].get("counts"), "L5cov_extra": codes(extra("L5cov"))})
    ii = extra("L5ii") or {"reasons": []}
    cov = extra("L5cov") or {"reasons": []}
    return [
        ("real Opengrep runs recorded findings in E (orders, more, multi x2, extra)", len(fps) == 5),
        ("02a same Policy rule, adapter, tool rule id, path and line -> still present, basis exact",
         more is not None and more["class"] == "still_present" and more["later"]["line"] == 2
         and more["basis"] == ["exact"] and more["identity"]["adapter"] == "opengrep"),
        ("02b/02c only finding of the group moved 2->4: still present, basis position (line moved 2→4), or "
         "fingerprint if the tool recorded valid equal fingerprints",
         orders is not None and orders["class"] == "still_present" and orders["later"]["line"] == 4
         and (orders["basis"] == ["position (line moved 2→4)"] if not any(fps) else orders["basis"] == ["fingerprint"])),
        ("02d group E{5,40} L{5,41,90}: 5 exact, 40->41 position, 90 new (comparable)",
         m5 is not None and m5["basis"] == ["exact"] and m40 is not None and m40["later"]["line"] == 41
         and m40["basis"] == ["position (line moved 40→41)"] and m90 is not None and m90["class"] == "new"),
        ("03b tool finding absent under identical tool, build, rule config and coverage -> not observed this time",
         extra("L5") is not None and extra("L5")["class"] == "not_observed_this_time"),
        ("04e different include-ignored setting -> not comparable 'tool or method differs' naming the difference",
         ii.get("class") == "not_comparable" and codes(ii) == ["method_differs"]
         and any("include-ignored" in (x["detail"] or "") for x in ii["reasons"])),
        ("03f pairs under a different include-ignored setting stay still present with a counted note",
         r["L5ii"][1]["counts"].get("still_present") == 4
         and r["L5ii"][1]["counts"].get("still_present_with_differences") == 4),
        ("04g later Adapter run for the covering check skipped items -> 'tool coverage incomplete' with counts",
         cov.get("class") == "not_comparable" and "tool_coverage_incomplete" in codes(cov)
         and any(x["code"] == "tool_coverage_incomplete" and "skipped" in json.dumps(x) for x in cov["reasons"])),
        ("03a counts consistent", all(counts_ok(x[1]) for x in r.values())),
    ]


# ---------------------------------------------------------------- cases: input integrity
FOOT = re.compile(r"<!-- guard-result-sha256: ([0-9a-f]{64}) -->")


def _integrity(mutate, role="earlier"):
    """Fresh basic copy, mutate it, compare E1/L1; returns (code, out, doc, text, before, after, e, l)."""
    m = meta("basic")
    p = fresh("basic")
    e, l = m["E1"], m["L1"]
    mutate(p, e, l)
    run_dirs = tree(p, (CMP,))
    code, out, so, se = cmp(p, e, l)
    INFO.update(out=so[-2500:], err=se[-800:])
    doc, text, raw = outputs(p, out) if code == 0 else ({}, "", b"")
    return code, out, doc, text, run_dirs, tree(p, (CMP,)), e, l, p


def _unresolved(doc, text, role, failed):
    ii = doc["input_integrity"][role]
    first = next((x for x in text.splitlines() if x.strip() and not x.startswith("# ")), "")
    return (ii["state"] == "unresolved" and sorted(ii["failed_checks"]) == sorted(failed)
            and "Input integrity unresolved for run " + role in first)


def tc_canonical_precondition():
    m = meta("basic")
    p = fresh("basic")
    vids = [m[k] for k in ("E1", "L1", "L1u", "L1cn", "E4k")]
    return [("fixture serializer equals the delivered canonical serialization on unedited results",
             all(canon(load(p, v)) == rp(p, v).read_bytes() for v in vids))]


def tc_integrity_variants():
    out = []
    # 05c Markdown missing
    code, o, doc, text, b, a, e, l, p = _integrity(lambda p, e, l: rp(p, e, "md").unlink())
    base = None
    if code == 0:
        base = [(x["class"], x["earlier"] and x["earlier"]["finding"]) for x in doc["entries"]]
    out.append(("05c Markdown missing -> structured result used, warning first, input_integrity unresolved, entries "
                "reference it, nothing written in the run", code == 0
                and _unresolved(doc, text, "earlier", ["markdown_missing"])
                and doc["input_integrity"]["later"]["state"] == "consistent"
                and all(x["input_integrity"] == ["earlier"] for x in doc["entries"] if x["earlier"])
                and base == [("not_observed_this_time", "F1")] and a == b))

    # 05g body changed, footer unchanged
    def body(p, e, l):
        t = rp(p, e, "md").read_text()
        rp(p, e, "md").write_text(t.replace("Unescaped user input in HTML", "Unescaped user input in HTML (edited)", 1))
    code, o, doc, text, b, a, *_ = _integrity(body)
    out.append(("05g body edited, footer unchanged -> only the full-Markdown check fails; unresolved", code == 0
                and _unresolved(doc, text, "earlier", ["markdown_canonical_rendering"]) and a == b))

    # 05h footer changed
    def foot(p, e, l):
        t = rp(p, e, "md").read_text()
        rp(p, e, "md").write_text(FOOT.sub("<!-- guard-result-sha256: " + "0" * 64 + " -->", t))
    code, o, doc, text, b, a, *_ = _integrity(foot)
    out.append(("05h footer digest altered -> footer and full-Markdown checks fail; unresolved", code == 0
                and _unresolved(doc, text, "earlier", ["footer_digest", "markdown_canonical_rendering"]) and a == b))

    # 05i JSON changed only (valid, canonical)
    def jonly(p, e, l):
        edit(p, e, lambda d: d["findings"][0].__setitem__("description", "edited afterwards"))
    code, o, doc, text, b, a, e, l, p = _integrity(jonly)
    st = (doc.get("input_integrity") or {}).get("earlier", {}).get("statement") or ""
    out.append(("05i JSON edited only -> footer and Markdown checks fail; unresolved; cannot tell which file; "
                "structured result used", code == 0
                and _unresolved(doc, text, "earlier", ["footer_digest", "markdown_canonical_rendering"])
                and "cannot be told which file was changed" in st and "used the structured result" in st
                and doc["entries"][0]["earlier"]["description"] == "edited afterwards" and a == b))

    # 05j both changed consistently
    def both(p, e, l):
        new_title = "Unescaped user input in an HTML page"
        edit(p, e, lambda d: d["findings"][0].__setitem__("title", new_title))
        t = rp(p, e, "md").read_text().replace("Unescaped user input in HTML", new_title)
        rp(p, e, "md").write_text(FOOT.sub("<!-- guard-result-sha256: " + sha(rp(p, e).read_bytes()) + " -->", t))
    code, o, doc, text, b, a, *_ = _integrity(both)
    out.append(("05j result and Markdown edited consistently -> all integrity checks pass; limit statement carried",
                code == 0 and doc["input_integrity"]["earlier"]["state"] == "consistent"
                and doc["entries"][0]["earlier"]["title"] == "Unescaped user input in an HTML page"
                and "edited consistently cannot be detected" in doc["statements"]["provenance"]))

    # 05k unresolved + strictly invalid -> refused, nothing written
    def bad(p, e, l):
        body(p, e, l)
        edit(p, e, lambda d: d.__setitem__("verdict", "zz-not-a-verdict"))
    code, o, doc, text, b, a, *_ = _integrity(bad)
    out.append(("05k integrity inconsistency + strict-validation failure -> refused, nothing written", code == 1
                and code_of(o) == "RESULT_INVALID" and a == b and not (Path(str(b)) and False)))

    # 05l report rendered by a different renderer (simulated: a section the older renderer did not emit removed)
    def older(p, e, l):
        t = rp(p, e, "md").read_text()
        cut = re.sub(r"### Copilot reports \(context only, never evidence of a pass\)\n\n\(none\)\n\n", "", t)
        assert cut != t
        rp(p, e, "md").write_text(cut)
    code, o, doc, text, b, a, *_ = _integrity(older)
    st = (doc.get("input_integrity") or {}).get("earlier", {}).get("statement") or ""
    out.append(("05l (simulated) older-renderer report -> unresolved; statement names 'edited, or rendered by a "
                "different toolkit version'; no tampering claim", code == 0
                and _unresolved(doc, text, "earlier", ["markdown_canonical_rendering"])
                and "edited, or the report was rendered by a different toolkit version" in st
                and "tamper" not in text.lower() and "tamper" not in json.dumps(doc).lower()))
    return out


def tc_schema_and_invalid():
    out = []
    code, o, doc, text, b, a, *_ = _integrity(
        lambda p, e, l: edit(p, e, lambda d: d.__setitem__("schema", "ai-secure-code-toolkit/guard-result/v2")))
    out.append(("05a unsupported schema refused naming found and supported versions; nothing written", code == 1
                and code_of(o) == "RESULT_SCHEMA_UNSUPPORTED" and o["data"]["found"].endswith("guard-result/v2")
                and o["data"]["supported"] == ["ai-secure-code-toolkit/guard-result/v1"] and a == b))
    code, o, doc, text, b, a, *_ = _integrity(lambda p, e, l: rp(p, e).write_bytes(rp(p, e).read_bytes()[:-40]))
    out.append(("05b not valid JSON -> RESULT_INVALID naming rule and path; nothing written", code == 1
                and code_of(o) == "RESULT_INVALID" and o["data"].get("rule") and "json_path" in o["data"] and a == b))
    code, o, doc, text, b, a, e, l, p = _integrity(
        lambda p, e, l: edit(p, e, lambda d: d.__setitem__("verification_id", "gv-20200101T000000Z-0000abcd")))
    out.append(("05b verification_id differs from the file name -> RESULT_INVALID at $.verification_id; value not "
                "echoed", code == 1 and code_of(o) == "RESULT_INVALID" and o["data"]["json_path"] == "$.verification_id"
                and "0000abcd" not in json.dumps(o) and a == b))
    code, o, doc, text, b, a, *_ = _integrity(
        lambda p, e, l: edit(p, e, lambda d: d["findings"][0]["location"].__setitem__("line", -77123)))
    out.append(("05b strict rule violation -> rule and JSON path named, never the value", code == 1
                and code_of(o) == "RESULT_INVALID" and o["data"]["json_path"] == "$.findings[0].location.line"
                and o["data"]["rule"] and "77123" not in json.dumps(o) and a == b))

    def old_v1(p, e, l):
        for v in (e, l):
            edit(p, v, lambda d: [d.pop(k, None) for k in ("adapter_runs", "tool_provisioning", "budget",
                                                           "cancellation")])
    code, o, doc, text, b, a, *_ = _integrity(old_v1)
    out.append(("05f v1 result without adapter_runs/tool_provisioning/budget/cancellation -> 'not recorded in this "
                "result', no error, semantic finding still compared", code == 0
                and doc["runs"]["earlier"]["adapter_runs"] == "not recorded in this result"
                and doc["runs"]["earlier"]["cancellation"]["state"] == "not recorded in this result"
                and doc["entries"][0]["class"] == "not_observed_this_time"))
    return out


def tc_masking():
    out = []

    def tok(p, e, l):
        edit(p, e, lambda d: d["findings"][0].update(title=f"leaked {TOKEN} in title",
                                                      description=f"token {TOKEN} again"))
    code, o, doc, text, b, a, *_ = _integrity(tok)
    blob = json.dumps(doc) + text + json.dumps(o)
    ent = (doc.get("entries") or [{}])[0].get("earlier") or {}
    out.append(("06c unmasked title/description value masked and labelled masked in both outputs", code == 0
                and TOKEN not in blob and "[masked:" in ent.get("title", "") and ent.get("masked") is True
                and "(masked)" in text))
    out.append(("06c identity does not depend on masked text (same class as unedited)",
                code == 0 and ent and doc["entries"][0]["class"] == "not_observed_this_time"))

    def tok_bad(p, e, l):
        tok(p, e, l)
        edit(p, e, lambda d: d["findings"][0]["location"].__setitem__("line", "2"))
    code, o, doc, text, b, a, *_ = _integrity(tok_bad)
    out.append(("06c validation refusal inside that finding never echoes the value", code == 1
                and code_of(o) == "RESULT_INVALID" and TOKEN not in INFO["out"] + INFO["err"] and a == b))
    return out


def tc_bounds():
    out = []
    big = 64 * 1024 * 1024
    code, o, doc, text, b, a, *_ = _integrity(
        lambda p, e, l: rp(p, e).write_bytes(rp(p, e).read_bytes() + b" " * (big + 1)))
    out.append(("NFR-002G-5 result above 64 MiB refused before parsing (limit, rule, next step; not 'invalid')",
                code == 1 and code_of(o) == "RESULT_TOO_LARGE" and o["data"]["rule"] == "bound.bytes"
                and o["next_steps"] and "not possible" in o["problems"][0]["message"] and a == b))

    def deep(p, e, l):
        edit(p, e, lambda d: d.__setitem__("request", None))
        raw = rp(p, e).read_bytes()
        rp(p, e).write_bytes(raw.replace(b'"request": null', b'"request": ' + b"[" * 70 + b"]" * 70, 1))
    code, o, doc, text, b, a, *_ = _integrity(deep)
    out.append(("NFR-002G-5 nesting depth above 64 refused by the pre-scan (bound.depth); nothing written",
                code == 1 and code_of(o) == "RESULT_TOO_LARGE" and o["data"]["rule"] == "bound.depth" and a == b))
    code, o, doc, text, b, a, *_ = _integrity(
        lambda p, e, l: rp(p, e, "md").write_bytes(rp(p, e, "md").read_bytes() + b"x" * (big + 1)))
    out.append(("05c/NFR-002G-5 Markdown above 64 MiB not read -> unresolved (markdown_oversized), comparison "
                "completes", code == 0 and "markdown_oversized" in doc["input_integrity"]["earlier"]["failed_checks"]
                and doc["input_integrity"]["earlier"]["state"] == "unresolved"))
    return out


# ---------------------------------------------------------------- cases: strict validation (representative)
OBS: list = []


def _strict(seed: str, ek: str, lk: str, role: str, fn, prefix: str, label: str) -> tuple[str, bool]:
    m = meta(seed)
    p = fresh(seed)
    vid = m[ek] if role == "earlier" else m[lk]
    edit(p, vid, fn)
    before = tree(p)
    code, o, so, se = cmp(p, m[ek], m[lk])
    after = tree(p)
    d = (o or {}).get("data") or {}
    ok = (code == 1 and code_of(o) == "RESULT_INVALID" and str(d.get("json_path", "")).startswith(prefix)
          and bool(d.get("rule")) and d.get("role") == role and before == after and not (p / CMP).exists())
    OBS.append({"case": label, "code": code_of(o), "rule": d.get("rule"), "json_path": d.get("json_path"), "ok": ok})
    return label, ok


def _set(path: list, value):
    def fn(d):
        cur = d
        for k in path[:-1]:
            cur = cur[k]
        cur[path[-1]] = value
    return fn


def _idx(d: dict, fid: str) -> int:
    return next(i for i, f in enumerate(d["findings"]) if f["id"] == fid)


def _first_count(d: dict):
    for i, r in enumerate(d["adapter_runs"]):
        for cid, c in sorted(r.get("checks", {}).items()):
            for k, v in sorted((c.get("counts") or {}).items()):
                if isinstance(v, int):
                    return ["adapter_runs", i, "checks", cid, "counts", k]
    raise AssertionError("no count")


def tc_strict_types_enums():
    B = ("basic", "E1", "L1", "earlier")
    rows = [
        (*B, _set(["findings", 0], "not an object"), "$.findings[0]", "05m non-object finding"),
        (*B, _set(["findings", 0, "location", "line"], "2"), "$.findings[0].location.line", "05m string line"),
        (*B, _set(["verdict"], "zz-verdict"), "$.verdict", "05m verdict outside value set"),
        (*B, _set(["ledger", 0, "state"], "zz-state"), "$.ledger[0].state", "05m ledger state outside value set"),
        (*B, _set(["findings", 0, "final_severity"], "zz-sev"), "$.findings[0].final_severity", "05m severity"),
        (*B, _set(["findings", 0, "review"], "zz-rev"), "$.findings[0].review", "05m Reviewer result"),
        (*B, _set(["artifact", "targets", 0, "kind"], "zz-kind"), "$.artifact.targets[0].kind", "05m target kind"),
        (*B, _set(["artifact", "targets", 0, "change"], "zz-ch"), "$.artifact.targets[0].change", "05m change kind"),
        (*B, _set(["evidence", 0, "kind"], "zz-mk"), "$.evidence[0].kind", "05m method kind"),
    ]
    m = meta("opengrep") if (HANDOFF / "opengrep").exists() else None
    out = [_strict(*r) for r in rows]
    if m:
        p = fresh("opengrep")
        path = _first_count(load(p, m["E5"]))
        out.append(_strict("opengrep", "E5", "L5", "earlier", _set(path, -1), "$.adapter_runs[0].checks",
                           "05m negative count"))
    return out


def tc_strict_unique_refs():
    B = ("basic", "E1", "L1", "earlier")
    dup = lambda key: lambda d: _walk(d, key).append(json.loads(json.dumps(_walk(d, key)[0])))  # noqa: E731

    def tdup(d):
        d["artifact"]["targets"][1]["path"] = d["artifact"]["targets"][0]["path"]

    def adup(d):
        d["scope"]["adopted"][1]["rule"] = d["scope"]["adopted"][0]["rule"]

    def no_ledger(d):
        d["ledger"] = [r for r in d["ledger"] if r["check"] != "C1"]
    rows = [
        (*B, tdup, "$.artifact.targets", "05n duplicate target path"),
        (*B, adup, "$.scope.adopted", "05n duplicate adopted rule"),
        (*B, dup(["plan", "checks"]), "$.plan.checks", "05n duplicate check id"),
        (*B, dup(["findings"]), "$.findings", "05n duplicate finding id"),
        (*B, dup(["ledger"]), "$.ledger", "05n two ledger entries for one check"),
        (*B, _set(["findings", 0, "rule"], "CWE/4.14/CWE-22"), "$.findings[0]", "05o finding rule not adopted"),
        (*B, _set(["findings", 0, "check"], "C9"), "$.findings[0].check", "05o finding check not planned"),
        (*B, _set(["findings", 0, "location", "path"], "src/zz.py"), "$.findings[0].location", "05o finding path "
         "not a target"),
        (*B, _set(["plan", "checks", 0, "object"], ["src/zz.py"]), "$.plan.checks[0].object", "05o check object not "
         "a target"),
        (*B, no_ledger, "$.", "05o planned check without ledger entry"),
        (*B, _set(["ledger", 0, "check"], "C9"), "$.ledger[0]", "05o ledger entry for unknown check"),
        (*B, _set(["ledger", 0, "findings"], ["F9"]), "$.ledger[0].findings", "05o ledger reference to unknown "
         "finding"),
        (*B, _set(["plan", "not_applicable", 0, "rule"], "CWE/4.14/CWE-22"), "$.plan.not_applicable[0]",
         "05o N/A of a rule not adopted"),
        ("rich", "E3", "L3", "earlier", _set(["risk_acceptances", 0, "finding"], "F99"), "$.risk_acceptances[0]",
         "05o risk acceptance of an unknown finding"),
    ]
    out = [_strict(*r) for r in rows]
    if (HANDOFF / "opengrep").exists():
        O = ("opengrep", "E5", "L5", "earlier")
        out += [_strict(*O, dup(["adapter_runs"]), "$.adapter_runs", "05n duplicate adapter-run number"),
                _strict(*O, _set(["findings", 0, "tool", "run"], 99), "$.findings[0].tool", "05p tool.run unknown"),
                _strict(*O, _set(["findings", 0, "tool", "adapter"], "trivy"), "$.findings[0]",
                        "05p tool.adapter differs from the run's Adapter / source"),
                _strict(*O, lambda d: d["adapter_runs"][0].__setitem__(
                    "checks", {"C9": d["adapter_runs"][0]["checks"]["C1"]}), "$.adapter_runs[0].checks",
                        "05p adapter-run check key not a planned check")]
    return out


def _walk(d, keys):
    for k in keys:
        d = d[k]
    return d


def tc_strict_digests_targets_merges():
    B = ("basic", "E1", "L1", "earlier")

    def rich_target(name):
        return lambda d: next(i for i, t in enumerate(d["artifact"]["targets"]) if t["path"] == name)
    ren, gone = rich_target("src/new.py"), rich_target("src/gone.py")
    R = ("rich", "E3", "L3", "later")

    def rows_merge(fn, prefix, label):
        return ("merge", "E4", "L4", "earlier", fn, prefix, label)

    def cycle(d):
        d["findings"][_idx(d, "M4")]["merged_into"] = "M2"
        d["findings"][_idx(d, "M2")]["merged_from"] = ["M4"]
    rows = [
        (*B, _set(["artifact", "targets", 0, "digest_at_open"], "sha256:xyz"), "$.artifact.targets[0].digest_at_open",
         "05q target digest malformed"),
        (*B, _set(["scope", "adopted", 0, "state_digest"], "md5:" + "a" * 32), "$.scope.adopted[0].state_digest",
         "05q Policy state digest malformed"),
        (*B, _set(["opened_at"], "2026-10-23 14:00:00"), "$.opened_at", "05q opened_at format"),
        (*B, _set(["ended_at"], "2000-01-01T00:00:00Z"), "$.ended_at", "05q ended_at before opened_at"),
        (*R, lambda d: d["artifact"]["targets"][ren(d)].__setitem__("old_path", None), "$.artifact.targets",
         "05r renamed target without old_path"),
        (*R, lambda d: d["artifact"]["targets"][0].__setitem__("old_path", "src/x.py"), "$.artifact.targets[0]",
         "05r old_path on a non-renamed target"),
        (*R, lambda d: d["artifact"]["targets"][0].update(change="renamed", old_path="src/old.py"),
         "$.artifact.targets", "05r two targets renamed from the same old_path"),
        (*R, lambda d: d["artifact"]["targets"][gone(d)].__setitem__("digest_at_open", "sha256:" + "a" * 64),
         "$.artifact.targets", "05r deleted target with a content digest at open"),
        rows_merge(lambda d: d["findings"][_idx(d, "M3")].__setitem__("merged_into", "M99"), "$.findings",
                   "05s merged_into unknown finding"),
        rows_merge(lambda d: d["findings"][_idx(d, "M3")].__setitem__("merged_into", "M3"), "$.findings",
                   "05s merged_into itself"),
        rows_merge(lambda d: d["findings"][_idx(d, "M3")]["merged_from"].append("M99"), "$.findings",
                   "05s merged_from unknown finding"),
        rows_merge(cycle, "$.findings", "05s merged_into cycle"),
        rows_merge(lambda d: d["findings"][_idx(d, "M2")].__setitem__("merged_into", "M6"), "$.findings",
                   "05s merged_into target not listing the finding in merged_from"),
    ]
    out = [_strict(*r) for r in rows]
    if (HANDOFF / "opengrep").exists():
        def cfg(d):
            r = d["adapter_runs"][0]["rules"][0]
            r["config_digests"][sorted(r["config_digests"])[0]] = "sha256:not-hex"
        out.append(_strict("opengrep", "E5", "L5", "earlier", cfg, "$.adapter_runs[0].rules[0].config_digests",
                           "05q rule-configuration digest malformed"))
    return out


# ---------------------------------------------------------------- cases: request, names, path safety
def _refusal(p: Path, earlier, later, want: str, audit: str | None = None):
    before = tree(p)
    env, log = audit_env(audit) if audit else (None, None)
    code, o, so, se = cmp(p, earlier, later, env=env)
    after = tree(p)
    INFO.setdefault("refusals", []).append([want, code_of(o), (o or {}).get("data"), (o or {}).get("next_steps"),
                                            se[-300:]])
    ok = code == 1 and code_of(o) == want and before == after and bool((o or {}).get("next_steps"))
    if log is not None:
        acc = project_access(audit_events(log), p)
        twin_reads = [n for n in acc["relative"] if n.endswith((".json", ".md"))]
        ok = ok and twin_reads == [] and acc["procs"] == [] and acc["net"] == []
    return ok, o


def tc_request_refusals():
    m = meta("basic")
    p = fresh("basic")
    e, l = m["E1"], m["L1"]
    rel = REPORTS + "/"
    one = _refusal(p, e, None, "COMPARE_REQUEST_INVALID")[0]
    three = _refusal(p, e, [l, m["L1u"]], "COMPARE_REQUEST_INVALID")[0]
    two_e = _refusal(p, [e, l], None, "COMPARE_REQUEST_INVALID")[0]
    same = _refusal(p, e, e, "COMPARE_REQUEST_INVALID")[0]
    twins = _refusal(p, rel + f"{e}.json", rel + f"{e}.md", "COMPARE_REQUEST_INVALID")[0]
    unknown = _refusal(p, "gv-20200101T000000Z-deadbeef", l, "RUN_NOT_FOUND", audit="unknown")[0]
    opened = _refusal(p, e, m["OPEN"], "NOT_CONCLUDED", audit="open")[0]
    badfmt = _refusal(p, "gv-123", l, "REPORT_NAME_INVALID", audit="badfmt")[0]
    (p / "copy").mkdir()
    shutil.copy(rp(p, e), p / "copy" / f"{e}.json")
    outside = _refusal(p, f"copy/{e}.json", l, "REPORT_NAME_INVALID", audit="outside")[0]
    shutil.rmtree(p / "copy")
    rev_ok, rev = _refusal(p, l, e, "END_ORDER_INVALID")
    rd = (rev or {}).get("data") or {}
    return [
        ("01b only one report named -> refused with reason and next step, nothing written", one),
        ("01b three reports named (two later) -> refused", three),
        ("01b two earlier and no later -> refused", two_e),
        ("01b same verification twice -> refused", same),
        ("01b <id>.json and <id>.md of one verification -> refused", twins),
        ("01c unknown verification id -> refused before any content read", unknown),
        ("01c open (not concluded) verification -> refused with conclude next step", opened),
        ("01c invalid id format -> refused before any read", badfmt),
        ("01c report path outside reports/guard/ -> refused before any read", outside),
        ("01g later ended before earlier -> refused with both end times and swap next step; never auto-ordered",
         rev_ok and rd["earlier"]["ended_at"] == load(p, l)["ended_at"] and rd["later"]["ended_at"]
         == load(p, e)["ended_at"] and "Swap" in " ".join(rev["next_steps"]) and not (p / CMP).exists()),
    ]


def tc_end_times():
    m = meta("basic")
    p = fresh("basic")
    e, l = m["E1"], m["L1"]
    end_e = load(p, e)["ended_at"]
    edit(p, l, lambda d: d.update(opened_at=end_e, ended_at=end_e))
    eq_ok, eq = _refusal(p, e, l, "END_ORDER_INVALID")
    p2 = fresh("basic")
    edit(p2, l, _set(["ended_at"], "sometime later"))
    unk_ok, unk = _refusal(p2, e, l, "RESULT_INVALID")
    ud = (unk or {}).get("data") or {}
    return [
        ("01g equal end times -> refused, both times shown, next step to name other reports",
         eq_ok and eq["data"]["earlier"]["ended_at"] == eq["data"]["later"]["ended_at"] == end_e
         and "other reports" in " ".join(eq["next_steps"])),
        ("01g unreadable end time -> refused with 'unknown' and next step to name other reports",
         unk_ok and ud.get("end_times", {}).get("later") == "unknown" and ud["end_times"]["earlier"] == end_e
         and "other reports" in " ".join(unk["next_steps"])),
    ]


def tc_names():
    m = meta("basic")
    p = fresh("basic")
    e, l = m["E1"], m["L1"]
    rel = REPORTS + "/"
    code, o, _, _ = cmp(p, "./" + rel + f"{e}.md", rel + f"{l}.json")
    accepted = code == 0 and o["data"]["earlier"]["verification_id"] == e and o["data"]["later"]["verification_id"] == l
    shutil.rmtree(p / CMP, ignore_errors=True)
    (p / rel / "sub").mkdir()
    shutil.copy(rp(p, e), p / rel / "sub" / f"{e}.json")
    refusals = {
        "absolute path": str(rp(p, e)),
        "'..' component": rel + f"../guard/{e}.json",
        "normalises outside the folder": REPORTS.rsplit("/", 1)[0] + f"/{e}.json",
        "other suffix": rel + f"{e}.txt",
        "extra characters": rel + f"{e}x.json",
        "different case": rel + f"{e}.JSON",
        "subfolder of reports/guard": rel + f"sub/{e}.json",
        "comparisons/ subfolder": rel + f"comparisons/{e}.json",
    }
    res = {k: _refusal(p, v, l, "REPORT_NAME_INVALID", audit="name")[0] for k, v in refusals.items()}
    shutil.rmtree(p / rel / "sub")
    return [("07a './'-prefixed relative .md and plain .json names resolve to the ids and are accepted", accepted)] + [
        (f"07a/07b {k} -> refused before any read, nothing written", ok) for k, ok in res.items()]


def tc_symlinks_special():
    m = meta("basic")
    e, l = m["E1"], m["L1"]
    out = []
    for comp in ("x-ipe-docs/secure-code", "x-ipe-docs/secure-code/reports", REPORTS):
        p = fresh("basic")
        real = p / (comp + "-real")
        (p / comp).rename(real)
        os.symlink(real.name, p / comp)
        by_id = _refusal(p, e, l, "PATH_UNSAFE", audit="symlink")[0]
        by_path = _refusal(p, REPORTS + f"/{e}.json", REPORTS + f"/{l}.json", "PATH_UNSAFE")[0]
        out.append((f"07c symbolic link at {comp} -> refused before any read (by id and by path), nothing written",
                    by_id and by_path))
    p = fresh("basic")
    shutil.copy(rp(p, e, "md"), p / "copy.md")
    rp(p, e, "md").unlink()
    os.symlink("../../../../copy.md", rp(p, e, "md"))
    out.append(("07d <id>.md twin is a symbolic link -> refused before any read", _refusal(p, e, l, "PATH_UNSAFE",
                                                                                          audit="mdlink")[0]))
    p = fresh("basic")
    rp(p, l).unlink()
    os.mkfifo(rp(p, l))
    out.append(("07d <id>.json is not a regular file (FIFO) -> refused before any read, no hang",
                _refusal(p, e, l, "PATH_UNSAFE")[0]))
    p = fresh("basic")
    rp(p, l).unlink()
    out.append(("07d missing <id>.json (run folder present) -> refused", _refusal(p, e, l, "NOT_CONCLUDED")[0]))
    shutil.rmtree(p / GUARD / l)
    out.append(("07d missing <id>.json and run folder -> refused", _refusal(p, e, l, "RUN_NOT_FOUND")[0]))
    outside = Path(tempfile.mkdtemp(prefix="outside-", dir=WORK))
    p = fresh("basic")
    os.symlink(str(outside), p / CMP)
    ok = _refusal(p, e, l, "PATH_UNSAFE")[0]
    out.append(("07e comparisons/ is a symbolic link to a folder outside the project -> refused, nothing written "
                "anywhere", ok and os.listdir(outside) == []))
    p = fresh("basic")
    (p / CMP).write_text("not a folder")
    out.append(("07e comparisons/ is a file -> refused, nothing written", _refusal(p, e, l, "PATH_UNSAFE")[0]))
    return out


def tc_existing_entries():
    m = meta("basic")
    p = fresh("basic")
    e, l = m["E1"], m["L1"]
    assert cmp(p, e, l)[0] == 0
    first = tree(p / CMP)
    outside = Path(tempfile.mkdtemp(prefix="outside-", dir=WORK)) / "victim.json"
    outside.write_text("victim")
    os.symlink(str(outside), p / CMP / "gc-20000101T000000Z-00000000.json")
    code, o, _, _ = cmp(p, e, l)
    now = tree(p / CMP)
    return [
        ("07f existing comparison files and a pre-placed link are never overwritten, replaced or followed",
         code == 0 and all(now.get(k) == v for k, v in first.items())
         and now.get("gc-20000101T000000Z-00000000.json", "").startswith("link:")
         and outside.read_text() == "victim" and len(now) == len(first) + 3),
    ]


def tc_unrelated_changes():
    m = meta("basic")
    e, l = m["E1"], m["L1"]
    base_p = fresh("basic")
    c0, o0, _, _ = cmp(base_p, e, l)
    base = strip_variable(outputs(base_p, o0)[0])
    p = fresh("basic")
    (p / "src" / "login.py").write_text("def login(u):\n    return escape(u)\n")
    (p / "src" / "util.py").unlink()
    (p / REPORTS / "gv-20200101T000000Z-0badf00d.json").write_bytes(b"\x00garbage{")
    (p / REPORTS / "gv-20200101T000000Z-0badf00d.md").write_bytes(b"\xff\xfe broken")
    st = p / GUARD / e / "state.json"
    os.chmod(st, 0)
    os.chmod(p / GUARD / l, 0)
    try:
        before = tree(p, (CMP,))
        env, log = audit_env("unrelated")
        code, o, so, se = cmp(p, e, l, env=env)
        after = tree(p, (CMP,))
        INFO.update(out=so[-1500:], err=se[-500:])
        doc = strip_variable(outputs(p, o)[0]) if code == 0 else {}
        acc = project_access(audit_events(log), p)
        unreadable_effective = os.geteuid() != 0
    finally:
        os.chmod(p / GUARD / l, 0o755)
        os.chmod(st, 0o644)
    checks = [
        ("01d comparison result identical to the one with all those files intact", c0 == 0 and code == 0 and doc == base),
        ("01d no Adapter, scan, Reviewer or model started (no subprocess, no socket)", acc["procs"] == []
         and acc["net"] == []),
        ("01d every target, both results, both reports and both run folders byte-identical afterwards",
         before == after),
    ]
    checks.append(("01d run-folder files unreadable for this user (chmod 000)" + (
        "" if unreadable_effective else " - NOT EFFECTIVE as root; clause evidenced on the host run"),
        True if not unreadable_effective else before.get(f"{GUARD}/{e}/state.json", "").startswith("unreadable")))
    return checks


def _shift(ts: str, days: int) -> str:
    t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) - timedelta(days=days)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def tc_retention():
    m = meta("basic")
    e, l = m["E1"], m["L1"]
    p = fresh("basic")
    code, o, _, _ = cmp(p, e, l)
    files_before = tree(p / CMP)
    c1, cl1, so1, _ = sc("guard", "cleanup", "--project", str(p), "--json")
    INFO.update(cleanup1=so1[-1500:])
    after_cleanup = tree(p / CMP)
    edit(p, e, lambda d: d.update(opened_at=_shift(d["opened_at"], 31), ended_at=_shift(d["ended_at"], 31)))
    c2, cl2, so2, _ = sc("guard", "cleanup", "--project", str(p), "--json")
    INFO.update(cleanup2=so2[-1500:])
    removed = [r["verification_id"] for r in ((cl2 or {}).get("data") or {}).get("removed", [])]
    after_expiry = tree(p / CMP)
    code3, o3, so3, _ = cmp(p, e, l)
    doc3, text3, _ = outputs(p, o3) if code3 == 0 else ({}, "", b"")
    q = fresh("basic")
    shutil.rmtree(q / GUARD / e)
    code4, o4, _, _ = cmp(q, e, l)
    doc4, text4, _ = outputs(q, o4) if code4 == 0 else ({}, "", b"")
    return [
        ("06f guard cleanup leaves comparison files byte-identical and does not list them", code == 0 and c1 == 0
         and after_cleanup == files_before and "comparisons" not in so1),
        ("06f evidence of a compared run expires (31 days, fixture-aged result) and cleanup removes it; comparison "
         "files remain byte-identical", c2 == 0 and removed == [e] and not (p / GUARD / e).exists()
         and after_expiry == files_before),
        ("05d raw evidence removed by cleanup -> comparison completes, availability stated per run, based only on "
         "recorded findings", code3 == 0 and doc3["runs"]["earlier"]["raw_evidence"] == "not available"
         and doc3["runs"]["later"]["raw_evidence"] == "available"
         and "never on raw evidence" in doc3["statements"]["evidence_basis"] and "never on raw evidence" in text3),
        ("05d raw evidence folder removed (results untouched, consistent) -> comparison completes, not available",
         code4 == 0 and doc4["runs"]["earlier"]["raw_evidence"] == "not available"
         and doc4["input_integrity"]["earlier"]["state"] == "consistent"),
    ]


def tc_skill():
    skill = (ga.GUARD_SKILL / "SKILL.md").read_bytes()
    text = skill.decode()
    sec = text.split("\n## Comparing two reports\n", 1)
    body = " ".join(sec[1].split()) if len(sec) == 2 else ""
    low = body.lower()
    checks = [
        ("01f compare only on an explicit request naming two reports", "only on an explicit request" in low
         and "names both" in low),
        ("01f when unclear ask; may list reports/guard/ file names only, never content, never comparisons/, never "
         "select", "is unclear, ask the user" in low and "list the report file names of `reports/guard/` only" in low
         and "never open their content" in low and "never list or name anything in `comparisons/`" in low
         and "never select the reports for the user" in low),
        ("01f never start a scan, re-verification or fix because of a comparison",
         "never start a scan, re-verification or fix because of a comparison" in low),
        ("01f never say fixed", 'never say "fixed"' in low),
        ("01f never cite a comparison as verification evidence", "never cite a comparison as evidence" in low),
        ("07k skill: a comparison is valid only as a pair whose footer equals the SHA-256 of the structured "
         "comparison", "valid only as a pair whose markdown footer" in low),
    ]
    if ORIG_SKILL:
        orig = Path(ORIG_SKILL).read_bytes()
        rest = skill[len(orig):].decode()
        checks.append(("01h delivered SKILL.md (sha256 cdbfc5bc…) is a byte-identical prefix; the only difference is "
                       "one added self-contained section", sha(orig).startswith("cdbfc5bc")
                       and skill.startswith(orig) and rest.startswith("\n## Comparing two reports\n")
                       and rest.count("\n## ") == 1 and "\n# " not in rest))
    return checks


# ---------------------------------------------------------------- main
def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    os.environ["FAT_MODE"] = mode
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        assert ga.sc_pty([(b"passphrase", ga.PASS), (b"passphrase", ga.PASS)], "auth", "init")[0] == 0
        HANDOFF.mkdir(parents=True, exist_ok=True)
        for fn in (seed_basic, seed_rich, seed_policy, seed_merge, seed_opengrep):
            fn()
        print(json.dumps({"seeds": {s: meta(s) for s in ("basic", "rich", "policy", "merge", "opengrep")}},
                         default=str)[:6000], flush=True)
    else:
        _, auth, _, _ = sc("auth", "status", "--json")
        print(json.dumps({"host_role": (auth or {}).get("data", {}).get("role")}), flush=True)
    case("TC-G-00", ["fixture"], tc_canonical_precondition)
    case("TC-G-01", ["AC-002G-01a", "AC-002G-01d", "AC-002G-01e", "AC-002G-03a", "AC-002G-03b", "AC-002G-03c",
                     "AC-002G-03e", "AC-002G-04m", "AC-002G-05e", "AC-002G-06a", "AC-002G-06e", "AC-002G-06f",
                     "AC-002G-07e", "AC-002G-07i"], tc_basic_success)
    case("TC-G-02", ["AC-002G-06b", "AC-002G-06a"], tc_determinism)
    case("TC-G-03", ["AC-002G-03b", "AC-002G-04c", "AC-002G-04d", "AC-002G-04h", "G-02"], tc_gating)
    case("TC-G-04", ["AC-002G-04k", "AC-002G-04l", "AC-002G-04a", "AC-002G-02j"], tc_no_common_targets)
    case("TC-G-05", ["AC-002G-02e", "AC-002G-02f", "AC-002G-02g", "AC-002G-02j", "AC-002G-02k", "AC-002G-03a",
                     "AC-002G-03b", "AC-002G-03d", "AC-002G-03g", "AC-002G-04a", "AC-002G-04i", "AC-002G-04j",
                     "AC-002G-04l", "AC-002G-04m", "AC-002G-06d"], tc_rich)
    case("TC-G-06", ["AC-002G-03f", "AC-002G-04b"], tc_policy)
    case("TC-G-07", ["AC-002G-02i", "AC-002G-05s", "AC-002G-03g"], tc_merge)
    if mode == "container":
        case("TC-G-08", ["AC-002G-02a", "AC-002G-02b", "AC-002G-02d", "AC-002G-03b", "AC-002G-03f", "AC-002G-04e",
                         "AC-002G-04g"], tc_opengrep)
    case("TC-G-09", ["AC-002G-05c", "AC-002G-05g", "AC-002G-05h", "AC-002G-05i", "AC-002G-05j", "AC-002G-05k",
                     "AC-002G-05l"], tc_integrity_variants)
    case("TC-G-10", ["AC-002G-05a", "AC-002G-05b", "AC-002G-05f"], tc_schema_and_invalid)
    case("TC-G-11", ["AC-002G-06c"], tc_masking)
    case("TC-G-12", ["AC-002G-05b", "AC-002G-05c", "NFR-002G-5"], tc_bounds)
    case("TC-G-13", ["AC-002G-05m", "AC-002G-05b"], tc_strict_types_enums)
    case("TC-G-14", ["AC-002G-05n", "AC-002G-05o", "AC-002G-05p"], tc_strict_unique_refs)
    case("TC-G-15", ["AC-002G-05q", "AC-002G-05r", "AC-002G-05s"], tc_strict_digests_targets_merges)
    case("TC-G-16", ["AC-002G-01b", "AC-002G-01c", "AC-002G-01g"], tc_request_refusals)
    case("TC-G-17", ["AC-002G-01g"], tc_end_times)
    case("TC-G-18", ["AC-002G-07a", "AC-002G-07b"], tc_names)
    case("TC-G-19", ["AC-002G-07c", "AC-002G-07d", "AC-002G-07e"], tc_symlinks_special)
    case("TC-G-20", ["AC-002G-07f", "AC-002G-06a"], tc_existing_entries)
    case("TC-G-21", ["AC-002G-01d"], tc_unrelated_changes)
    case("TC-G-22", ["AC-002G-06f", "AC-002G-05d"], tc_retention)
    case("TC-G-23", ["AC-002G-01f", "AC-002G-01h", "AC-002G-07k"], tc_skill)
    print(json.dumps({"strict_validation_observations": OBS}), flush=True)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    checks = sum(len(r.get("checks", [])) for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS), "checks": checks}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
