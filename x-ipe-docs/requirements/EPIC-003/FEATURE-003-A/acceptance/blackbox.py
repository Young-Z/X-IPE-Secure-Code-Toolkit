"""Black-box acceptance scenarios for FEATURE-003-A Copilot In-flow Suggestions & Adoption Review.

TASK-046; closing-review additions TASK-048 (01d stale-only record, 02b/02d removed Policy, 03a bug_fix/refactor
stages and `unspecified` folder, 04b/04f extra branches, 05a full Reviewer records, 06a lock file, 06f no report).

Calls the real CLI only: `uvx --from <framework>/scripts secure-code ...`. Never imports toolkit code.
Helpers are copied from the FEATURE-002-A and FEATURE-002-C runners.

  python3 blackbox.py host                         # never-authorized User path (no trust writes)
  FAT_ISOLATED=1 python3 blackbox.py container     # Maintainer-prepared scenarios (disposable HOME only!)

Environment: TOOLKIT_ROOT (toolkit folder), SAMPLES (folder holding `m` = marathon sample), FAT_WORK
(folder for disposable project copies; defaults to the platform temporary folder).

Fixtures (disclosed):
- Container: owner authorization (`auth init` at a pseudo-terminal), `knowledge import` of three Local
  rules (CWE-89, CWE-79, CWE-312, placeholder bodies) and `scope save` with the user's confirmation flag,
  exactly as the FEATURE-002-A container mode prepares Guard scenarios.
- Projects are copies of the marathon sample (`app/`, without `data/` and `__pycache__`).
- The "executor" edits are plain file writes by this runner between Copilot commands.
- Reviewer records are written by this runner in the shape a host Reviewer sub-agent would return
  (invocation is declared, not proven - the honest limit of the toolkit).
- Policy change: the Maintainer updates the CWE-312 rule body with `knowledge update`; restoring it
  is a second `knowledge update` with the original body.
- Maintenance-needed / partial scopes: a rule adopted in a scope is changed by `knowledge update`.
- Removed Policy (02b missing list, 02d removed): the toolkit has no knowledge removal or deactivation
  command, so the runner deletes the rule's folder under `x-ipe-docs/secure-code/knowledge/local/`, standing
  in for the Maintainer removing it - the same fixture the FEATURE-001-C runner uses for removed rules.
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
from datetime import UTC, datetime
from pathlib import Path

_UP = Path(__file__).resolve().parents
WORKSPACE = _UP[5] if len(_UP) > 5 else Path("/")  # inside the container the runner is mounted at /fat
TOOLKIT = Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ else WORKSPACE / "ai-secure-code-toolkit"
SCRIPTS = TOOLKIT / "x-ipe-secure-code-toolkit-framework" / "scripts"
COPILOT_SKILL = TOOLKIT / "x-ipe-secure-code-toolkit-copilot"
CLI_CONTRACT = TOOLKIT / "x-ipe-secure-code-toolkit-framework" / "references" / "cli-contract.md"
if "SAMPLES" in os.environ:
    SAMPLE_M = Path(os.environ["SAMPLES"]) / "m"
elif Path("/samples/m").is_dir():
    SAMPLE_M = Path("/samples/m")
else:
    SAMPLE_M = WORKSPACE / "study-case/secure-coding-guidance/playground/shanghai-marathon-registration"
GUARD = ".x-ipe/private/secure-code/guard"
GREPORTS = "x-ipe-docs/secure-code/reports/guard"
COLLAB = ".x-ipe/private/secure-code/copilot"
LOCKS = ".x-ipe/private/secure-code/locks"
CREPORTS = "x-ipe-docs/secure-code/reports/copilot"
LOCK_FILE = f"{LOCKS}/copilot.lock"  # project-wide Copilot lock file: private data per AC-003A-06a
LOCAL = "x-ipe-docs/secure-code/knowledge/local"
PASS = "acceptance passphrase 42"
R89, R79, R312 = "CWE/4.14/CWE-89", "CWE/4.14/CWE-79", "CWE/4.14/CWE-312"
RULES = (R89, R79, R312)
TOKEN = "ghp_" + "Z" * 36
S_OPEN = "ai-secure-code-toolkit/copilot-open/v1"
S_ART = "ai-secure-code-toolkit/copilot-artifacts/v1"
S_SUG = "ai-secure-code-toolkit/copilot-suggest/v1"
S_REV = "ai-secure-code-toolkit/reviewer-record/v1"
S_RES = "ai-secure-code-toolkit/copilot-result/v1"
CID = re.compile(r"cp-\d{8}T\d{6}Z-[0-9a-f]{8}")
FORBIDDEN_KEYS = {"pass", "passed", "approved", "approval", "verdict", "completed_safely", "safe"}
RESULTS: list[dict] = []
WRITES: list[dict] = []  # one entry per Copilot command: what changed in the project tree


# ---------------------------------------------------------------- CLI helpers (copied)
def sc(*args: str):
    proc = subprocess.run(["uvx", "--from", str(SCRIPTS), "secure-code", *args], capture_output=True,
                          text=True, env=dict(os.environ), stdin=subprocess.DEVNULL, timeout=600)
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
    """Markdown source form of free text in report cells (the report escapes Markdown specials)."""
    return re.sub(r"([\\`*_\[\]<>#|!~])", r"\\\1", text)


def code_of(out: dict | None) -> str | None:
    return out["problems"][0]["code"] if out and out.get("problems") else None


def msg_of(out: dict | None) -> str:
    return out["problems"][0]["message"] if out and out.get("problems") else ""


def step_of(out: dict | None) -> str:
    return " ".join(out.get("next_steps") or []) if out else ""


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


def work_dir(prefix: str) -> Path:
    base = os.environ.get("FAT_WORK")
    if base:
        Path(base).mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base or None))


def jfile(project: Path, doc: dict) -> str:
    path = Path(tempfile.mkstemp(suffix=".json", dir=project.parent)[1])
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def fdig(p: Path, rel: str) -> str:
    f = p / rel
    return "sha256:" + hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() else "absent"


def now_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def keys_of(obj) -> set[str]:
    if isinstance(obj, dict):
        return set(obj) | {k for v in obj.values() for k in keys_of(v)}
    if isinstance(obj, list):
        return {k for v in obj for k in keys_of(v)}
    return set()


# ---------------------------------------------------------------- fixtures (copied/adapted)
def item(rule: str, body: str = "Rule body.\n") -> dict:
    ns, ver, rid = rule.split("/")
    return {"namespace": ns, "version": ver, "rule_id": rid, "content": body,
            "source_location": f"https://example.org/{rid}"}


def new_project(rules=RULES, prefix: str = "fat-ca-") -> Path:
    root = work_dir(prefix) / "proj ü"
    root.mkdir()
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    if rules:
        batch = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": [item(r) for r in rules]}
        code, out, _, _ = sc("knowledge", "import", "--project", str(root), "--batch", jfile(root, batch), "--json")
        assert code == 0, out
    shutil.copytree(SAMPLE_M, root / "app", ignore=shutil.ignore_patterns("__pycache__", "data"))
    return root


def save_scope(p: Path, rules=RULES) -> tuple[str, dict[str, str]]:
    args = ["policy", "resolve", "--project", str(p), "--json"] + [x for r in rules for x in ("--rule", r)]
    code, prop, _, _ = sc(*args)
    assert code == 0, prop
    digests = {e["requested"]: e["source_evidence"]["state_digest"] for e in prop["data"]["entries"]}
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": "clues", "considered": list(rules),
           "proposal_digest": prop["data"]["proposal_digest"], "clues": "registration export change",
           "language_context": ["python", "javascript"], "confirmation_note": "user confirmed",
           "decisions": [{"ref": e["requested"], "decision": "adopted",
                          "state_digest": e["source_evidence"]["state_digest"]} for e in prop["data"]["entries"]]}
    code, out, _, _ = sc("scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed",
                         "--json")
    assert code == 0, out
    return out["data"]["scope_id"], digests


def change_rule(p: Path, rule: str, body: str) -> None:
    """Maintainer knowledge update of one Local rule (the real Policy-change fixture)."""
    code, prop, _, _ = sc("policy", "resolve", "--project", str(p), "--rule", rule, "--json")
    base = prop["data"]["entries"][0]["source_evidence"]["state_digest"]
    upd = {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": body}
    code, out, _, _ = sc("knowledge", "update", "--project", str(p), "--rule", rule, "--base-state", base,
                         "--input", jfile(p, upd), "--json")
    assert code == 0, out


def remove_rule(p: Path, rule: str) -> None:
    """Disclosed fixture: no removal command exists; delete the rule folder (as the FEATURE-001-C runner)."""
    shutil.rmtree(p / LOCAL / rule)


# ---------------------------------------------------------------- Copilot command wrapper (06a probe)
def _copilot_area(path: str) -> bool:
    """Copilot's private data (collaboration folders, the project-wide lock file) or report files (06a)."""
    return path in (LOCKS, LOCK_FILE) or any(path == a or path.startswith(a + "/") for a in (COLLAB, CREPORTS))


def _allowed_inside(path: str, cid: str | None) -> bool:
    if path in (COLLAB, LOCKS, CREPORTS, LOCK_FILE):
        return True
    if cid and (path == f"{COLLAB}/{cid}" or path.startswith(f"{COLLAB}/{cid}/")):
        return True
    return bool(cid and re.fullmatch(re.escape(f"{CREPORTS}/{cid}") + r"-r\d+\.(json|md)", path))


def cp(p: Path, cmd: str, cid: str | None = None, doc: dict | None = None):
    """Run one `secure-code copilot` command; record every project path it changed."""
    args = ["copilot", cmd, "--project", str(p)]
    if cid:
        args += ["--id", cid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    before = tree(p)
    code, out, text, err = sc(*args, "--json")
    after = tree(p)
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    owner = cid or ((out or {}).get("data") or {}).get("collaboration_id")
    outside = [k for k in changed if not _copilot_area(k)]
    inside = [k for k in changed if k not in outside]
    rewritten = [k for k in changed if k.startswith(CREPORTS + "/") and k in before and before[k] != "dir"]
    WRITES.append({"cmd": cmd, "code": code, "cid": owner, "outside": outside, "rewritten_reports": rewritten,
                   "foreign": [k for k in inside if not _allowed_inside(k, owner)], "lock": LOCK_FILE in changed,
                   "stdout": text})
    return code, out, text, err


def rjson(p: Path, cid: str, n: int) -> dict:
    return json.loads((p / CREPORTS / f"{cid}-r{n}.json").read_text(encoding="utf-8"))


def rmd(p: Path, cid: str, n: int) -> str:
    return (p / CREPORTS / f"{cid}-r{n}.md").read_text(encoding="utf-8")


def rbytes(p: Path, cid: str) -> dict[str, bytes]:
    return {f.name: f.read_bytes() for f in sorted((p / CREPORTS).glob(f"{cid}-r*"))}


def cstate(p: Path, cid: str) -> dict:
    return json.loads((p / COLLAB / cid / "state.json").read_text(encoding="utf-8"))


def collab_entries(p: Path) -> list[str]:
    return sorted(x.name for x in (p / COLLAB).iterdir()) if (p / COLLAB).is_dir() else []


def report_entries(p: Path) -> list[str]:
    return sorted(x.name for x in (p / CREPORTS).iterdir()) if (p / CREPORTS).is_dir() else []


def sections(md: str) -> dict[str, str]:
    parts = re.split(r"^## ", md, flags=re.M)
    return {s.split("\n", 1)[0].strip(): s for s in parts[1:]}


def first_cells(section: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"^\| `([^`]+)` \|", section, flags=re.M)]


def mcell(value) -> str:
    """Expected Markdown of agent free text: neutralized, mask markers as code spans (documented format)."""
    if value is None or value == "":
        return "—"
    text = esc(str(value).replace("\r", " ").replace("\n", " "))
    return re.sub(r"\\\[masked:([a-z_.]+)\\\]", r"`[masked:\1]`", text)


def mcode(value) -> str:
    """Expected Markdown of an identifier, path, digest, state or generated text: code span(s), `—` if empty."""
    if value is None or value == "" or value == []:
        return "—"
    if isinstance(value, list):
        return ", ".join(mcode(v) for v in value)
    return "`" + str(value).replace("|", "\\|") + "`"


def mrow(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


REVIEW_KEYS = {"seq", "valid", "reasons", "invocation", "requirement", "reviewed_targets", "reviewed_at", "subjects",
               "masked", "recorded_at", "counted", "not_counted"}


def review_fields(res: dict, rev: str) -> list[tuple[str, bool]]:
    """Every Reviewer-record field of the structured result compared with its Markdown (AC-003A-05a)."""
    lines = rev.splitlines()
    keys = summary = declared = targets = subjects = True
    for r in res["reviews"]:
        inv, seq = r["invocation"], r["seq"]
        keys &= (set(r) == REVIEW_KEYS and set(inv) == {"host", "agent", "read_only", "invoked_at", "declared"}
                 and all(set(s) == {"type", "id", "result", "basis"} for s in r["subjects"]))
        summary &= mrow([str(seq), "yes" if r["valid"] else "no", mcell(inv["host"]), mcell(inv["agent"]),
                         "yes" if inv["read_only"] else "no", mcell(inv["invoked_at"]), mcell(r["reviewed_at"]),
                         mcode(r["recorded_at"]), mcell(r["requirement"]), mcode(r["reasons"]), mcode(r["counted"]),
                         mcode([f"{x['id']}: {x['reason']}" for x in r["not_counted"]]),
                         mcode([f"masked: {m}" for m in r["masked"]])]) in lines
        parts = rev.split(f"\n### Reviewer record {seq}\n", 1)
        block = parts[1].split("\n### ", 1)[0] if len(parts) == 2 else ""
        declared &= ("Invocation declared by the agent, not proven." in block) == bool(inv["declared"])
        tpart, _, spart = block.partition("\nSubjects:\n")
        targets &= [x for x in tpart.splitlines() if x.startswith("| `")] == [
            mrow([mcode(t["path"]), mcode(t["digest"])]) for t in r["reviewed_targets"]]
        subjects &= [x for x in spart.splitlines() if x.startswith("| `")] == [
            mrow([mcode(s["id"]), mcode(s["type"]), mcode(s["result"]), mcell(s["basis"]),
                  mcode([f"masked: {m.removeprefix(f'subjects[{i}].')}" for m in r["masked"]
                         if m.startswith(f"subjects[{i}].")])])
            for i, s in enumerate(r["subjects"])]
    return [
        ("Reviewer records: every JSON field is a rendered field (no unrendered key)", keys),
        ("Reviewer records field by field: seq, validity, host, agent, read-only, invoked, reviewed, recorded, "
         "requirement, reasons, counts for, not counted, masked", summary),
        ("Reviewer records: invocation declared (not proven) stated per record", declared),
        ("Reviewer records: reviewed targets with the digest seen or `absent`, same order", targets),
        ("Reviewer records: subjects with id, type, result, basis and masked labels, same order", subjects),
    ]


def consistent(res: dict, md: str) -> list[tuple[str, bool]]:
    """Field-by-field comparison of one structured result with its Markdown (AC-003A-05a)."""
    sec = sections(md)
    sug_s, rev, art, pol = (sec.get(k, "") for k in ("Suggestions", "Reviewer Records", "Artifacts",
                                                      "Adopted Policies"))
    return [
        ("same suggestions with state, severity, Policy",
         all(f"| `{s['id']}` | `{s['state']}` | `{s['severity']}` | `{s['rule']}` |" in sug_s
             for s in res["suggestions"])
         and len(first_cells(sug_s.split("Earlier results")[0])) == len(res["suggestions"])),
        ("same Reviewer basis per suggestion",
         all(s["basis"] is None or mcell(s["basis"]) in sug_s for s in res["suggestions"])),
        ("same attention list (order)", first_cells(sec.get("Attention", "")) == [a["id"] for a in res["attention"]]),
        ("same gaps (order)", first_cells(sec.get("Gaps", "")) == [g["id"] for g in res["gaps"]]),
        ("same Reviewer records with validity",
         all(f"| {r['seq']} | {'yes' if r['valid'] else 'no'} |" in rev for r in res["reviews"])
         and len(re.findall(r"^\| \d+ \|", rev, flags=re.M)) == len(res["reviews"])),
        ("same artifacts and manifest digests",
         all(f"| `{m['path']}` | `{m['change']}` |" in art
             and (m["recorded_digest"] is None or m["recorded_digest"] in art)
             and (m["current_digest"] is None or m["current_digest"] in art) for m in res["manifest"])
         and all(f"| `{a['path']}` | `{a['kind']}` | `{a['change']}` |" in art for a in res["artifacts"])),
        ("same adopted Policies with digests and now",
         all(f"| `{a['rule']}` | `{a['state_digest']}` | `{a['now']}` |" in pol for a in res["scope"]["adopted"])),
        ("same stage, task, scope id and round", f"Stage: `{res['stage']}`" in md and mcell(res["task"]) in md
         and f"`{res['scope']['scope_id']}`" in md and f"— round {res['round']}" in md),
    ] + review_fields(res, rev)


def footer_ok(p: Path, cid: str, n: int) -> bool:
    js = (p / CREPORTS / f"{cid}-r{n}.json").read_bytes()
    return rmd(p, cid, n).rstrip().endswith(f"<!-- copilot-result-sha256: {hashlib.sha256(js).hexdigest()} -->")


def no_pass_keys(res: dict) -> bool:
    return not (keys_of(res) & FORBIDDEN_KEYS)


def states(res: dict) -> dict[str, str]:
    return {s["id"]: s["state"] for s in res["suggestions"]}


def by_id(res: dict, sid: str) -> dict:
    return next(s for s in res["suggestions"] if s["id"] == sid)


def odoc(scope: str | None, artifacts: list, **over) -> dict:
    doc = {"schema": S_OPEN, "scope_id": scope, "stage": "implementation",
           "task": "Add a CSV export of marathon registrations for the organiser", "artifacts": artifacts}
    if scope is None:
        doc.pop("scope_id")
    doc.update(over)
    return doc


def sug(sid: str, rule: str, files: list[str], severity: str | None = "high", **over) -> dict:
    s = {"id": sid, "rule": rule, "files": files, "location": f"location of {sid}",
         "action": f"concrete action for {sid}", "reason": f"reason for {sid}"}
    if severity is not None:
        s["severity"] = severity
    s.update(over)
    return s


def batch(*items: dict) -> dict:
    return {"schema": S_SUG, "suggestions": list(items)}


def subj(sid: str, result: str | None, basis: str | None) -> dict:
    s = {"type": "adoption", "id": sid}
    if result is not None:
        s["result"] = result
    if basis is not None:
        s["basis"] = basis
    return s


def rdoc(p: Path, subjects: list, paths: list[str], digests: dict | None = None, **over) -> dict:
    doc = {"schema": S_REV,
           "invocation": {"host": "github-copilot", "agent": "copilot-reviewer", "read_only": True,
                          "invoked_at": now_z()},
           "requirement": "Check in the formed artifact whether the listed suggestions were adopted",
           "reviewed_targets": [{"path": x, "digest": (digests or {}).get(x) or fdig(p, x)} for x in paths],
           "subjects": subjects, "reviewed_at": now_z()}
    doc.update(over)
    return doc


# ---------------------------------------------------------------- scenario bookkeeping
CHK: dict[str, list[tuple[str, bool]]] = {}
ERR: dict[str, str] = {}
MAIN: dict = {}


def chk(tc: str, name: str, ok) -> None:
    CHK.setdefault(tc, []).append((name, bool(ok)))


def stage(name: str, fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - recorded and reported by every dependent test case
        ERR[name] = f"{type(exc).__name__}: {exc}"
        print(json.dumps({"stage_error": name, "error": ERR[name]}), file=sys.stderr, flush=True)


def tc_from(tc: str, *deps: str):
    def fn():
        checks = list(CHK.get(tc, []))
        checks += [(f"stage {d} completed ({ERR.get(d, 'ok')})", d not in ERR) for d in deps]
        return checks if CHK.get(tc) else checks + [("checks recorded", False)]
    return fn


EXPORT_V1 = ('import sqlite3\n\n\ndef export_rows(db_path, status):\n    with sqlite3.connect(db_path) as c:\n'
             '        return c.execute(f"SELECT name, city FROM registrations WHERE status = \'{status}\'")'
             '.fetchall()\n')
EXPORT_V2 = ('import sqlite3\n\n\ndef export_rows(db_path, status):\n    with sqlite3.connect(db_path) as c:\n'
             '        return c.execute("SELECT name, city FROM registrations WHERE status = ?", (status,)).fetchall()\n')
BASIS = {
    "S1": "registration.py create() binds every value with ? placeholders",
    "S2": "app.js renderSummary has no change for the summary list yet",
    "S3": "the key file permissions are set at run time and cannot be seen in the files",
    "S4": "index.html sets default-src but no script-src in the policy meta tag",
    "S5": "export.py export_rows uses a constant SELECT with a bound parameter",
    "S2b": "app.js renders the summary with textContent only",
    "S3b": "server.py was removed so the key is no longer loaded by the server",
    "S5b": "export.py was renamed and the query moved to exporter.py",
    "S6": "exporter.py export_rows binds the status parameter",
}
REVIEWED_1 = ["app/registration.py", "app/public/app.js", "app/server.py", "app/public/index.html", "app/export.py"]


# ---------------------------------------------------------------- main outcome scenario (marathon copy)
def main_open() -> None:
    p = new_project()
    MAIN["p"] = p
    scope, dig = save_scope(p)
    MAIN["scope"], MAIN["dig"] = scope, dig
    app = p / "app"
    (app / "export.py").write_text(EXPORT_V1)  # the executor's change before Copilot opens
    (app / "tests/test_portal_contract.py").unlink()
    (app / "tests/test_server.py").rename(app / "tests/test_http_server.py")
    os.symlink("app.js", app / "public/app-link.js")
    arts = [{"path": "app/registration.py", "change": "modified"}, {"path": "app/server.py", "change": "modified"},
            {"path": "app/export.py", "change": "added"},
            {"path": "app/tests/test_portal_contract.py", "change": "deleted"},
            {"path": "app/tests/test_http_server.py", "change": "renamed", "old_path": "app/tests/test_server.py"},
            {"path": "app/.gitignore"}, {"path": "app/public", "change": "modified"}]
    files = ["app/registration.py", "app/server.py", "app/export.py", "app/tests/test_http_server.py",
             "app/.gitignore"] + [f"app/public/{n}" for n in ("index.html", "styles.css", "shanghai-runners.jpg",
                                                                 "app.js")]
    expected = {f: fdig(p, f) for f in files} | {"app/tests/test_portal_contract.py": None,
                                                 "app/tests/test_server.py": None}
    MAIN["open_digests"] = dict(expected)
    code, out, _, err = cp(p, "open", doc=odoc(scope, arts, context=[{"path": "app/tests/test_registration.py"}]))
    assert code == 0, (out, err)
    cid = out["data"]["collaboration_id"]
    MAIN["cid"] = cid
    st = cstate(p, cid)
    man = st["manifest"]
    chk("TC1", "03a opened: collaboration id, stage and task recorded", code == 0 and CID.fullmatch(cid)
        and st["stage"] == out["data"]["stage"] == "implementation"
        and st["task"] == "Add a CSV export of marathon registrations for the organiser")
    chk("TC1", "02c adopted scope id recorded", st["scope"]["scope_id"] == out["data"]["scope_id"] == scope)
    chk("TC1", "02c every adopted rule recorded with its confirmed state digest",
        {a["rule"]: a["state_digest"] for a in st["scope"]["adopted"]} == dig
        and sorted(out["data"]["adopted_rules"]) == sorted(RULES))
    chk("TC1", "03a artifacts with change meaning (added/modified/deleted/renamed+old path/unspecified, folder)",
        [(a["path"], a["kind"], a["change"], a["old_path"]) for a in st["artifacts"]] == [
            ("app/registration.py", "file", "modified", None), ("app/server.py", "file", "modified", None),
            ("app/export.py", "file", "added", None), ("app/tests/test_portal_contract.py", "file", "deleted", None),
            ("app/tests/test_http_server.py", "file", "renamed", "app/tests/test_server.py"),
            ("app/.gitignore", "file", "unspecified", None), ("app/public", "dir", "modified", None)])
    chk("TC1", "03a per-file manifest: every artifact file and every regular file of the folder with its digest",
        out["data"]["manifest"] == expected and {k: v["digest"] for k, v in man.items()} == expected)
    chk("TC1", "03a deleted artifact without digest; renamed old path recorded renamed_away",
        man["app/tests/test_portal_contract.py"]["change"] == "deleted"
        and man["app/tests/test_server.py"]["change"] == "renamed_away"
        and man["app/tests/test_http_server.py"]["old_path"] == "app/tests/test_server.py"
        and man["app/public/app.js"]["change"] == "modified" and man["app/public/app.js"]["source"] == "app/public")
    chk("TC1", "03a/03c symbolic link inside the folder listed not bindable, not a manifest member",
        any(n["path"] == "app/public/app-link.js" for n in out["data"]["not_bindable"])
        and "app/public/app-link.js" not in man)
    chk("TC1", "read-only context recorded, not a manifest member",
        out["data"]["context"] == ["app/tests/test_registration.py"] and "app/tests/test_registration.py" not in man)


def main_suggest() -> None:
    p, cid = MAIN["p"], MAIN["cid"]
    s1 = sug("S1", R89, ["app/registration.py"], location="RegistrationStore.create(), INSERT statement",
             action="Keep the INSERT parameterized with placeholders; never format request values into SQL",
             reason="Registration fields come from the HTTP request")
    bad = {
        "rule outside the adopted scope": (sug("X1", "CWE/4.14/CWE-22", ["app/registration.py"]), "adopted scope"),
        "no bound file": (sug("X1", R89, []), "files must not be empty"),
        "bound file not a manifest member": (sug("X1", R89, ["app/tests/test_registration.py"]), "manifest member"),
        "empty location": (sug("X1", R89, ["app/registration.py"], location=""), "location is required"),
        "empty action": (sug("X1", R89, ["app/registration.py"], action="   "), "action is required"),
        "ID used twice": (sug("S1", R79, ["app/public/app.js"]), "already used"),
    }
    for name, (item_, word) in bad.items():
        c, o, _, _ = cp(p, "suggest", cid, batch(s1, item_))
        chk("TC2", f"03e {name}: whole batch refused with the reason, nothing stored",
            c == 1 and code_of(o) == "SUGGESTION_INVALID" and word in msg_of(o) and step_of(o)
            and cstate(p, cid)["suggestions"] == [])
    items = [
        s1,
        sug("S2", R79, ["app/public/app.js"], location="renderSummary(), summary list",
            action="Render every registration value with textContent, never innerHTML",
            reason="Runner names are echoed back in the page"),
        sug("S3", R312, ["app/registration.py", "app/server.py"], "critical",
            location="RegistrationStore key file and server start-up",
            action="Keep the HMAC key outside the web root with owner-only permissions",
            reason="The key protects stored ID numbers"),
        sug("S4", R79, ["app/public/index.html"], "medium", location="registration form page",
            action="Add a Content-Security-Policy meta tag with script-src self", reason="Limits injection impact"),
        sug("S5", R89, ["app/export.py"], None, location="export_rows()",
            action="Query registrations with a constant SQL text and bound parameters",
            reason="The export filter comes from the organiser request"),
    ]
    c, o, _, err = cp(p, "suggest", cid, batch(*items))
    assert c == 0, (o, err)
    stored = cstate(p, cid)["suggestions"]
    chk("TC2", "03d batch stored: id, one adopted rule, manifest files, location, action, reason, severity, stage",
        o["data"]["recorded"] == ["S1", "S2", "S3", "S4", "S5"]
        and [(s["id"], s["rule"], s["files"], s["location"], s["action"], s["reason"]) for s in stored]
        == [(i["id"], i["rule"], i["files"], i["location"], i["action"], i["reason"]) for i in items]
        and [s["severity"] for s in stored[:4]] == ["high", "high", "critical", "medium"]
        and all(s["stage"] == "implementation" for s in stored))
    chk("TC2", "03f suggestion without severity stored as unknown, never low", stored[4]["severity"] == "unknown")
    c, o, _, _ = cp(p, "report", cid)
    MAIN["r1"] = o
    res = rjson(p, cid, 1)
    chk("TC5", "05a/05c round r1 published as a snapshot before review (both files)",
        c == 0 and o["data"]["round"] == 1 and o["data"]["published"] is True and o["data"]["report_exists"]
        and o["data"]["result_exists"] and res["snapshot_before_review"] is True
        and "snapshot before review" in rmd(p, cid, 1) and o["data"]["supersedes"] is None)
    chk("TC5", "04e never-reviewed suggestions are not_reviewed and never counted as adopted",
        set(states(res).values()) == {"not_reviewed"} and res["counts"]["adopted"] == 0)
    chk("TC5", "04i r1 attention = high/critical/unknown not_reviewed (critical, high, unknown order); gap = medium",
        [a["id"] for a in res["attention"]] == ["S3", "S1", "S2", "S5"] and [g["id"] for g in res["gaps"]] == ["S4"]
        and all(a["reason"] == "no valid review covers it" for a in res["attention"]))
    MAIN["r1_bytes"] = rbytes(p, cid)


def main_review() -> None:
    p, cid = MAIN["p"], MAIN["cid"]
    app = p / "app"
    # the executor applies S1 (comment in registration.py) and S5 (parameterized export); S2 untouched
    with (app / "registration.py").open("a", encoding="utf-8") as fh:
        fh.write("\n# Registrations are written with parameterized SQL only.\n")
    (app / "export.py").write_text(EXPORT_V2)
    one = [subj("S1", "adopted", BASIS["S1"])]
    for key, value in (("suggestions", []), ("artifacts", []), ("scope", {}), ("stage", "design"),
                       ("manifest", {})):
        c, o, _, _ = cp(p, "review", cid, rdoc(p, one, ["app/registration.py"], **{key: value}))
        chk("TC4", f"04d Reviewer record with `{key}` refused (no extra authority), nothing stored",
            c == 1 and code_of(o) == "REVIEW_AUTHORITY" and cstate(p, cid)["reviews"] == [])
    c, o, _, _ = cp(p, "review", cid, rdoc(p, one, ["app/registration.py"], attempt="a-1-00000000"))
    chk("TC4", "04a no attempt field for Copilot (refused), nothing stored",
        c == 1 and code_of(o) == "REVIEW_INVALID" and cstate(p, cid)["reviews"] == [])
    for name, subjects, paths, word in (
            ("adopted without basis", [subj("S1", "adopted", None)], ["app/registration.py"], "basis"),
            ("not_adopted without basis", [subj("S2", "not_adopted", None)], ["app/public/app.js"], "basis"),
            ("partial without basis", [subj("S4", "partial", None)], ["app/public/index.html"], "basis"),
            ("not_applicable without basis", [subj("S5", "not_applicable", None)], ["app/export.py"], "basis"),
            ("cannot_verify without basis", [subj("S3", "cannot_verify", None)],
             ["app/registration.py", "app/server.py"], "basis"),
            ("unknown suggestion", [subj("S9", "adopted", "x")], ["app/registration.py"], "unknown suggestion")):
        c, o, _, _ = cp(p, "review", cid, rdoc(p, subjects, paths))
        chk("TC4", f"04b subject {name}: record refused, nothing stored",
            c == 1 and code_of(o) == "REVIEW_INVALID" and word in msg_of(o) and cstate(p, cid)["reviews"] == [])
    c, o, _, _ = cp(p, "review", cid, rdoc(p, [subj("S3", "cannot_verify", BASIS["S3"])], ["app/registration.py"]))
    chk("TC4", "04c digest list missing a bound file of a covered suggestion: whole record refused",
        c == 1 and code_of(o) == "REVIEW_INVALID" and "app/server.py" in msg_of(o)
        and cstate(p, cid)["reviews"] == [])
    s4 = [subj("S4", "partial", BASIS["S4"])]
    idx = ["app/public/index.html"]
    inv = {"host": "github-copilot", "agent": "copilot-reviewer", "read_only": True, "invoked_at": now_z()}
    incomplete = [
        ("invocation time missing", {"invocation": {k: v for k, v in inv.items() if k != "invoked_at"}},
         "invocation.invoked_at is missing"),
        ("invocation source missing", {"invocation": {"read_only": True, "invoked_at": now_z()}},
         "invocation.host is missing"),
        ("read-only not declared", {"invocation": {**inv, "read_only": False}}, "invocation.read_only is not true"),
        ("review requirement missing", {"requirement": None}, "requirement is missing"),
        ("reviewed-digest list missing as a whole", {"reviewed_targets": None}, "reviewed_targets is missing"),
        ("result missing", {"subjects": [subj("S4", None, BASIS["S4"])]}, "subjects[0].result is missing"),
    ]
    for n, (name, over, reason) in enumerate(incomplete, start=1):
        doc = rdoc(p, s4, idx)
        doc.update(over)
        doc = {k: v for k, v in doc.items() if v is not None}
        c, o, _, _ = cp(p, "review", cid, doc)
        chk("TC4", f"04f {name}: record kept (seq {n}) but not valid, with the reason",
            c == 0 and o["data"]["seq"] == n and o["data"]["valid"] is False and reason in o["data"]["completeness"]
            and len(cstate(p, cid)["reviews"]) == n)
    MAIN["incomplete"] = incomplete
    old = MAIN["open_digests"]["app/registration.py"]
    c, o, _, _ = cp(p, "review", cid, rdoc(p, one, ["app/registration.py"], {"app/registration.py": old}))
    chk("TC4", "04h record bound to an older version is kept, marked wrong version, not valid",
        c == 0 and o["data"]["seq"] == 7 and o["data"]["wrong_version"] == ["app/registration.py"]
        and o["data"]["valid"] is False and "wrong version" in step_of(o))
    subjects = [subj("S1", "adopted", BASIS["S1"]), subj("S2", "not_adopted", BASIS["S2"]),
                subj("S3", "cannot_verify", BASIS["S3"]), subj("S4", "partial", BASIS["S4"]),
                subj("S5", "adopted", BASIS["S5"])]
    c, o, _, err = cp(p, "review", cid, rdoc(p, subjects, REVIEWED_1))
    assert c == 0, (o, err)
    rec = cstate(p, cid)["reviews"][-1]
    chk("TC4", "04a shared reviewer-record/v1 stored: invocation (host, agent, read-only, time), requirement, "
        "reviewed digests, adoption subjects with result and basis",
        o["data"]["valid"] is True and o["data"]["seq"] == 8 and o["data"]["covers"] == ["S1", "S2", "S3", "S4", "S5"]
        and rec["invocation"]["host"] == "github-copilot" and rec["invocation"]["agent"] == "copilot-reviewer"
        and rec["invocation"]["read_only"] is True and rec["invocation"]["invoked_at"]
        and rec["requirement"] and [t["path"] for t in rec["reviewed_targets"]] == REVIEWED_1
        and all(t["digest"] == fdig(p, t["path"]) for t in rec["reviewed_targets"])
        and [(s["type"], s["id"], s["result"], s["basis"]) for s in rec["subjects"]]
        == [("adoption", s["id"], s["result"], s["basis"]) for s in subjects])
    c, o, _, _ = cp(p, "report", cid)
    res, md = rjson(p, cid, 2), rmd(p, cid, 2)
    MAIN["r2"] = o
    rows = {r["seq"]: r for r in res["reviews"]}
    rev_md = sections(md).get("Reviewer Records", "")
    chk("TC4", "04f report says why each incomplete record is not a valid review (JSON and Markdown)",
        all(rows[n]["valid"] is False and reason in rows[n]["reasons"] and f"| {n} | no |" in rev_md
            and f"`{reason}`" in rev_md for n, (_, _, reason) in enumerate(incomplete, start=1)))
    chk("TC4", "04h report says the wrong-version record does not count for S1",
        rows[7]["valid"] is False and rows[7]["reasons"] == ["wrong version: app/registration.py"]
        and {"id": "S1", "reason": "wrong version of app/registration.py"} in rows[7]["not_counted"]
        and "S1: wrong version of app/registration.py" in rev_md and rows[7]["counted"] == [])
    chk("TC4", "04a the valid record counts for all five suggestions", rows[8]["valid"] is True
        and rows[8]["counted"] == ["S1", "S2", "S3", "S4", "S5"] and "| 8 | yes |" in rev_md)
    want = {"S1": "adopted", "S2": "not_adopted", "S3": "cannot_verify", "S4": "partial", "S5": "adopted"}
    chk("TC5", "outcome: r2 distinguishes adopted / not adopted / cannot verify / partial bound to current digests",
        c == 0 and o["data"]["round"] == 2 and o["data"]["published"] and states(res) == want
        and all(by_id(res, s)["review_seq"] == 8 and by_id(res, s)["basis"] == BASIS[s] for s in want)
        and res["snapshot_before_review"] is False)
    chk("TC5", "04i r2 attention = critical cannot_verify S3, high not_adopted S2 with reasons; gap = partial S4; "
        "adopted S1/S5 in neither",
        [(a["id"], a["state"], a["reason"]) for a in res["attention"]]
        == [("S3", "cannot_verify", f"Reviewer: {BASIS['S3']}"), ("S2", "not_adopted", f"Reviewer: {BASIS['S2']}")]
        and [(g["id"], g["state"]) for g in res["gaps"]] == [("S4", "partial")]
        and [a["id"] for a in o["data"]["attention"]] == ["S3", "S2"] and [g["id"] for g in o["data"]["gaps"]] == ["S4"])
    chk("TC5", "05c r2 states id/round, stage, task, artifacts with digests, scope and rules, every suggestion "
        "state with Reviewer basis, attention and gaps",
        f"Copilot Adoption Report {MAIN['cid']} — round 2" in md and "## Attention" in md and "## Gaps" in md
        and all(m["current_digest"] in md for m in res["manifest"] if m["current_digest"])
        and all(f"`{r}`" in md for r in RULES) and all(esc(BASIS[s]) in md for s in want))
    chk("TC5", "05d r2 boundary statements (not pass/approval/verification; review not a guarantee; not Guard) in "
        "both outputs; no design statement for implementation stage",
        all(b in res["boundaries"] for b in (
            "This report is not a pass, approval or security verification; Copilot gives no verdict.",
            "The independent review reduces self-confirmation bias but is not a correctness guarantee."))
        and any("does not replace Guard verification" in b for b in res["boundaries"])
        and all(esc(b) in md for b in res["boundaries"]) and not any("design" in b for b in res["boundaries"]))
    chk("TC5", "05e structured result has suggestions, states, attention and gaps and no pass/approved/verdict key",
        res["schema"] == S_RES and {"suggestions", "attention", "gaps", "counts"} <= set(res)
        and all("state" in s for s in res["suggestions"]) and no_pass_keys(res) and no_pass_keys(o))
    chk("TC6", "05b r1 byte-identical after r2; r2 is the next number and states it supersedes r1",
        {k: v for k, v in rbytes(p, cid).items() if "-r1." in k} == MAIN["r1_bytes"]
        and res["supersedes"] == f"{cid}-r1" and f"This round supersedes {cid}-r1" in md)
    # no change -> same pair; the removed Markdown is re-rendered from the same result identically
    before = rbytes(p, cid)
    c1, o1, _, _ = cp(p, "report", cid)
    (p / CREPORTS / f"{cid}-r2.md").unlink()
    c2, o2, _, _ = cp(p, "report", cid)
    chk("TC8", "05f unchanged state: no new round, the existing latest pair is returned",
        c1 == 0 and o1["data"]["round"] == 2 and o1["data"]["published"] is False and rbytes(p, cid) == before
        and o1["data"]["report"] == f"{CREPORTS}/{cid}-r2.md")
    chk("TC8", "05f same structured result rendered twice gives the identical Markdown",
        c2 == 0 and o2["data"]["published"] is False and rbytes(p, cid) == before)
    c, o, _, _ = cp(p, "show", cid)
    MAIN["show0"] = o
    chk("TC8", "05g show: private data present and each report exists",
        c == 0 and o["data"]["private_data_present"] is True and o["data"]["latest_round"] == 2
        and [(r["round"], r["json_exists"], r["md_exists"]) for r in o["data"]["reports"]]
        == [(1, True, True), (2, True, True)] and o["data"]["report_current"] is True)


def main_changes() -> None:
    p, cid = MAIN["p"], MAIN["cid"]
    app = p / "app"
    want2 = {"S1": "adopted", "S2": "not_adopted", "S3": "cannot_verify", "S4": "partial", "S5": "adopted"}
    # unrelated edits: an unbound member of the folder artifact and a read-only context file
    with (app / "public/styles.css").open("a", encoding="utf-8") as fh:
        fh.write("\n/* organiser export button */\n")
    with (app / "tests/test_registration.py").open("a", encoding="utf-8") as fh:
        fh.write("\n# export covered elsewhere\n")
    c, o, _, _ = cp(p, "show", cid)
    shown = {s["id"]: s["state"] for s in o["data"]["suggestions"]}
    c3, o3, _, _ = cp(p, "report", cid)
    r3 = rjson(p, cid, 3)
    chk("TC6", "01a unrelated edit: every suggestion keeps its reviewed result as current, no re-review requested",
        c == 0 and shown == want2 and o["data"]["re_review"] == [] and c3 == 0 and o3["data"]["round"] == 3
        and states(r3) == want2 and all(by_id(r3, s)["review_seq"] == 8 for s in want2)
        and r3["re_review"] == [] and o3["data"]["re_review"] == []
        and not any("re-review" in s for s in o3["next_steps"]))
    # relevant edits by the executor: S2's file changes, S3's server.py deleted, S5's export.py renamed away
    with (app / "public/app.js").open("a", encoding="utf-8") as fh:
        fh.write("\n// summary rendered with textContent only\n")
    (app / "server.py").unlink()
    (app / "export.py").rename(app / "exporter.py")
    (app / "audit.py").write_text("def audit(event):\n    return {'event': event}\n")
    (app / "public/new.js").write_text("export const x = 1;\n")
    c, o, _, _ = cp(p, "show", cid)
    before = {s["id"]: s for s in o["data"]["suggestions"]}
    chk("TC6", "01b bound file modified/deleted/gone: only those suggestions stale, file and change named",
        c == 0 and {k: v["state"] for k, v in before.items()}
        == {"S1": "adopted", "S2": "stale", "S3": "stale", "S4": "partial", "S5": "stale"}
        and before["S2"]["changed"] == [{"path": "app/public/app.js", "change": "modified"}]
        and before["S3"]["changed"] == [{"path": "app/server.py", "change": "deleted"}]
        and before["S5"]["changed"] == [{"path": "app/export.py", "change": "deleted"}])
    chk("TC6", "01c show lists the stale suggestions as needing re-review and not the current ones",
        o["data"]["re_review"] == ["S2", "S3", "S5"] and "S2, S3, S5" in step_of(o))
    c, o, _, _ = cp(p, "suggest", cid, batch(sug("X2", R79, ["app/public/new.js"])))
    chk("TC6", "03i a new file inside the folder is not bindable until recorded by an artifact update",
        c == 1 and code_of(o) == "SUGGESTION_INVALID" and "manifest member" in msg_of(o))
    upd = {"schema": S_ART, "artifacts": [
        {"path": "app/exporter.py", "change": "renamed", "old_path": "app/export.py"},
        {"path": "app/server.py", "change": "deleted"}, {"path": "app/audit.py", "change": "added"},
        {"path": "app/public/app.js", "change": "modified"}]}
    c, o, _, err = cp(p, "artifacts", cid, upd)
    assert c == 0, (o, err)
    man = cstate(p, cid)["manifest"]
    chk("TC6", "03i update records each change with its meaning and the digest at the update (none for deleted)",
        o["data"]["recorded"] == ["app/exporter.py", "app/server.py", "app/audit.py", "app/public/app.js"]
        and man["app/exporter.py"]["digest"] == fdig(p, "app/exporter.py")
        and man["app/exporter.py"]["old_path"] == "app/export.py"
        and (man["app/export.py"]["change"], man["app/export.py"]["digest"]) == ("renamed_away", None)
        and (man["app/server.py"]["change"], man["app/server.py"]["digest"]) == ("deleted", None)
        and (man["app/audit.py"]["change"], man["app/audit.py"]["digest"]) == ("added", fdig(p, "app/audit.py"))
        and man["app/public/app.js"]["digest"] == fdig(p, "app/public/app.js")
        and "app/public/new.js" not in man)
    c, o, _, _ = cp(p, "show", cid)
    after = {s["id"]: s for s in o["data"]["suggestions"]}
    chk("TC6", "03i the update itself changes no suggestion state; renamed-away path named",
        {k: v["state"] for k, v in after.items()} == {k: v["state"] for k, v in before.items()}
        and after["S5"]["changed"] == [{"path": "app/export.py", "change": "renamed_away"}]
        and after["S3"]["changed"] == [{"path": "app/server.py", "change": "deleted"}])
    c, o, _, _ = cp(p, "suggest", cid, batch(sug("S1", R89, ["app/exporter.py"])))
    chk("TC2", "03e ID already used in the collaboration: batch refused, nothing stored",
        c == 1 and code_of(o) == "SUGGESTION_INVALID" and "already used" in msg_of(o)
        and len(cstate(p, cid)["suggestions"]) == 5)
    c, o, _, _ = cp(p, "suggest", cid, batch(
        sug("S6", R89, ["app/exporter.py"], location="exporter.py export_rows()",
            action="Keep the status filter as a bound parameter after the rename", reason="Same organiser input"),
        sug("S7", R312, ["app/audit.py"], "low", location="audit()",
            action="Never write ID numbers into the audit event", reason="Audit logs are widely readable")))
    chk("TC6", "03i added and renamed files are bindable (new suggestions S6, S7 recorded)",
        c == 0 and o["data"]["recorded"] == ["S6", "S7"] and o["data"]["batch"] == 2)
    c, o, _, _ = cp(p, "report", cid)
    r4, md4 = rjson(p, cid, 4), rmd(p, cid, 4)
    MAIN["r4"] = o
    s2 = by_id(r4, "S2")
    chk("TC6", "01b r4: stale S2 names the file and change; its earlier result is history, not current adoption",
        c == 0 and o["data"]["round"] == 4 and states(r4) == {
            "S1": "adopted", "S2": "stale", "S3": "stale", "S4": "partial", "S5": "stale", "S6": "not_reviewed",
            "S7": "not_reviewed"}
        and s2["changed"] == [{"path": "app/public/app.js", "change": "modified"}] and s2["basis"] is None
        and s2["history"] == [{"seq": 8, "result": "not_adopted", "basis": BASIS["S2"]}]
        and by_id(r4, "S5")["changed"] == [{"path": "app/export.py", "change": "renamed_away"}]
        and r4["counts"]["adopted"] == 1
        and "Earlier results (history, not current adoption)" in md4
        and f"History of `S2`: review 8 `not_adopted` — {esc(BASIS['S2'])}" in md4)
    chk("TC6", "03i stale suggestions bound to deleted / renamed-away paths name that path at the next report",
        by_id(r4, "S3")["changed"] == [{"path": "app/server.py", "change": "deleted"}]
        and "`app/export.py (renamed_away)`" in md4 and "`app/server.py (deleted)`" in md4)
    row8 = next(r for r in r4["reviews"] if r["seq"] == 8)
    chk("TC6", "04g the review bound to older digests does not count for the stale suggestions; report says so",
        {"id": "S2", "reason": "stale: app/public/app.js modified since the review"} in row8["not_counted"]
        and "S2" not in row8["counted"] and row8["counted"] == ["S1", "S4"]
        and "S2: stale: app/public/app.js modified since the review" in sections(md4)["Reviewer Records"])
    chk("TC5", "04i r4 attention covers stale and not_reviewed high-risk; low not_reviewed and partial are gaps",
        [(a["id"], a["state"]) for a in r4["attention"]]
        == [("S3", "stale"), ("S2", "stale"), ("S6", "not_reviewed"), ("S5", "stale")]
        and [(g["id"], g["state"]) for g in r4["gaps"]] == [("S4", "partial"), ("S7", "not_reviewed")])
    c, o, _, _ = cp(p, "show", cid)
    chk("TC6", "01c show after new suggestions: stale and new suggestions need re-review, current ones do not",
        o["data"]["re_review"] == ["S2", "S3", "S5", "S6", "S7"])
    # targeted re-review: only S2, S3, S5 (stale) and S6 (new); deleted / renamed-away files as absent
    subjects = [subj("S2", "adopted", BASIS["S2b"]), subj("S3", "not_applicable", BASIS["S3b"]),
                subj("S5", "not_applicable", BASIS["S5b"]), subj("S6", "adopted", BASIS["S6"])]
    paths = ["app/public/app.js", "app/registration.py", "app/server.py", "app/export.py", "app/exporter.py"]
    c, o, _, err = cp(p, "review", cid, rdoc(p, subjects, paths))
    rec = cstate(p, cid)["reviews"][-1]
    chk("TC6", "01d targeted record covers only stale and new suggestions; deleted/renamed-away files `absent`",
        c == 0 and o["data"]["valid"] is True and o["data"]["seq"] == 9
        and o["data"]["covers"] == ["S2", "S3", "S5", "S6"]
        and {t["path"]: t["digest"] for t in rec["reviewed_targets"]}["app/server.py"] == "absent"
        and {t["path"]: t["digest"] for t in rec["reviewed_targets"]}["app/export.py"] == "absent")
    c, o, _, _ = cp(p, "report", cid)
    r5, md5 = rjson(p, cid, 5), rmd(p, cid, 5)
    MAIN["r5"] = o
    chk("TC6", "01d r5: re-reviewed suggestions show the new results; S1/S4 keep their earlier current results",
        c == 0 and o["data"]["round"] == 5 and states(r5) == {
            "S1": "adopted", "S2": "adopted", "S3": "not_applicable", "S4": "partial", "S5": "not_applicable",
            "S6": "adopted", "S7": "not_reviewed"}
        and [by_id(r5, s)["review_seq"] for s in ("S1", "S4", "S2", "S3", "S5", "S6")] == [8, 8, 9, 9, 9, 9]
        and by_id(r5, "S1")["basis"] == BASIS["S1"] and by_id(r5, "S2")["basis"] == BASIS["S2b"]
        and by_id(r5, "S2")["history"] == [{"seq": 8, "result": "not_adopted", "basis": BASIS["S2"]}])
    chk("TC5", "04i r5 only adopted / not_applicable in neither list; medium partial and low not_reviewed gaps",
        r5["attention"] == [] and [g["id"] for g in r5["gaps"]] == ["S4", "S7"])
    chk("TC6", "05b r1…r4 byte-identical after r5; r5 supersedes r4",
        all(rbytes(p, cid)[k] == v for k, v in MAIN["r1_bytes"].items())
        and r5["supersedes"] == f"{cid}-r4" and f"This round supersedes {cid}-r4" in md5)
    MAIN["r5_bytes"] = rbytes(p, cid)


def main_policy_and_close() -> None:
    p, cid = MAIN["p"], MAIN["cid"]
    change_rule(p, R312, "Changed body: keep keys in a secrets manager.\n")  # Maintainer knowledge update
    c, o, _, _ = cp(p, "report", cid)
    n6 = o["data"]["round"]
    r6, md6 = rjson(p, cid, n6), rmd(p, cid, n6)
    s3, s7 = by_id(r6, "S3"), by_id(r6, "S7")
    chk("TC7", "02d Policy changed after opening: every suggestion of that rule is policy_changed, earlier "
        "result kept as history",
        c == 0 and o["data"]["published"] and s3["state"] == "policy_changed" and s7["state"] == "policy_changed"
        and s3["basis"] is None and {"seq": 9, "result": "not_applicable", "basis": BASIS["S3b"]} in s3["history"]
        and {a["rule"]: a["now"] for a in r6["scope"]["adopted"]}[R312] == "changed"
        and R312 in r6["scope"]["invalidated"])
    chk("TC7", "02d not counted as current adoption; attention (critical S3) and gap (low S7)",
        r6["counts"]["policy_changed"] == 2 and r6["counts"]["not_applicable"] == 1
        and ("S3", "policy_changed") in [(a["id"], a["state"]) for a in r6["attention"]]
        and ("S7", "policy_changed") in [(g["id"], g["state"]) for g in r6["gaps"]])
    chk("TC7", "02d next step: re-confirm the scope and open a new collaboration (result, Markdown, CLI)",
        "open a new collaboration" in (r6["policy_next_step"] or "") and "scope save" in r6["policy_next_step"]
        and "Next step for Policy-changed suggestions" in md6 and "open a new collaboration" in step_of(o)
        and "Invalidated for the rest of this collaboration: `CWE/4.14/CWE-312`" in md6)
    change_rule(p, R312, "Rule body.\n")  # the Maintainer restores the original body
    c, o, _, _ = cp(p, "show", cid)
    c2, o2, _, _ = cp(p, "report", cid)
    latest = rjson(p, cid, o2["data"]["round"])
    chk("TC7", "02d policy_changed stays for the rest of the collaboration after the Policy is restored",
        {s["id"]: s["state"] for s in o["data"]["suggestions"]}["S3"] == "policy_changed"
        and states(latest)["S3"] == states(latest)["S7"] == "policy_changed")
    # close with an unreported change -> final round
    with (p / "app/public/styles.css").open("a", encoding="utf-8") as fh:
        fh.write("/* final touch */\n")
    last = o2["data"]["round"]
    c, o, _, err = cp(p, "close", cid)
    assert c == 0, (o, err)
    n = o["data"]["round"]
    st = cstate(p, cid)
    chk("TC8", "06f close with unreported changes publishes a final round, closes and returns the latest pair",
        n == last + 1 and o["data"]["published"] is True and o["data"]["status"] == "closed"
        and st["status"] == "closed" and st["closed_at"] and o["data"]["report"] == f"{CREPORTS}/{cid}-r{n}.md"
        and o["data"]["result"] == f"{CREPORTS}/{cid}-r{n}.json" and o["data"]["report_exists"]
        and o["data"]["result_exists"] and rjson(p, cid, n)["supersedes"] == f"{cid}-r{last}")
    MAIN["final_round"] = n
    frozen = rbytes(p, cid)
    c, o, _, _ = cp(p, "report", cid)
    chk("TC8", "report after close returns the same latest pair (no new round)",
        c == 0 and o["data"]["round"] == n and o["data"]["published"] is False)
    refusals = {
        "suggest": cp(p, "suggest", cid, batch(sug("S8", R89, ["app/registration.py"]))),
        "review": cp(p, "review", cid, rdoc(p, [subj("S7", "adopted", "x")], ["app/audit.py"])),
        "artifacts": cp(p, "artifacts", cid, {"schema": S_ART, "artifacts": [{"path": "app/audit.py"}]}),
        "close": cp(p, "close", cid),
    }
    chk("TC8", "06d closed collaboration refuses suggestions, reviews, artifacts and close with the next step "
        "to open a new collaboration",
        all(r[0] == 1 and code_of(r[1]) == "COLLAB_CLOSED" and "copilot open" in step_of(r[1])
            for r in refusals.values()) and len(cstate(p, cid)["suggestions"]) == 7)
    chk("TC8", "06d its reports stay unchanged", rbytes(p, cid) == frozen
        and all(frozen[k] == v for k, v in MAIN["r5_bytes"].items()))
    MAIN["all_rounds"] = list(range(1, n + 1))
    every = []
    for k in MAIN["all_rounds"]:
        res, md = rjson(p, cid, k), rmd(p, cid, k)
        every.append((k, res, md))
        for name, ok in consistent(res, md):
            chk("TC5", f"05a r{k}: {name}", ok)
    chk("TC5", "05a every round: Markdown footer binds the exact structured-result bytes",
        all(footer_ok(p, cid, k) for k in MAIN["all_rounds"]))
    chk("TC5", "05e every round: no pass, approved, verdict or completed-safely key",
        all(no_pass_keys(res) for _, res, _ in every))
    chk("TC1", "02c the adopted scope id and every rule with its confirmed digest appear in every report",
        all(res["scope"]["scope_id"] == MAIN["scope"] and f"`{MAIN['scope']}`" in md
            and {a["rule"]: a["state_digest"] for a in res["scope"]["adopted"]} == MAIN["dig"]
            and all(f"`{d}`" in md for d in MAIN["dig"].values()) for _, res, md in every))
    chk("TC5", "05a each round names the round it supersedes (contiguous numbering)",
        [res["supersedes"] for _, res, _ in every] == [None] + [f"{cid}-r{k}" for k in MAIN["all_rounds"][:-1]]
        and report_entries(p) == sorted(f"{cid}-r{k}.{x}" for k in MAIN["all_rounds"] for x in ("json", "md")))


# ---------------------------------------------------------------- masking (03g), same project
def masking() -> None:
    p = MAIN["p"]
    scope2, _ = save_scope(p, (R89, R79))
    MAIN["scope2"] = scope2
    start = len(WRITES)
    c, o, _, err = cp(p, "open", doc=odoc(scope2, [{"path": "app/registration.py"}],
                                          task=f"Rotate the organiser API token {TOKEN} before the export"))
    assert c == 0, (o, err)
    cid = o["data"]["collaboration_id"]
    c, o, _, _ = cp(p, "suggest", cid, batch(sug("M9", R89, ["app/registration.py"],
                                                action="Remove [masked:credential.token] again")))
    chk("TC3", "03g agent text containing a toolkit mask marker is refused (only the toolkit masks)",
        c == 1 and code_of(o) == "SUGGESTION_INVALID" and "mask marker" in msg_of(o))
    c, o, _, err = cp(p, "suggest", cid, batch(
        sug("M1", R89, ["app/registration.py"], location=f"key loader near {TOKEN}"),
        sug("M2", R89, ["app/registration.py"], action=f"Remove the hard-coded value {TOKEN}"),
        sug("M3", R79, ["app/registration.py"], reason=f"The value {TOKEN} grants repository access")))
    assert c == 0, (o, err)
    c, o, _, err = cp(p, "review", cid, rdoc(
        p, [subj("M1", "adopted", f"the loader no longer contains {TOKEN}"),
            subj("M2", "not_adopted", "value still present"), subj("M3", "cannot_verify", "not visible")],
        ["app/registration.py"], requirement=f"Check that {TOKEN} is gone from the loader"))
    assert c == 0, (o, err)
    c, o, _, err = cp(p, "report", cid)
    assert c == 0, (o, err)
    raw_state = (p / COLLAB / cid / "state.json").read_text(encoding="utf-8")
    st, res, md = json.loads(raw_state), rjson(p, cid, 1), rmd(p, cid, 1)
    js_raw = (p / CREPORTS / f"{cid}-r1.json").read_text(encoding="utf-8")
    outs = "".join(w["stdout"] for w in WRITES[start:])
    want = {"M1": ["location"], "M2": ["action"], "M3": ["reason"]}
    chk("TC3", "03g credential absent from collaboration state, structured result, Markdown and command output",
        TOKEN not in raw_state and TOKEN not in js_raw and TOKEN not in md and TOKEN not in outs
        and "[masked:" in st["task"] and "[masked:" in res["task"])
    chk("TC3", "03g state labels the masked fields: task, location, action, reason, requirement, basis",
        st["masked"] == ["task"] and {s["id"]: s["masked"] for s in st["suggestions"]} == want
        and st["reviews"][0]["masked"] == ["requirement", "subjects[0].basis"])
    chk("TC3", "03g structured result labels the same masked fields",
        res["masked"] == ["task"] and {s["id"]: s["masked"] for s in res["suggestions"]} == want
        and res["reviews"][0]["masked"] == ["requirement", "subjects[0].basis"]
        and "[masked:" in by_id(res, "M1")["location"] and "[masked:" in by_id(res, "M1")["basis"])
    chk("TC3", "03g Markdown labels each masked item as masked (never as unchanged input)",
        "Task (masked): " in md and "`masked: location`" in md and "`masked: action`" in md
        and "`masked: reason`" in md and "`masked: requirement`, `masked: subjects[0].basis`" in md
        and "`[masked:credential" in md)
    for name, ok in consistent(res, md):
        chk("TC5", f"05a masking r1: {name}", ok)


# ---------------------------------------------------------------- design stage, no-change close, retention (05d, 05g, 06f)
def design_collab() -> None:
    p = MAIN["p"]
    (p / "app/docs").mkdir()
    (p / "app/docs/design.md").write_text("# Export design\n\nThe export page lists names and cities.\n")
    c, o, _, err = cp(p, "open", doc=odoc(MAIN["scope2"], [{"path": "app/docs", "change": "added"}], stage="design",
                                          task="Design the organiser export page"))
    assert c == 0, (o, err)
    cid = o["data"]["collaboration_id"]
    assert cp(p, "suggest", cid, batch(sug("D1", R79, ["app/docs/design.md"])))[0] == 0
    c, o, _, _ = cp(p, "report", cid)
    res, md = rjson(p, cid, 1), rmd(p, cid, 1)
    pub = res["published_at"]
    c2, o2, _, _ = cp(p, "close", cid)
    chk("TC8", "06f close without change since the latest report publishes no new round, returns the latest pair",
        c2 == 0 and o2["data"]["round"] == 1 and o2["data"]["published"] is False
        and o2["data"]["status"] == "closed" and report_entries(p).count(f"{cid}-r1.json") == 1
        and not (p / CREPORTS / f"{cid}-r2.json").exists())
    design = "For the design stage, adoption in the design does not show the measure is implemented."
    chk("TC8", "05d design stage: both outputs state adoption in the design does not show implementation",
        design in res["boundaries"] and esc(design) in md
        and any("not a pass, approval or security verification" in b for b in res["boundaries"]))
    chk("TC8", "05g both outputs state retention until the user removes them; existence as of publication",
        res["retention"] == {"reports": "kept until the user removes them",
                             "private_data": "kept until the user removes it; no automatic expiry"}
        and res["private_data_present_as_of_publication"] is True
        and "Reports: kept until the user removes them" in md
        and "Private collaboration data: kept until the user removes it; no automatic expiry" in md
        and f"Private collaboration data present as of publication {esc(pub)}: yes" in md)
    c, o, _, _ = cp(p, "show", cid)
    ok1 = c == 0 and o["data"]["private_data_present"] is True and o["data"]["reports"] == [
        {"round": 1, "json": f"{CREPORTS}/{cid}-r1.json", "json_exists": True, "md": f"{CREPORTS}/{cid}-r1.md",
         "md_exists": True}]
    (p / CREPORTS / f"{cid}-r1.md").unlink()  # the user removes a report
    c, o, _, _ = cp(p, "show", cid)
    ok2 = c == 0 and o["data"]["reports"][0]["md_exists"] is False and o["data"]["reports"][0]["json_exists"]
    shutil.rmtree(p / COLLAB / cid)  # the user removes the private collaboration data
    c, o, _, _ = cp(p, "show", cid)
    ok3 = c == 0 and o["data"]["private_data_present"] is False and o["data"]["latest_round"] == 1
    chk("TC8", "05g show states whether the private data and each report still exist (later removals seen)",
        ok1 and ok2 and ok3)


# ---------------------------------------------------------------- open/update refusals (02a, 02b, 02e, 03b, 03c)
def refusals() -> None:
    pm = new_project(rules=(R89,), prefix="fat-ca-m-")
    scope_m, _ = save_scope(pm, (R89,))
    change_rule(pm, R89, "Changed body.\n")
    c, o, _, _ = cp(pm, "open", doc=odoc(scope_m, [{"path": "app/registration.py"}]))
    chk("TC9", "02a scope without usable Policies: maintenance needed with the Framework maintenance next step",
        c == 1 and code_of(o) == "MAINTENANCE_NEEDED" and "Maintainer" in step_of(o) and "Framework" in step_of(o)
        and len(o["next_steps"]) == 1)
    chk("TC9", "02a no collaboration opened, no suggestion or report recorded",
        collab_entries(pm) == [] and report_entries(pm) == [])
    pp = new_project(rules=(R89, R79), prefix="fat-ca-p-")
    scope_p, _ = save_scope(pp, (R89, R79))
    change_rule(pp, R79, "Changed body.\n")
    c, o, _, _ = cp(pp, "open", doc=odoc(scope_p, [{"path": "app/registration.py"}]))
    chk("TC9", "02b partial scope refused listing available, changed and missing Policies; next step re-propose "
        "and confirm a new scope",
        c == 1 and code_of(o) == "SCOPE_PARTIAL" and o["data"]["adopted"] == [R89]
        and o["data"]["needs_reconfirmation"] == [R79] and o["data"]["missing"] == []
        and "scope save" in step_of(o) and len(o["next_steps"]) == 1)
    for name, doc in (("no scope identifier", odoc(None, [{"path": "app/registration.py"}])),
                      ("unknown scope identifier", odoc("sha256:" + "0" * 64, [{"path": "app/registration.py"}]))):
        c, o, _, _ = cp(pp, "open", doc=doc)
        chk("TC9", f"02e {name}: refused with resolve/select/confirm next step, not knowledge maintenance",
            c == 1 and code_of(o) in ("SCOPE_REQUIRED", "SCOPE_NOT_FOUND") and "scope save" in step_of(o)
            and "Maintainer" not in step_of(o) and "maintenance" not in step_of(o).lower())
    chk("TC9", "02b/02e nothing opened", collab_entries(pp) == [])
    scope_ok, _ = save_scope(pp, (R89, R79))
    app = pp / "app"
    os.symlink("registration.py", app / "link.py")
    whole = [("empty artifact list", odoc(scope_ok, []), "ARTIFACTS_REQUIRED"),
             ("no artifacts given", {k: v for k, v in odoc(scope_ok, []).items() if k != "artifacts"},
              "ARTIFACTS_REQUIRED"),
             ("whole project as '.'", odoc(scope_ok, [{"path": "."}]), "WHOLE_PROJECT_REFUSED"),
             ("whole_project flag", odoc(scope_ok, [{"path": "app/registration.py"}], whole_project=True),
              "WHOLE_PROJECT_REFUSED")]
    for name, doc, code in whole:
        c, o, _, _ = cp(pp, "open", doc=doc)
        chk("TC9", f"03b {name}: refused with the next step to name the changed artifacts",
            c == 1 and code_of(o) == code and "Name the changed artifact" in step_of(o)
            and "no automatic whole-project review" in step_of(o))
    bad = [("missing path", {"path": "app/nope.py", "change": "modified"}, "app/nope.py"),
           ("path outside the project", {"path": "../outside.py"}, "outside.py"),
           ("symbolic link", {"path": "app/link.py"}, "app/link.py"),
           ("folder declared deleted", {"path": "app/public", "change": "deleted"}, "app/public"),
           ("folder declared renamed", {"path": "app/public", "change": "renamed", "old_path": "app/old"},
            "app/public"),
           ("private toolkit data", {"path": ".x-ipe/private/secure-code"}, ".x-ipe/private")]
    for name, entry, word in bad:
        c, o, _, _ = cp(pp, "open", doc=odoc(scope_ok, [entry]))
        chk("TC9", f"03c open with {name}: refused naming the path with a next step",
            c == 1 and code_of(o) == "TARGET_INVALID" and word in msg_of(o) and len(o["next_steps"]) == 1)
    chk("TC9", "03b/03c nothing opened by any refusal", collab_entries(pp) == [])
    (app / "docs").mkdir()
    (app / "docs/a.md").write_text("a\n")
    (app / "docs/b.md").write_text("b\n")
    c, o, _, err = cp(pp, "open", doc=odoc(scope_ok, [{"path": "app/docs", "change": "added"},
                                                      {"path": "app/registration.py"}]))
    assert c == 0, (o, err)
    cid = o["data"]["collaboration_id"]
    man0 = cstate(pp, cid)["manifest"]
    shutil.rmtree(app / "docs")
    (app / "docs2").mkdir()
    (app / "docs2/a.md").write_text("a\n")
    upd = [("deleted folder", {"path": "app/docs", "change": "deleted"}, "app/docs"),
           ("renamed folder", {"path": "app/docs2", "change": "renamed", "old_path": "app/docs"}, "app/docs"),
           ("symbolic link", {"path": "app/link.py", "change": "added"}, "app/link.py")]
    for name, entry, word in upd:
        c, o, _, _ = cp(pp, "artifacts", cid, {"schema": S_ART, "artifacts": [entry]})
        chk("TC9", f"03c artifact update with {name}: refused naming the path with a next step",
            c == 1 and code_of(o) == "TARGET_INVALID" and word in msg_of(o) and step_of(o))
    chk("TC9", "03c refused updates change nothing", cstate(pp, cid)["manifest"] == man0)
    c, o, _, _ = cp(pp, "artifacts", cid, {"schema": S_ART, "artifacts": [
        {"path": "app/docs/a.md", "change": "deleted"}, {"path": "app/docs/b.md", "change": "deleted"}]})
    chk("TC9", "03c a deleted folder is recorded as its individual files",
        c == 0 and cstate(pp, cid)["manifest"]["app/docs/a.md"]["change"] == "deleted"
        and cstate(pp, cid)["manifest"]["app/docs/b.md"]["digest"] is None)


# ---------------------------------------------------------------- Guard takes the Copilot report as context only (06e)
GATTEMPT = "ai-secure-code-toolkit/guard-attempt/v1"


def _g(p: Path, cmd: str, vid: str | None = None, doc: dict | None = None, *extra: str):
    args = ["guard", cmd, "--project", str(p)]
    if vid:
        args += ["--run", vid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    return sc(*args, *extra, "--json")


def _attempt(p: Path, vid: str, kind: str, covers: dict) -> str:
    code, out, _, _ = _g(p, "attempt", vid, {"schema": GATTEMPT, "kind": kind, "covers": covers})
    assert code == 0, out
    return out["data"]["attempt"]


def guard_context() -> None:
    p, cid, n = MAIN["p"], MAIN["cid"], MAIN["final_round"]
    md_rel = f"{CREPORTS}/{cid}-r{n}.md"
    before = rbytes(p, cid)
    code, out, _, err = _g(p, "open", doc={"schema": "ai-secure-code-toolkit/guard-open/v1",
                                           "scope_id": MAIN["scope2"],
                                           "targets": [{"path": "app/public/app.js", "change": "modified"}],
                                           "copilot_reports": [{"path": md_rel}]})
    assert code == 0, (out, err)
    vid = out["data"]["verification_id"]
    digests = {t["path"]: t["digest"] for t in out["data"]["targets"]}
    plan = {"schema": "ai-secure-code-toolkit/guard-plan/v1",
            "checks": [{"id": "C1", "rule": R79, "object": ["app/public/app.js"],
                        "methods": [{"name": "semantic-review", "kind": "reading", "required": True}],
                        "minimum_evidence": ["reading"]}],
            "not_applicable": [{"rule": R89, "reason": "no database access in app.js"}]}
    assert _g(p, "plan", vid, plan)[0] == 0
    att = _attempt(p, vid, "semantic_review", {"pairs": [{"check": "C1", "method": "semantic-review"}]})
    record = {"schema": "ai-secure-code-toolkit/guard-record/v1", "attempt": att,
              "evidence": [{"id": "E1", "kind": "reading", "method": "semantic-review", "method_status": "ok",
                            "checks": ["C1"], "paths": [md_rel], "summary": "Copilot report says S2 adopted"}],
              "ledger": [{"check": "C1", "state": "met", "evidence": ["E1"]}]}
    rc, rout, _, _ = _g(p, "record", vid, record)
    att2 = _attempt(p, vid, "reviewer", {"findings": [], "na": [f"policy:{R89}"]})
    review = {"schema": S_REV, "attempt": att2,
              "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
              "requirement": "Re-check N/A decisions",
              "reviewed_targets": [{"path": "app/public/app.js", "digest": digests["app/public/app.js"]}],
              "subjects": [{"type": "na_decision", "id": f"policy:{R89}", "result": "confirmed",
                            "basis": "no SQL in app.js"}]}
    vc, vout, _, _ = _g(p, "review", vid, review)
    cc, cout, _, err = _g(p, "conclude", vid)
    assert cc == 0, (cout, err)
    res = json.loads((p / GREPORTS / f"{vid}.json").read_text(encoding="utf-8"))
    gmd = (p / GREPORTS / f"{vid}.md").read_text(encoding="utf-8")
    row = next(r for r in res["ledger"] if r["check"] == "C1")
    chk("TC10", "06e Guard opened with the Copilot report records it as context (copilot_reports)",
        res["artifact"]["copilot_reports"][0]["path"] == md_rel and "never evidence of a pass" in gmd)
    chk("TC10", "06e Copilot report cited as evidence never makes a check met or a Pass",
        (rc != 0 or row["state"] == "unconfirmed") and cout["data"]["verdict"] != "pass"
        and vc == 0)
    chk("TC10", "06e Guard leaves the Copilot report files byte-identical", rbytes(p, cid) == before)


# ---------------------------------------------------------------- closing-review additions (TASK-048), main copy
def _rev_row(md: str, seq: int) -> str:
    return next((x for x in sections(md).get("Reviewer Records", "").splitlines()
                 if x.startswith(f"| {seq} | ")), "")


def extras() -> None:
    """03a bug_fix/refactor + `unspecified` folder, 04f single missing fields, 01d stale-only record, 06f."""
    p = MAIN["p"]
    scope, _ = save_scope(p, (R89, R79))
    pub = sorted(f.relative_to(p).as_posix() for f in (p / "app/public").rglob("*")
                 if f.is_file() and not f.is_symlink())
    expected = {f: fdig(p, f) for f in [*pub, "app/registration.py"]}
    c, o, _, err = cp(p, "open", doc=odoc(scope, [{"path": "app/public"},
                                                  {"path": "app/registration.py", "change": "modified"}],
                                          stage="bug_fix", task="Fix the escaping bug in the summary list"))
    assert c == 0, (o, err)
    cid = o["data"]["collaboration_id"]
    MAIN["x_cid"] = cid
    st = cstate(p, cid)
    man = st["manifest"]
    chk("TC1", "03a bug_fix stage recorded; folder artifact without change meaning recorded as `unspecified`",
        st["stage"] == o["data"]["stage"] == "bug_fix" and len(pub) >= 4
        and [(a["path"], a["kind"], a["change"]) for a in st["artifacts"]]
        == [("app/public", "dir", "unspecified"), ("app/registration.py", "file", "modified")])
    chk("TC1", "03a `unspecified` folder: every regular file recorded per file with its digest and source folder",
        o["data"]["manifest"] == expected and {k: v["digest"] for k, v in man.items()} == expected
        and all(man[f]["change"] == "unspecified" and man[f]["source"] == "app/public" for f in pub)
        and any(n["path"] == "app/public/app-link.js" for n in o["data"]["not_bindable"]))
    c, o, _, err = cp(p, "suggest", cid, batch(
        sug("B1", R89, ["app/registration.py"]), sug("B2", R79, ["app/public/app.js"]),
        sug("B3", R79, ["app/public/index.html"], "medium")))
    assert c == 0, (o, err)
    chk("TC1", "03a suggestions of a bug_fix collaboration take its stage",
        [s["stage"] for s in cstate(p, cid)["suggestions"]] == ["bug_fix"] * 3)
    b1 = [subj("B1", "adopted", "registration.py binds every value")]
    inv = {"host": "github-copilot", "agent": "copilot-reviewer", "read_only": True, "invoked_at": now_z()}
    single = [
        ("agent missing (host present)", {"invocation": {k: v for k, v in inv.items() if k != "agent"}},
         "invocation.agent is missing"),
        ("read-only declaration missing", {"invocation": {k: v for k, v in inv.items() if k != "read_only"}},
         "invocation.read_only is not true"),
        ("invocation time missing", {"invocation": {k: v for k, v in inv.items() if k != "invoked_at"}},
         "invocation.invoked_at is missing"),
        ("review requirement missing", {"requirement": None}, "requirement is missing"),
    ]
    for n, (name, over, reason) in enumerate(single, start=1):
        doc = rdoc(p, b1, ["app/registration.py"])
        doc.update(over)
        doc = {k: v for k, v in doc.items() if v is not None}
        c, o, _, _ = cp(p, "review", cid, doc)
        chk("TC4", f"04f {name}: record kept (seq {n}), not valid, only that reason",
            c == 0 and o["data"]["seq"] == n and o["data"]["valid"] is False
            and o["data"]["completeness"] == [reason])
    c, o, _, _ = cp(p, "report", cid)
    r1, md1 = rjson(p, cid, 1), rmd(p, cid, 1)
    rows = {r["seq"]: r for r in r1["reviews"]}
    chk("TC4", "04f report names each single missing field (JSON reasons and the Markdown row)",
        c == 0 and all(rows[n]["valid"] is False and rows[n]["reasons"] == [reason]
                       and _rev_row(md1, n).startswith(f"| {n} | no |") and f"`{reason}`" in _rev_row(md1, n)
                       for n, (_, _, reason) in enumerate(single, start=1)))
    chk("TC4", "04f missing agent only: the report shows the host, no agent, and names the missing agent",
        rows[1]["invocation"]["host"] == "github-copilot" and rows[1]["invocation"]["agent"] is None
        and _rev_row(md1, 1).startswith("| 1 | no | github-copilot | — | yes |")
        and "`invocation.agent is missing`" in _rev_row(md1, 1) and states(r1)["B1"] == "not_reviewed")
    c, o, _, err = cp(p, "review", cid, rdoc(p, [
        subj("B1", "adopted", "registration.py binds every value"),
        subj("B2", "adopted", "app.js uses textContent"),
        subj("B3", "partial", "index.html meta tag lacks script-src")],
        ["app/registration.py", "app/public/app.js", "app/public/index.html"]))
    assert c == 0 and o["data"]["seq"] == 5, (o, err)
    assert cp(p, "report", cid)[0] == 0
    with (p / "app/public/app.js").open("a", encoding="utf-8") as fh:
        fh.write("\n// bug fix: summary list escaped\n")
    with (p / "app/public/index.html").open("a", encoding="utf-8") as fh:
        fh.write("\n<!-- bug fix -->\n")
    c, o, _, _ = cp(p, "show", cid)
    shown_rr = o["data"]["re_review"]
    stale_only = [subj("B2", "not_adopted", "app.js again uses innerHTML for the list"),
                  subj("B3", "adopted", "index.html now sets script-src self")]
    c, o, _, err = cp(p, "review", cid, rdoc(p, stale_only, ["app/public/app.js", "app/public/index.html"]))
    chk("TC6", "01d record covering ONLY the stale suggestions (no new suggestion exists or is covered)",
        shown_rr == ["B2", "B3"] and c == 0 and o["data"]["valid"] is True and o["data"]["seq"] == 6
        and o["data"]["covers"] == ["B2", "B3"] and len(cstate(p, cid)["suggestions"]) == 3)
    c, o, _, _ = cp(p, "report", cid)
    r3, md3 = rjson(p, cid, 3), rmd(p, cid, 3)
    b1r, b2r, b3r = by_id(r3, "B1"), by_id(r3, "B2"), by_id(r3, "B3")
    row6 = next(r for r in r3["reviews"] if r["seq"] == 6)
    chk("TC6", "01d stale-only record: those suggestions show the new results (seq 6), earlier ones as history",
        c == 0 and o["data"]["round"] == 3 and (b2r["state"], b2r["review_seq"], b2r["basis"])
        == ("not_adopted", 6, stale_only[0]["basis"]) and (b3r["state"], b3r["review_seq"]) == ("adopted", 6)
        and b2r["history"] == [{"seq": 5, "result": "adopted", "basis": "app.js uses textContent"}]
        and row6["counted"] == ["B2", "B3"] and [s["id"] for s in row6["subjects"]] == ["B2", "B3"])
    chk("TC6", "01d stale-only record: the unaffected suggestion keeps its earlier current result, not re-reviewed",
        (b1r["state"], b1r["review_seq"], b1r["basis"], b1r["history"])
        == ("adopted", 5, "registration.py binds every value", []) and r3["re_review"] == []
        and "| `B1` | `adopted` |" in sections(md3)["Suggestions"])
    # 06f: a refactor collaboration closed without any earlier report
    c, o, _, err = cp(p, "open", doc=odoc(scope, [{"path": "app/audit.py", "change": "modified"}],
                                          stage="refactor", task="Extract the audit helper"))
    assert c == 0, (o, err)
    fid = o["data"]["collaboration_id"]
    MAIN["f_cid"] = fid
    chk("TC1", "03a refactor stage recorded", cstate(p, fid)["stage"] == o["data"]["stage"] == "refactor")
    assert cp(p, "suggest", fid, batch(sug("F1", R89, ["app/audit.py"], "low")))[0] == 0
    no_report = not any(x.startswith(fid) for x in report_entries(p))
    c, o, _, err = cp(p, "close", fid)
    st = cstate(p, fid)
    chk("TC8", "06f close of a collaboration with NO prior report publishes a first round before closing and "
        "returns it",
        no_report and c == 0 and o["data"]["round"] == 1 and o["data"]["published"] is True
        and o["data"]["status"] == "closed" and st["status"] == "closed" and st["closed_at"]
        and [r["n"] for r in st["rounds"]] == [1] and o["data"]["report"] == f"{CREPORTS}/{fid}-r1.md"
        and o["data"]["result"] == f"{CREPORTS}/{fid}-r1.json" and o["data"]["report_exists"]
        and o["data"]["result_exists"] and rjson(p, fid, 1)["supersedes"] is None
        and [x for x in report_entries(p) if x.startswith(fid)] == [f"{fid}-r1.json", f"{fid}-r1.md"])
    chk("TC1", "03a refactor stage stated in the published round (JSON and Markdown)",
        rjson(p, fid, 1)["stage"] == "refactor" and "Stage: `refactor`" in rmd(p, fid, 1)
        and [s["stage"] for s in rjson(p, fid, 1)["suggestions"]] == ["refactor"])
    for k in (1, 2, 3):
        for name, ok in consistent(rjson(p, cid, k), rmd(p, cid, k)):
            chk("TC5", f"05a bug_fix r{k}: {name}", ok)
    for name, ok in consistent(rjson(p, fid, 1), rmd(p, fid, 1)):
        chk("TC5", f"05a refactor r1: {name}", ok)
    chk("TC5", "05a bug_fix and refactor rounds: footer binds the exact structured-result bytes",
        all(footer_ok(p, cid, k) for k in (1, 2, 3)) and footer_ok(p, fid, 1))


# ---------------------------------------------------------------- removed Policy (02b missing list, 02d removed)
def policy_extras() -> None:
    p = new_project(prefix="fat-ca-x-")
    scope, _ = save_scope(p)
    c, o, _, err = cp(p, "open", doc=odoc(scope, [{"path": "app/registration.py", "change": "modified"},
                                                  {"path": "app/server.py"}]))
    assert c == 0, (o, err)
    cid = o["data"]["collaboration_id"]
    assert cp(p, "suggest", cid, batch(sug("P1", R312, ["app/registration.py"], "critical"),
                                       sug("P2", R89, ["app/registration.py"]),
                                       sug("P3", R312, ["app/server.py"], "low")))[0] == 0
    basis = {"P1": "the key file is created with mode 0600", "P2": "INSERT uses placeholders",
             "P3": "server.py reads the key path from the environment"}
    c, o, _, err = cp(p, "review", cid, rdoc(p, [subj(s, "adopted", b) for s, b in basis.items()],
                                             ["app/registration.py", "app/server.py"]))
    assert c == 0, (o, err)
    c, o, _, _ = cp(p, "report", cid)
    r1 = rjson(p, cid, 1)
    remove_rule(p, R312)  # disclosed fixture: the Maintainer removes the adopted Policy after opening
    c, o, _, _ = cp(p, "report", cid)
    r2, md2 = rjson(p, cid, 2), rmd(p, cid, 2)
    p1 = by_id(r2, "P1")
    chk("TC7", "02d REMOVED Policy after opening: its suggestions policy_changed, earlier result as history, "
        "rule now `missing`",
        states(r1) == {"P1": "adopted", "P2": "adopted", "P3": "adopted"} and c == 0 and o["data"]["round"] == 2
        and states(r2) == {"P1": "policy_changed", "P2": "adopted", "P3": "policy_changed"}
        and p1["basis"] is None and p1["history"] == [{"seq": 1, "result": "adopted", "basis": basis["P1"]}]
        and {a["rule"]: a["now"] for a in r2["scope"]["adopted"]}[R312] == "missing"
        and R312 in r2["scope"]["invalidated"])
    chk("TC7", "02d removed: not counted as adoption; critical P1 attention, low P3 gap; next step re-confirm "
        "and open a new collaboration (result, Markdown, CLI)",
        r2["counts"]["adopted"] == 1 and r2["counts"]["policy_changed"] == 2
        and [(a["id"], a["state"]) for a in r2["attention"]] == [("P1", "policy_changed")]
        and [(g["id"], g["state"]) for g in r2["gaps"]] == [("P3", "policy_changed")]
        and "open a new collaboration" in (r2["policy_next_step"] or "") and "open a new collaboration" in step_of(o)
        and f"| `{R312}` | " in sections(md2)["Adopted Policies"] and "| `missing` |" in md2
        and f"Invalidated for the rest of this collaboration: `{R312}`" in md2)
    for k in (1, 2):
        for name, ok in consistent(rjson(p, cid, k), rmd(p, cid, k)):
            chk("TC5", f"05a removed-Policy r{k}: {name}", ok)
    change_rule(p, R79, "Changed body.\n")
    before_c, before_r = collab_entries(p), report_entries(p)
    c, o, _, _ = cp(p, "open", doc=odoc(scope, [{"path": "app/registration.py"}]))
    chk("TC9", "02b partial scope with a MISSING (removed) and a changed Policy refused listing available, "
        "changed and missing; one next step to re-propose and confirm",
        c == 1 and code_of(o) == "SCOPE_PARTIAL" and o["data"]["adopted"] == [R89]
        and o["data"]["needs_reconfirmation"] == [R79] and o["data"]["missing"] == [R312]
        and "scope save" in step_of(o) and len(o["next_steps"]) == 1)
    chk("TC9", "02b missing-Policy refusal opens nothing and writes no report",
        collab_entries(p) == before_c and report_entries(p) == before_r)


def writes_check() -> None:
    copilot_calls = [w for w in WRITES]
    chk("TC10", f"06a no artifact or other project file changed by any of {len(copilot_calls)} Copilot commands",
        len(copilot_calls) > 50 and all(w["outside"] == [] for w in copilot_calls))
    chk("TC10", "06a only Copilot's private data (the own collaboration folder and the project-wide Copilot lock "
        "file .x-ipe/private/secure-code/locks/copilot.lock) and own report files written",
        all(w["foreign"] == [] for w in copilot_calls))
    chk("TC10", "06a the project-wide Copilot lock file is written (created on first use in each project)",
        any(w["lock"] for w in copilot_calls))
    chk("TC10", "06a/05b no existing report file was ever rewritten by a Copilot command",
        all(w["rewritten_reports"] == [] for w in copilot_calls))
    bad = [(w["cmd"], w["outside"], w["foreign"], w["rewritten_reports"]) for w in copilot_calls
           if w["outside"] or w["foreign"] or w["rewritten_reports"]]
    if bad:
        print(json.dumps({"writes_violations": bad[:20]}), file=sys.stderr, flush=True)


# ---------------------------------------------------------------- skill package (01e, 03h, 04j, 06b, 06c) - both modes
def tc_skill_package():
    raw = (COPILOT_SKILL / "SKILL.md").read_text(encoding="utf-8")
    text = " ".join(raw.lower().split())
    ref = (COPILOT_SKILL / "references" / "copilot-records.md").read_text(encoding="utf-8")
    examples = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", ref, re.S)]
    contract = CLI_CONTRACT.read_text(encoding="utf-8")

    def has(*phrases: str) -> bool:
        return all(x in text for x in phrases)

    return [
        ("01e no re-review after every edit; check stale after a relevant change; send only stale and new",
         has("do not re-review after every edit", "after a relevant change",
             "to see which suggestions are stale", "send only the stale and new suggestions to the reviewer")),
        ("03h work during design, implementation, bug fix and refactor incl. changes to an existing design",
         has("collaborate during design, implementation, bug fix and refactor tasks, including changes to an "
             "existing design")),
        ("03h load adopted Policies through the Framework",
         has("load the adopted policies through the framework skill")),
        ("03h concrete suggestions tied to artifact location and Policy source; no generic checklist",
         has("concrete suggestions, each tied to an artifact location and a policy source", "no generic checklist")),
        ("03h focus on the change and its related impact; all edits to the current executor",
         has("focus on the change and its related impact", "leave all edits to the current executor")),
        ("04j one independent read-only Reviewer per batch through the host, not one per rule",
         has("call one independent read-only reviewer per batch through the host", "not one per rule")),
        ("04j pass only task, relevant suggestions, artifact locations and digests",
         has("pass only the task, the relevant suggestions, artifact locations and digests")),
        ("04j Reviewer checks the actual artifact, not the executor's claim",
         has("the reviewer must check the actual artifact, not the executor's claim")),
        ("04j Reviewer never edits, never widens the review, never starts further agents",
         has("never edits artifacts, never widens the review and never starts further agents")),
        ("06b Copilot and its Reviewer never edit business artifacts; the current executor makes all changes",
         has("copilot and its reviewer never edit business artifacts", "the current executor makes all changes")),
        ("06b Copilot does not pause or block; the upstream caller decides from the attention list",
         has("copilot does not pause or block the work", "the upstream caller decides from the attention list")),
        ("06c decision to continue is not adoption or a pass",
         has("an upstream decision to continue is not adoption or a pass")),
        ("06c the read-only Reviewer must not trigger the Copilot or Guard flow again",
         has("must not trigger the copilot or guard flow again")),
        ("06c failed or old reports never count as done for the current version",
         has("failed or old reports never count as done for the current version")),
        ("06c Policies never invented from memory", has("never invent policies from memory")),
        ("skeleton note replaced; frontmatter name kept",
         "not yet available" not in text and raw.startswith("---\nname: x-ipe-secure-code-toolkit-copilot\n")),
        ("reference documents the four request schemas with parseable examples",
         {S_OPEN, S_ART, S_SUG, S_REV} <= {e.get("schema") for e in examples}),
        ("reference documents states, attention rule and report rounds",
         all(h in ref for h in ("## Suggestion States", "## Attention Rule", "## Report Rounds"))),
        ("CLI contract lists the seven copilot commands",
         all(f"`secure-code copilot {c}`" in contract
             for c in ("open", "artifacts", "suggest", "review", "report", "show", "close"))),
    ]


# ---------------------------------------------------------------- host case (never-authorized User)
def tc_host_user():
    p = new_project(rules=(), prefix="fat-ca-host-")
    _, auth, _, _ = sc("auth", "status", "--json")
    app_before = tree(p / "app")
    os.symlink("registration.py", p / "app" / "link.py")
    c1, o1, _, _ = cp(p, "open", doc=odoc(None, [{"path": "app/registration.py"}]))
    c2, o2, _, _ = cp(p, "open", doc=odoc("sha256:" + "0" * 64, [{"path": "app/registration.py"}]))
    c3, o3, _, _ = cp(p, "open", doc=odoc("sha256:" + "0" * 64, [{"path": "."}]))
    c4, o4, _, _ = cp(p, "open", doc=odoc("sha256:" + "0" * 64, []))
    c5, o5, _, _ = cp(p, "open", doc=odoc("sha256:" + "0" * 64, [{"path": "app/link.py"}]))
    c6, o6, _, _ = cp(p, "show", "cp-20261021T000000Z-00000000")
    (p / "app" / "link.py").unlink()
    return [
        ("host User role (never authorized)", auth["data"].get("role") == "user"),
        ("02e no scope -> SCOPE_REQUIRED with resolve/select/confirm next step",
         c1 == 1 and code_of(o1) == "SCOPE_REQUIRED" and "scope save" in step_of(o1)),
        ("02e unknown scope -> refused with the same select-and-confirm step, not maintenance",
         c2 == 1 and code_of(o2) == "SCOPE_NOT_FOUND" and "scope save" in step_of(o2)
         and "maintenance" not in step_of(o2).lower()),
        ("03b whole project / no artifacts refused with name-the-change next step",
         c3 == 1 and code_of(o3) == "WHOLE_PROJECT_REFUSED" and c4 == 1 and code_of(o4) == "ARTIFACTS_REQUIRED"
         and "Name the changed artifact" in step_of(o3)),
        ("03c symbolic link refused naming the path", c5 == 1 and code_of(o5) == "TARGET_INVALID"
         and "app/link.py" in msg_of(o5)),
        ("unknown collaboration -> COLLAB_NOT_FOUND with open next step",
         c6 == 1 and code_of(o6) == "COLLAB_NOT_FOUND" and "copilot open" in step_of(o6)),
        ("nothing opened, no report, artifacts byte-identical, writes only in allowed areas",
         collab_entries(p) == [] and report_entries(p) == [] and tree(p / "app") == app_before
         and all(w["outside"] == [] and w["foreign"] == [] for w in WRITES)),
    ]


ACS = {
    # TC -> AC map (TASK-048 additions: TC1 03a bug_fix/refactor/unspecified folder; TC4 04b all results, 04f
    # single missing fields; TC5 05a full Reviewer records; TC6 01d stale-only record; TC7 02d removed Policy;
    # TC8 06f close without report; TC9 02b missing Policy; TC10 06a project-wide lock file)
    "TC1": ["AC-003A-02c", "AC-003A-03a"],
    "TC2": ["AC-003A-03d", "AC-003A-03e", "AC-003A-03f"],
    "TC3": ["AC-003A-03g"],
    "TC4": ["AC-003A-04a", "AC-003A-04b", "AC-003A-04c", "AC-003A-04d", "AC-003A-04f", "AC-003A-04h"],
    "TC5": ["AC-003A-04e", "AC-003A-04i", "AC-003A-05a", "AC-003A-05c", "AC-003A-05d", "AC-003A-05e"],
    "TC6": ["AC-003A-01a", "AC-003A-01b", "AC-003A-01c", "AC-003A-01d", "AC-003A-03i", "AC-003A-04g",
            "AC-003A-05b"],
    "TC7": ["AC-003A-02d"],
    "TC8": ["AC-003A-05d", "AC-003A-05f", "AC-003A-05g", "AC-003A-06d", "AC-003A-06f"],
    "TC9": ["AC-003A-02a", "AC-003A-02b", "AC-003A-02e", "AC-003A-03b", "AC-003A-03c"],
    "TC10": ["AC-003A-06a", "AC-003A-06e"],
    "TC11": ["AC-003A-01e", "AC-003A-03h", "AC-003A-04j", "AC-003A-06b", "AC-003A-06c"],
    "TC12": ["AC-003A-02e", "AC-003A-03b", "AC-003A-03c"],
}
MAIN_STAGES = ("open", "suggest", "review", "changes", "policy_close")


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        assert sc_pty([(b"passphrase", PASS), (b"passphrase", PASS)], "auth", "init")[0] == 0
        for name, fn in zip(MAIN_STAGES, (main_open, main_suggest, main_review, main_changes,
                                          main_policy_and_close), strict=True):
            if ERR:
                ERR[name] = "skipped after an earlier stage error"
                continue
            stage(name, fn)
        for name, fn in (("masking", masking), ("design", design_collab), ("refusals", refusals),
                         ("guard", guard_context), ("extras", extras), ("policy_extras", policy_extras)):
            stage(name, fn)
        stage("writes", writes_check)
        case("TC-CA-01", ACS["TC1"], tc_from("TC1", "open", "policy_close", "extras"))
        case("TC-CA-02", ACS["TC2"], tc_from("TC2", "suggest", "changes"))
        case("TC-CA-03", ACS["TC3"], tc_from("TC3", "masking"))
        case("TC-CA-04", ACS["TC4"], tc_from("TC4", "review", "extras"))
        case("TC-CA-05", ACS["TC5"], tc_from("TC5", "suggest", "review", "changes", "policy_close", "masking",
                                             "extras", "policy_extras"))
        case("TC-CA-06", ACS["TC6"], tc_from("TC6", "review", "changes", "extras"))
        case("TC-CA-07", ACS["TC7"], tc_from("TC7", "policy_close", "policy_extras"))
        case("TC-CA-08", ACS["TC8"], tc_from("TC8", "review", "policy_close", "design", "extras"))
        case("TC-CA-09", ACS["TC9"], tc_from("TC9", "refusals", "policy_extras"))
        case("TC-CA-10", ACS["TC10"], tc_from("TC10", "guard", "writes", *MAIN_STAGES, "masking", "design",
                                              "refusals", "extras", "policy_extras"))
        case("TC-CA-11", ACS["TC11"], tc_skill_package)
    else:
        case("TC-CA-12", ACS["TC12"], tc_host_user)
        case("TC-CA-11", ACS["TC11"], tc_skill_package)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS),
                                  "copilot_commands": len(WRITES)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
