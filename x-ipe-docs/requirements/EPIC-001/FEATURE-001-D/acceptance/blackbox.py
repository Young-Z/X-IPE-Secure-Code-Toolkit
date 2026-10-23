"""Black-box acceptance scenarios for FEATURE-001-D Knowledge Exit Impact & Broken-Link Handling (TASK-052).

Calls the real CLI only: `uvx --from <framework>/scripts secure-code ...`. Never imports toolkit code.
Guard and Copilot helpers are copied from the FEATURE-002-A and FEATURE-003-A runners.

  python3 blackbox.py host                         # never-authorized User path (no trust writes)
  FAT_ISOLATED=1 python3 blackbox.py container     # Maintainer-prepared scenarios (disposable HOME only!)

Environment: TOOLKIT_ROOT (toolkit folder), FAT_WORK (folder for disposable projects; defaults to the
platform temporary folder).

Fixtures (disclosed):
- Container: owner authorization (`auth init` at a pseudo-terminal), `knowledge import` of placeholder
  CWE rules, `policy resolve` + `scope save --confirmed` (the user's confirmation flag), Guard and Copilot
  runs driven exactly as in the FEATURE-002-A / FEATURE-003-A runners (Reviewer records written by this
  runner in the shape a host read-only Reviewer returns).
- Pending decision: a Maintainer import of an update with a credential-shaped line (`needs_decision`).
- Document index entries: imports carrying `source_document_digest`.
- Damaged rules (03h): hand edit of `content.md`, non-UTF-8 bytes, an atomic-residue file and a symbolic
  link inside the rule folder, written by this runner (standing in for hand edits).
- Crash, pause and race scenarios (06a, 06b, 02f) use the design's documented test-only environment hooks
  SECURE_CODE_TEST_CRASH_AT / SECURE_CODE_TEST_PAUSE_AT, set only on the one CLI subprocess concerned.
- Held knowledge lock (06a LOCKED): this runner holds `flock` on the lock file.
- Missing / invalid authorization (container, 01b/01c): the trust folder is moved aside, or one byte of a
  grant file is changed, and then restored; revocation uses `auth revoke` at a pseudo-terminal (last case).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_UP = Path(__file__).resolve().parents
WORKSPACE = _UP[5] if len(_UP) > 5 else Path("/")  # inside the container the runner is mounted at /fat
TOOLKIT = Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ else WORKSPACE / "ai-secure-code-toolkit"
FRAMEWORK = TOOLKIT / "x-ipe-secure-code-toolkit-framework"
SCRIPTS = FRAMEWORK / "scripts"
LOCAL = "x-ipe-docs/secure-code/knowledge/local"
PRIVATE = ".x-ipe/private/secure-code"
PENDING = f"{PRIVATE}/pending"
INDEX = f"{PRIVATE}/knowledge-documents.json"
EXITS = f"{PRIVATE}/exits"
KLOCK = f"{PRIVATE}/locks/knowledge.lock"
SCOPES = "x-ipe-docs/secure-code/scopes"
GUARD = f"{PRIVATE}/guard"
COLLAB = f"{PRIVATE}/copilot"
REPORTS = "x-ipe-docs/secure-code/reports"
GREPORTS = f"{REPORTS}/guard"
CREPORTS = f"{REPORTS}/copilot"
PASS = "acceptance passphrase 42"
R20, R79, R89, R89SQL = "CWE/4.14/CWE-20", "CWE/4.14/CWE-79", "CWE/4.14/CWE-89", "CWE/4.14/CWE-89-SQL"
DOC, DOC2 = "sha256:" + "d" * 64, "sha256:" + "e" * 64
SECRET = 'password = "Zq8vLr2mNp4tXw9yKp"\n'
REASON = "Superseded by a narrower rule"
NOT_CHECKED = "not checked in this version"
KINDS = ("relations", "scopes", "guard_runs", "copilot_collaborations", "pending_decisions", "document_index")
UNSUPPORTED = ("presets", "tags", "reference_cache")
PREVIEW_KEYS = {"impact", "action", "rule", "target", "reason", "rule_state", "will", "impact_digest",
                "references_block"}
CONFIRM_KEYS = {"outcome", "rule", "target", "exit_id", "lifecycle_revision", "state_digest", "removed_pending",
                "invalidated_index", "tombstone", "impact"}
EXIT_ID = re.compile(r"ex-\d{8}T\d{6}Z-[0-9a-f]{8}")
DIG = re.compile(r"sha256:[0-9a-f]{64}")
TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
HOOKS = ("SECURE_CODE_TEST_CRASH_AT", "SECURE_CODE_TEST_PAUSE_AT", "SECURE_CODE_TEST_FAIL_AT")
RESULTS: list[dict] = []


# ---------------------------------------------------------------- CLI helpers
def env_with(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in HOOKS}
    env.update(extra)
    return env


def _parse(args: tuple[str, ...], stdout: str):
    try:
        return json.loads(stdout) if "--json" in args else None
    except json.JSONDecodeError:
        return None


def sc(*args: str, env: dict[str, str] | None = None):
    proc = subprocess.run(["uvx", "--from", str(SCRIPTS), "secure-code", *args], capture_output=True,
                          text=True, env=env or env_with(), stdin=subprocess.DEVNULL, timeout=600)
    return proc.returncode, _parse(args, proc.stdout), proc.stdout, proc.stderr


def spawn(*args: str, env: dict[str, str] | None = None) -> tuple[subprocess.Popen, tuple[str, ...]]:
    proc = subprocess.Popen(["uvx", "--from", str(SCRIPTS), "secure-code", *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env or env_with(), stdin=subprocess.DEVNULL)
    return proc, args


def finish(spawned: tuple[subprocess.Popen, tuple[str, ...]]):
    proc, args = spawned
    out, err = proc.communicate(timeout=300)
    return proc.returncode, _parse(args, out), out, err


def wait_file(path: Path, timeout: float = 90) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if path.exists():
            return True
        time.sleep(0.05)
    return False


def sc_pty(answers: list[tuple[bytes, str]], *args: str) -> tuple[int, str]:
    """Run under a pseudo-terminal; answer each (prompt marker, text) in order."""
    import pty

    cmd = ["uvx", "--from", str(SCRIPTS), "secure-code", *args]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, env_with())
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
        import traceback

        detail = {"status": "Fail", "error": f"{type(exc).__name__}: {exc}",
                  "where": traceback.format_exc().strip().splitlines()[-3:]}
    RESULTS.append({"tc": tc, "acs": acs, **detail})
    print(json.dumps(RESULTS[-1]), flush=True)


def tree(root: Path, prefixes: tuple[str, ...] = (), skip: tuple[str, ...] = ()) -> dict[str, str]:
    """Every entry (no links followed): directory, link text, file SHA-256 or special kind."""
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if prefixes and not any(rel == x or rel.startswith(x + "/") for x in prefixes):
                continue
            if any(rel == x or rel.startswith(x + "/") for x in skip):
                continue
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode):
                out[rel] = "link:" + os.readlink(full)
            elif stat.S_ISDIR(info.st_mode):
                out[rel] = "dir"
            elif stat.S_ISREG(info.st_mode):
                out[rel] = hashlib.sha256(full.read_bytes()).hexdigest()
            else:
                out[rel] = f"special:{oct(info.st_mode)}"
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
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def rjson(p: Path, rel: str) -> dict:
    return json.loads((p / rel).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- knowledge / Policy fixtures
def item(rule: str, body: str | None = None, **over) -> dict:
    ns, ver, rid = rule.split("/")
    data = {"namespace": ns, "version": ver, "rule_id": rid, "content": body or f"Rule {rid} body.\n",
            "source_location": f"https://example.org/{rid}"}
    data.update(over)
    return data


R89_ITEM = dict(examples={"general": "Use bound parameters.\n", "python": "cur.execute(q, (x,))\n"},
                applicability=["python"], relations=[R79, R89], source_document_digest=DOC)


def must(res, what: str) -> dict:
    code, out, _, err = res
    assert code == 0, (what, out, err[-400:])
    return out


def new_project(prefix: str = "fat-d-") -> Path:
    root = work_dir(prefix) / "proj ü"
    root.mkdir()
    must(sc("init", "--project", str(root), "--env", "github-copilot", "--json"), "init")
    (root / "src").mkdir()
    (root / "src" / "login.py").write_text("def login(u):\n    return '<p>' + u\n")
    (root / "src" / "util.py").write_text("def helper():\n    return 1\n")
    (root / "README.md").write_text("# readme\n")
    return root


def imp(p: Path, *items: dict, accept: tuple[str, ...] = ()):
    doc = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": list(items)}
    extra = [x for a in accept for x in ("--accept-update", a)]
    return sc("knowledge", "import", "--project", str(p), "--batch", jfile(p, doc), *extra, "--json")


def resolve(p: Path, *rules: str, all_: bool = False):
    args = ["policy", "resolve", "--project", str(p), "--json"]
    args += ["--all"] if all_ else [x for r in rules for x in ("--rule", r)]
    return sc(*args)


def entry(out: dict, requested: str) -> dict:
    return next(e for e in out["data"]["entries"] if e["requested"] == requested)


def decisions_doc(out: dict, adopted: tuple[str, ...], skipped: dict[str, str] | None = None,
                  mode: str = "clues") -> dict:
    items = [{"ref": r, "decision": "adopted", "state_digest": entry(out, r)["source_evidence"]["state_digest"]}
             for r in adopted]
    items += [{"ref": r, "decision": "not_adopted", "reason": why} for r, why in (skipped or {}).items()]
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": mode,
           "proposal_digest": out["data"]["proposal_digest"], "clues": "login change",
           "language_context": ["python"], "decisions": items, "confirmation_note": "user confirmed"}
    if mode == "clues":
        doc["considered"] = [e["requested"] for e in out["data"]["entries"]]
    return doc


def save(p: Path, doc: dict, env: dict | None = None):
    return sc("scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed", "--json",
              env=env)


def save_scope(p: Path, rules: tuple[str, ...]) -> str:
    out = must(resolve(p, *rules), "resolve")
    return must(save(p, decisions_doc(out, rules)), "scope save")["data"]["scope_id"]


def scope_show(p: Path, sid: str):
    return sc("scope", "show", "--project", str(p), "--scope", sid, "--json")


def kupdate(p: Path, rule: str, base: str, env: dict | None = None, **changes):
    doc = {"schema": "ai-secure-code-toolkit/knowledge-update/v1", **changes}
    return sc("knowledge", "update", "--project", str(p), "--rule", rule, "--base-state", base,
              "--input", jfile(p, doc), "--json", env=env)


def kshow(p: Path, rule: str):
    return sc("knowledge", "show", "--project", str(p), "--rule", rule, "--json")


def klist(p: Path):
    return sc("knowledge", "list", "--project", str(p), "--json")


def links(p: Path, json_: bool = True):
    return sc("knowledge", "links", "--project", str(p), *(["--json"] if json_ else []))


def kcheck(p: Path, *docs: str) -> dict[str, str]:
    doc = {"schema": "ai-secure-code-toolkit/knowledge-check/v1", "items": [], "source_documents": list(docs)}
    return must(sc("knowledge", "check", "--project", str(p), "--input", jfile(p, doc), "--json"),
                "check")["data"]["source_documents"]


def exit_args(cmd: str, p: Path, rule: str, action: str, to: str | None, reason: str | None,
              digest: str | None, json_: bool) -> list[str]:
    args = ["knowledge", cmd, "--project", str(p), "--rule", rule, "--action", action]
    if to is not None:
        args += ["--to", to]
    if reason is not None:
        args += ["--reason", reason]
    if digest is not None:
        args += ["--impact-digest", digest]
    return args + (["--json"] if json_ else [])


def preview(p: Path, rule: str, action: str, to: str | None = None, reason: str | None = REASON,
            json_: bool = True, env: dict | None = None):
    return sc(*exit_args("exit-preview", p, rule, action, to, reason, None, json_), env=env)


def confirm(p: Path, rule: str, action: str, digest: str | None, to: str | None = None,
            reason: str | None = REASON, json_: bool = True, env: dict | None = None):
    return sc(*exit_args("exit-confirm", p, rule, action, to, reason, digest, json_), env=env)


def do_exit(p: Path, rule: str, action: str, to: str | None = None, reason: str = REASON) -> tuple[dict, dict]:
    pv = must(preview(p, rule, action, to, reason), f"preview {action}")
    cf = must(confirm(p, rule, action, pv["data"]["impact_digest"], to, reason), f"confirm {action}")
    return pv, cf


def item_digest(p: Path, rule: str) -> str:
    return next(r["item_digest"] for r in must(klist(p), "list")["data"]["rules"] if r["rule"] == rule)


def make_pending(p: Path, rule: str, **over) -> None:
    """Maintainer import of an update holding a credential-shaped line → pending decision for the rule."""
    out = imp(p, item(rule, body=SECRET, **over), accept=(f"{rule}@{item_digest(p, rule)}",))[1]
    assert out["data"]["items"][0]["outcome"] == "needs_decision", out
    assert (p / PENDING / f"{rule}.json").is_file()


# ---------------------------------------------------------------- Guard helpers (copied from 002-A runner)
ATTEMPT = "ai-secure-code-toolkit/guard-attempt/v1"


def _g(p: Path, cmd: str, vid: str | None = None, doc: dict | None = None, *extra: str):
    args = ["guard", cmd, "--project", str(p)]
    if vid:
        args += ["--run", vid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    return sc(*args, *extra, "--json")


def _attempt(p: Path, vid: str, kind: str, covers: dict) -> str:
    code, out, _, _ = _g(p, "attempt", vid, {"schema": ATTEMPT, "kind": kind, "covers": covers})
    assert code == 0, out
    return out["data"]["attempt"]


def guard_open_doc(scope: str) -> dict:
    return {"schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope,
            "targets": [{"path": "src/login.py", "change": "modified"}], "context": [{"path": "README.md"}]}


GPLAN = {"schema": "ai-secure-code-toolkit/guard-plan/v1",
         "checks": [{"id": "C1", "rule": R79, "object": ["src/login.py"],
                     "methods": [{"name": "semantic-review", "kind": "reading", "required": True}],
                     "minimum_evidence": ["reading"]}],
         "not_applicable": [{"rule": R89, "reason": "no database access in the target"}]}


def guard_open_reviewed(p: Path, scope: str) -> str:
    """open → plan → record → review (left open, like a verification in progress)."""
    code, out, _, err = _g(p, "open", doc=guard_open_doc(scope))
    assert code == 0, (out, err)
    vid = out["data"]["verification_id"]
    digests = {t["path"]: t["digest"] for t in out["data"]["targets"]}
    assert _g(p, "plan", vid, GPLAN)[0] == 0
    att = _attempt(p, vid, "semantic_review", {"pairs": [{"check": "C1", "method": "semantic-review"}]})
    record = {"schema": "ai-secure-code-toolkit/guard-record/v1", "attempt": att,
              "evidence": [{"id": "E1", "kind": "reading", "method": "semantic-review", "method_status": "ok",
                            "checks": ["C1"], "paths": ["src/login.py"], "summary": "read login()"}],
              "ledger": [{"check": "C1", "state": "met", "evidence": ["E1"]}]}
    code, out, _, _ = _g(p, "record", vid, record)
    assert code == 0, out
    att2 = _attempt(p, vid, "reviewer", {"findings": [], "na": [f"policy:{R89}"]})
    review = {"schema": "ai-secure-code-toolkit/reviewer-record/v1", "attempt": att2,
              "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
              "requirement": "Re-check N/A decisions",
              "reviewed_targets": [{"path": "src/login.py", "digest": digests["src/login.py"]}],
              "subjects": [{"type": "na_decision", "id": f"policy:{R89}", "result": "confirmed",
                            "basis": "no SQL"}]}
    code, out, _, _ = _g(p, "review", vid, review)
    assert code == 0, out
    return vid


def guard_conclude(p: Path, vid: str):
    return _g(p, "conclude", vid)


def policy_changed(out: dict, rule: str) -> bool:
    return any(r["code"] == "POLICY_CHANGED" and r["subject"] == rule for r in out["data"]["reasons"])


# ---------------------------------------------------------------- Copilot helpers (copied from 003-A runner)
S_OPEN = "ai-secure-code-toolkit/copilot-open/v1"
S_SUG = "ai-secure-code-toolkit/copilot-suggest/v1"
S_REV = "ai-secure-code-toolkit/reviewer-record/v1"


def cp(p: Path, cmd: str, cid: str | None = None, doc: dict | None = None):
    args = ["copilot", cmd, "--project", str(p)]
    if cid:
        args += ["--id", cid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    return sc(*args, "--json")


def copilot_open_doc(scope: str) -> dict:
    return {"schema": S_OPEN, "scope_id": scope, "stage": "implementation", "task": "Harden the login page",
            "artifacts": [{"path": "src/login.py", "change": "modified"}]}


def copilot_reported(p: Path, scope: str) -> str:
    """open → suggest (S1 on CWE-89, S2 on CWE-79) → Reviewer record → report r1; stays open."""
    code, out, _, err = cp(p, "open", doc=copilot_open_doc(scope))
    assert code == 0, (out, err)
    cid = out["data"]["collaboration_id"]
    sugs = [{"id": sid, "rule": rule, "files": ["src/login.py"], "location": f"location of {sid}",
             "action": f"concrete action for {sid}", "reason": f"reason for {sid}", "severity": "high"}
            for sid, rule in (("S1", R89), ("S2", R79))]
    assert cp(p, "suggest", cid, {"schema": S_SUG, "suggestions": sugs})[0] == 0
    review = {"schema": S_REV,
              "invocation": {"host": "github-copilot", "agent": "copilot-reviewer", "read_only": True,
                             "invoked_at": now_z()},
              "requirement": "Check in the formed artifact whether the listed suggestions were adopted",
              "reviewed_targets": [{"path": "src/login.py", "digest": fdig(p, "src/login.py")}],
              "subjects": [{"type": "adoption", "id": s, "result": "adopted", "basis": f"login() handles {s}"}
                           for s in ("S1", "S2")],
              "reviewed_at": now_z()}
    code, out, _, _ = cp(p, "review", cid, review)
    assert code == 0, out
    code, out, _, _ = cp(p, "report", cid)
    assert code == 0, out
    return cid


def suggestion_state(report: dict, sid: str) -> str:
    return next(s["state"] for s in report["suggestions"] if s["id"] == sid)


def adopted_now(report: dict, rule: str) -> str:
    return {a["rule"]: a["now"] for a in report["scope"]["adopted"]}[rule]


def rich_project(guard_open: int = 1) -> dict:
    """CWE-20 and CWE-89 (self) relate to CWE-89; a confirmed scope adopts CWE-79 and CWE-89; a concluded
    Guard verification and a Copilot round r1 exist (historical reports); `guard_open` Guard verifications
    and one Copilot collaboration stay open; CWE-89 has a pending decision and a document-index edge."""
    p = new_project()
    must(imp(p, item(R79), item(R89, **R89_ITEM), item(R20, relations=[R89], source_document_digest=DOC)),
         "import")
    sid = save_scope(p, (R79, R89))
    g0 = guard_open_reviewed(p, sid)
    code, out, _, err = guard_conclude(p, g0)
    assert code == 0, (out, err)
    gopen = [guard_open_reviewed(p, sid) for _ in range(guard_open)]
    cid = copilot_reported(p, sid)
    make_pending(p, R89, **{k: v for k, v in R89_ITEM.items() if k != "source_document_digest"})
    return {"p": p, "sid": sid, "g0": g0, "gopen": gopen, "cid": cid}


def deps(p: Path) -> dict[str, str]:
    """Other rules, scope records, Guard/Copilot run states and every report (AC-001D-01a, 04f)."""
    return tree(p, prefixes=(f"{LOCAL}/{R79}", f"{LOCAL}/{R20}", SCOPES, GUARD, COLLAB, REPORTS))


def historical(p: Path) -> dict[str, str]:
    return tree(p, prefixes=(SCOPES, REPORTS))


def rule_files(p: Path, rule: str) -> dict[str, bytes]:
    d = p / LOCAL / rule
    return {f.name: f.read_bytes() for f in sorted(d.iterdir()) if f.is_file()} if d.is_dir() else {}


# ---------------------------------------------------------------- shared checks
def impact_checks(label: str, pv: dict, f: dict, *, pending: bool = True, edge: bool = True) -> list:
    d = pv["data"]
    imp_ = d["impact"]
    return [
        (f"02a {label}: preview ok, impact is the first key, contract keys",
         list(d)[0] == "impact" and set(d) - {"recovered_exit"} == PREVIEW_KEYS),
        (f"02a {label}: incoming relations listed with identifiers (CWE-20, self-relation of CWE-89)",
         imp_["relations"]["items"] == [{"source": R20, "self": False}, {"source": R89, "self": True}]),
        (f"02a {label}: adopted scope record listed with id",
         [i["scope_id"] for i in imp_["scopes"]["items"]] == [f["sid"]]),
        (f"02a {label}: open Guard verifications listed (the concluded one is not)",
         sorted(i["verification_id"] for i in imp_["guard_runs"]["items"]) == sorted(f["gopen"])
         and f["g0"] not in json.dumps(imp_["guard_runs"])),
        (f"02a {label}: open Copilot collaboration listed",
         [i["collaboration_id"] for i in imp_["copilot_collaborations"]["items"]] == [f["cid"]]),
        (f"02a {label}: pending decision listed",
         [i["rule"] for i in imp_["pending_decisions"]["items"]] == ([R89] if pending else [])),
        (f"02a {label}: document-index entry listed",
         [(i["document"], i["edge"]) for i in imp_["document_index"]["items"]] == [(DOC, edge)]),
        (f"02a {label}: counts equal listed items",
         all(imp_[k]["count"] == len(imp_[k]["items"]) for k in KINDS)),
        (f"02b {label}: Presets, tags, Reference cache 'not checked in this version' (never empty)",
         all(imp_[k] == NOT_CHECKED for k in UNSUPPORTED)),
        (f"02a {label}: impact digest, references_block false, effects stated",
         bool(DIG.fullmatch(d["impact_digest"])) and d["references_block"] is False
         and any("no other rule, scope record, run or report is changed" in w for w in d["will"])),
        (f"02a {label}: exact preview contract values (action, rule, target, reason, rule_state)",
         d["action"] == label and d["rule"] == R89 and d["reason"] == REASON
         and d["target"] == (R89SQL if label == "rename" else None)
         and {"consistent", "state", "revision", "state_digest", "fingerprint"} <= set(d["rule_state"])
         and d["rule_state"]["consistent"] is True
         and d["rule_state"]["state"] == ("deactivated" if label == "reactivate" else "active")
         and isinstance(d["will"], list) and len(d["will"]) >= 2),
        (f"02a {label}: exact pending item and provider shape",
         [i["rule"] for i in imp_["pending_decisions"]["items"]] == ([R89] if pending else [])
         and all(set(imp_[k]) >= {"count", "items"} and isinstance(imp_[k]["items"], list) for k in KINDS)),
    ]


def after_exit_checks(label: str, f: dict, reason: str, renamed_to: str | None, hist0: dict) -> list:
    """Resolve, scope load, links, show of the relating rule, open runs, unchanged history (04a/c/e/f)."""
    p, sid = f["p"], f["sid"]
    _, res, rtext, _ = resolve(p, R89)
    e = entry(res, R89)
    _, sc_out, _, _ = scope_show(p, sid)
    by = {x["rule"]: x for x in sc_out["data"]["entries"]}
    _, lk, _, _ = links(p)
    broken = [b for b in lk["data"]["broken_relations"] if b["target"] == R89]
    _, s20, _, _ = kshow(p, R20)
    checks = [
        (f"04a {label}: explicit reference missing with reason, no content, nothing substituted",
         e["availability"] == "missing" and e["reason"] == reason and e.get("renamed_to") == renamed_to
         and "requirement" not in e and "source_evidence" not in e and e.get("rule") in (None, R89)
         and "Rule CWE-89 body" not in rtext),
        (f"04c {label}: scope load → CWE-89 missing with the same reason; status partial",
         by[R89]["adoption"] == "missing" and by[R89]["reason"] == reason
         and by[R89].get("renamed_to") == renamed_to and sc_out["data"]["status"] == "partial"
         and sc_out["data"]["adopted_rules"] == [R79]),
        (f"04e {label}: links reports CWE-20 → CWE-89 with reason (read-only)",
         lk["ok"] and any(b["source"] == R20 and b["reason"] == reason and b.get("renamed_to") == renamed_to
                          for b in broken)),
        (f"04e {label}: links lists the scope adopting the exited rule",
         any(s["scope_id"] == sid and s["rule"] == R89 and s["reason"] == reason for s in lk["data"]["scopes"])),
        (f"04e {label}: show CWE-20 marks the broken relation; its relations unchanged",
         any(b["target"] == R89 and b["reason"] == reason for b in s20["data"]["broken_relations"])
         and s20["data"]["record"]["relations"] == [R89]),
    ]
    code, gout, _, err = guard_conclude(p, f["gopen"][0])
    gres = rjson(p, f"{GREPORTS}/{f['gopen'][0]}.json")
    code2, cout, _, _ = cp(p, "report", f["cid"])
    r = rjson(p, f"{CREPORTS}/{f['cid']}-r{cout['data']['round']}.json")
    checks += [
        (f"04f {label}: open Guard verification reports the Policy change at conclusion",
         code == 0 and gout["data"]["verdict"] != "pass" and policy_changed(gout, R89)
         and any(r_["code"] == "POLICY_CHANGED" and r_["subject"] == R89 for r_ in gres["reasons"])),
        (f"04f {label}: open Copilot collaboration reports policy_changed for the CWE-89 suggestion",
         code2 == 0 and suggestion_state(r, "S1") == "policy_changed" and suggestion_state(r, "S2") == "adopted"
         and adopted_now(r, R89) == "missing"),
        (f"04f {label}: earlier Guard/Copilot reports (MD + JSON) and the scope record byte-identical",
         all(historical(p).get(k) == v for k, v in hist0.items())),
    ]
    return checks


# ---------------------------------------------------------------- TC-D-01 rename (specification scenario)
def tc_rename_scenario():
    f = rich_project()
    p = f["p"]
    doc_before = kcheck(p, DOC)[DOC]
    all0, deps0, hist0 = tree(p), deps(p), historical(p)
    files0 = rule_files(p, R89)
    rec0 = json.loads(files0["record.json"])
    pend0 = (p / PENDING / f"{R89}.json").is_file()
    code, pv, _, _ = preview(p, R89, "rename", to=R89SQL)
    all1 = tree(p)
    time.sleep(1.2)
    cc, cf, ctext, cerr = confirm(p, R89, "rename", pv["data"]["impact_digest"], to=R89SQL)
    deps1 = deps(p)
    files1 = rule_files(p, R89SQL)
    rec1 = json.loads(files1.get("record.json", b"{}"))
    diff = {k for k in set(rec0) | set(rec1) if rec0.get(k) != rec1.get(k)}
    memory = rjson(p, f"{EXITS}/memory.json")["exited"]
    _, lst, _, _ = klist(p)
    _, old, _, _ = kshow(p, R89)
    _, new, _, _ = kshow(p, R89SQL)
    log0, log1 = files0["changelog.md"].decode(), files1.get("changelog.md", b"").decode()
    d = cf["data"] if cf else {}
    checks = [("setup: document fully stored and pending decision held before the exit",
               doc_before == "fully_stored" and pend0)]
    checks += impact_checks("rename", pv, f)
    checks += [
        ("02a rename: will names the target, pending removal, index invalidation and reservation",
         any(R89SQL in w and "move" in w for w in pv["data"]["will"])
         and any("remove 1 pending" in w for w in pv["data"]["will"])
         and any("invalidate 1 index" in w for w in pv["data"]["will"])
         and any(f"reserve {R89} as renamed to {R89SQL}" in w for w in pv["data"]["will"])),
        ("02a rename: preview wrote nothing (whole project incl. private files and locks)", all0 == all1),
        ("01a rename performed although a rule relates to it and a scope adopts it",
         code == 0 and cc == 0 and d.get("outcome") == "renamed"),
        ("02a confirm contract: rule, target, exit id, revision, state digest, removed pending, invalidated "
         "index, no tombstone, committed impact = previewed impact",
         set(d) - {"recovered_exit"} == CONFIRM_KEYS and d["rule"] == R89 and d["target"] == R89SQL
         and bool(EXIT_ID.fullmatch(d["exit_id"])) and d["lifecycle_revision"] == 1
         and bool(DIG.fullmatch(d["state_digest"])) and d["removed_pending"] == [R89]
         and d["invalidated_index"] == [DOC] and d["tombstone"] is None
         and d["impact"] == pv["data"]["impact"]),
        ("01a/04f no other rule, scope record, Guard/Copilot run or report modified", deps0 == deps1),
        ("03d rule exists only under the new ID", not (p / LOCAL / R89).exists() and bool(files1)),
        ("03d content and examples byte-identical",
         {k: v for k, v in files0.items() if k not in ("record.json", "changelog.md")}
         == {k: v for k, v in files1.items() if k not in ("record.json", "changelog.md")}
         and "content.md" in files1 and sum(k.startswith("example") for k in files1) == 2),
        ("03d record differs only in rule_id, item_digest, updated_at, lifecycle",
         diff == {"rule_id", "item_digest", "updated_at", "lifecycle"} and rec1["rule_id"] == "CWE-89-SQL"
         and rec1["lifecycle"] == {"state": "active", "revision": 1}
         and all(rec1[k] == rec0[k] for k in ("name", "applicability", "source_location", "source_documents",
                                                  "relations", "created_at") if k in rec0)),
        ("03d relation to its old ID kept and reported broken `renamed`",
         rec1["relations"] == [R79, R89] and any(
             b["target"] == R89 and b["reason"] == "renamed" and b.get("renamed_to") == R89SQL
             for b in new["data"]["broken_relations"])),
        ("03d changelog kept and records old and new ID, time and reason",
         log1.startswith(log0) and "renamed" in log1[len(log0):] and R89 in log1[len(log0):]
         and R89SQL in log1[len(log0):] and REASON in log1[len(log0):]
         and bool(TIME.search(log1[len(log0):]))),
        ("03d state digest = confirm result; old ID remembered as renamed to the new ID",
         new["data"]["state_digest"] == d.get("state_digest")
         and any(m["rule"] == R89 and m["action"] == "renamed" and m["renamed_to"] == R89SQL for m in memory)
         and old["problems"][0]["code"] == "RULE_NOT_FOUND"
         and old["data"]["exited"]["renamed_to"] == R89SQL),
        ("03f rename: pending decision removed, index invalidated, document no longer fully stored",
         not (p / PENDING / f"{R89}.json").exists() and kcheck(p, DOC)[DOC] == "not_fully_stored"
         and R89 not in json.dumps(rjson(p, INDEX)[DOC]["items"]) and R89 in rjson(p, INDEX)[DOC]["failed"]),
        ("05d list marks the renamed identity as exited with reason and time; new ID listed active",
         any(x["rule"] == R89 and x["action"] == "renamed" and x["renamed_to"] == R89SQL
             and x["reason"] == REASON and TIME.fullmatch(x["at"] or "") for x in lst["data"]["exited"])
         and any(r["rule"] == R89SQL and r["state"] == "active" for r in lst["data"]["rules"])),
    ]
    checks += after_exit_checks("renamed", f, "renamed", R89SQL, hist0)
    _, _, ltext, _ = links(p, json_=False)
    checks.append(("text: links output lists the broken relation with reason (no repair)",
                   ltext.startswith("knowledge links: OK") and "renamed" in ltext and R20 in ltext
                   and "separate, explicit" in ltext))
    return checks


# ---------------------------------------------------------------- TC-D-02 deactivate → reactivate
def tc_deactivate_reactivate():
    f = rich_project(guard_open=2)
    p = f["p"]
    all0, deps0, hist0 = tree(p), deps(p), historical(p)
    files0 = rule_files(p, R89)
    pend0 = (p / PENDING / f"{R89}.json").read_bytes()
    sd0 = must(kshow(p, R89), "show")["data"]["state_digest"]
    code, pv, _, _ = preview(p, R89, "deactivate")
    all1 = tree(p)
    cc, cf, _, _ = confirm(p, R89, "deactivate", pv["data"]["impact_digest"])
    deps1 = deps(p)
    files1 = rule_files(p, R89)
    _, sh1, _, _ = kshow(p, R89)
    _, lst, _, _ = klist(p)
    log0, log1 = files0["changelog.md"].decode(), files1["changelog.md"].decode()
    d = cf["data"]
    checks = impact_checks("deactivate", pv, f)
    checks += [
        ("02a deactivate: preview wrote nothing", all0 == all1),
        ("02a deactivate: will keeps pending, invalidates index, records changelog/revision",
         any("keep 1 pending" in w for w in pv["data"]["will"])
         and any("invalidate 1 index" in w for w in pv["data"]["will"])
         and any("lifecycle revision 0 → 1" in w for w in pv["data"]["will"])),
        ("01a deactivation performed although referenced", code == 0 and cc == 0 and d["outcome"] == "deactivated"),
        ("01a/04f no other rule, scope record, run or report modified", deps0 == deps1),
        ("03a rule stays stored with content and examples; changelog kept",
         {k: v for k, v in files0.items() if k not in ("record.json", "changelog.md")}
         == {k: v for k, v in files1.items() if k not in ("record.json", "changelog.md")}
         and log1.startswith(log0)),
        ("03a marked deactivated; changelog records action, time and reason",
         sh1["data"]["state"] == "deactivated" and sh1["data"]["lifecycle_revision"] == 1
         and json.loads(files1["record.json"])["lifecycle"] == {"state": "deactivated", "revision": 1}
         and "deactivated" in log1[len(log0):] and REASON in log1[len(log0):]
         and bool(TIME.search(log1[len(log0):]))),
        ("03a rule state revision changes", sh1["data"]["state_digest"] != sd0
         and sh1["data"]["state_digest"] == d["state_digest"]),
        ("03f deactivate: pending decision kept, index entry invalidated, document not fully stored",
         (p / PENDING / f"{R89}.json").read_bytes() == pend0 and d["removed_pending"] == []
         and d["invalidated_index"] == [DOC] and kcheck(p, DOC)[DOC] == "not_fully_stored"),
        ("05d list marks the rule deactivated", any(r["rule"] == R89 and r["state"] == "deactivated"
                                                    for r in lst["data"]["rules"])),
    ]
    c2, again, _, _ = preview(p, R89, "deactivate")
    checks.append(("03b/edge: deactivating a deactivated rule refused (no change)",
                   c2 == 1 and code_of(again) == "ACTION_NOT_APPLICABLE"))
    checks += after_exit_checks("deactivated", f, "deactivated", None, hist0)
    # reactivation (the second open Guard verification and the Copilot collaboration see the cycle)
    deps2, all2 = deps(p), tree(p)
    rc, rpv, _, _ = preview(p, R89, "reactivate")
    all3 = tree(p)
    imp_ = rpv["data"]["impact"]
    rcc, rcf, _, _ = confirm(p, R89, "reactivate", rpv["data"]["impact_digest"])
    _, sh2, _, _ = kshow(p, R89)
    files2 = rule_files(p, R89)
    log2 = files2["changelog.md"].decode()
    _, res, _, _ = resolve(p, R89)
    checks += [
        ("02a reactivate: preview lists relations, scope, open Guard/Copilot runs, pending, index (failed label)",
         rc == 0 and [i["source"] for i in imp_["relations"]["items"]] == [R20, R89]
         and [i["scope_id"] for i in imp_["scopes"]["items"]] == [f["sid"]]
         and [i["verification_id"] for i in imp_["guard_runs"]["items"]] == [f["gopen"][1]]
         and [i["collaboration_id"] for i in imp_["copilot_collaborations"]["items"]] == [f["cid"]]
         and imp_["pending_decisions"]["count"] == 1
         and [(i["document"], i["edge"]) for i in imp_["document_index"]["items"]] == [(DOC, False)]
         and all(imp_[k] == NOT_CHECKED for k in UNSUPPORTED) and all2 == all3),
        *impact_checks("reactivate", rpv, {**f, "gopen": [f["gopen"][1]]}, edge=False),
        ("03b reactivation confirmed: usable again", rcc == 0 and rcf["data"]["outcome"] == "reactivated"
         and entry(res, R89)["availability"] == "available" and sh2["data"]["state"] == "active"),
        ("03b changelog records the reactivation", log2.startswith(log1) and "reactivated" in log2[len(log1):]
         and REASON in log2[len(log1):]),
        ("03b state revision changes again, never back to the pre-deactivation value",
         sh2["data"]["lifecycle_revision"] == 2 and sh2["data"]["state_digest"] not in (sd0, d["state_digest"])),
        ("01a/04f reactivation modified no other rule, scope record, run or report", deps(p) == deps2),
    ]
    c3, act, _, _ = preview(p, R89, "reactivate")
    checks.append(("03b reactivating an active rule refused", c3 == 1 and code_of(act) == "ACTION_NOT_APPLICABLE"))
    c4, sc4, _, _ = scope_show(p, f["sid"])
    e = next(x for x in sc4["data"]["entries"] if x["rule"] == R89)
    checks.append(("04d deactivate→reactivate (unchanged content): needs_reconfirmation, partial, next step "
                   "to re-confirm; record byte-identical",
                   e["adoption"] == "needs_reconfirmation" and sc4["data"]["status"] == "partial"
                   and "confirm" in step_of(sc4).lower() and c4 == 0
                   and all(historical(p).get(k) == v for k, v in hist0.items())))
    code, gout, _, _ = guard_conclude(p, f["gopen"][1])
    code2, cout, _, _ = cp(p, "report", f["cid"])
    r = rjson(p, f"{CREPORTS}/{f['cid']}-r{cout['data']['round']}.json")
    checks += [
        ("04f cycle: Guard verification opened before deactivation reports the Policy change after reactivation",
         code == 0 and gout["data"]["verdict"] != "pass" and policy_changed(gout, R89)),
        ("04f cycle: Copilot keeps policy_changed and the rule is `changed`, not `missing`",
         code2 == 0 and suggestion_state(r, "S1") == "policy_changed" and adopted_now(r, R89) == "changed"),
        ("04f cycle: all earlier reports and the scope record still byte-identical",
         all(historical(p).get(k) == v for k, v in hist0.items())),
    ]
    return checks


# ---------------------------------------------------------------- TC-D-03 delete
def tc_delete():
    f = rich_project()
    p = f["p"]
    all0, deps0, hist0 = tree(p), deps(p), historical(p)
    files0 = rule_files(p, R89)
    code, pv, _, _ = preview(p, R89, "delete")
    all1 = tree(p)
    cc, cf, _, _ = confirm(p, R89, "delete", pv["data"]["impact_digest"])
    d = cf["data"]
    tomb = p / (d.get("tombstone") or "missing")
    rec = rjson(p, f"{d.get('tombstone')}/exit-record.json") if (tomb / "exit-record.json").is_file() else {}
    tfiles = {x.name: x.read_bytes() for x in sorted((tomb / "rule").iterdir())} if (tomb / "rule").is_dir() else {}
    memory = rjson(p, f"{EXITS}/memory.json")["exited"]
    _, lst, _, _ = klist(p)
    _, shown, _, _ = kshow(p, R89)
    checks = impact_checks("delete", pv, f)
    checks += [
        ("02a delete: preview wrote nothing", all0 == all1),
        ("02a delete: will states tombstone move, pending removal, reservation, index invalidation",
         any("tombstone" in w for w in pv["data"]["will"]) and any("remove 1 pending" in w for w in pv["data"]["will"])
         and any(f"reserve {R89} as deleted" in w for w in pv["data"]["will"])),
        ("01a deletion performed although referenced", code == 0 and cc == 0 and d["outcome"] == "deleted"
         and d["state_digest"] is None and str(d["tombstone"]).startswith(f"{EXITS}/tombstones/")),
        ("01a/04f no other rule, scope record, run or report modified", deps0 == deps(p)),
        ("03c rule no longer in formal Local knowledge", not (p / LOCAL / R89).exists()
         and all(r["rule"] != R89 for r in lst["data"]["rules"])),
        ("03c tombstone holds last record, content, examples and full changelog (bytes)", tfiles == files0),
        ("03c exit record: action, time, reason (and consistency, counts, removed pending, index)",
         rec.get("action") == "delete" and rec.get("rule") == R89 and rec.get("reason") == REASON
         and bool(TIME.fullmatch(rec.get("at") or "")) and rec.get("consistent") is True
         and rec.get("exit_id") == d["exit_id"] and rec.get("removed_pending") == [R89]
         and rec.get("invalidated_index") == [DOC] and rec.get("impact_counts", {}).get("relations") == 2),
        ("NFR-1 tombstone private: owner-only folder and exit record",
         stat.S_IMODE(os.stat(p / EXITS).st_mode) == 0o700
         and stat.S_IMODE(os.stat(tomb / "exit-record.json").st_mode) == 0o600),
        ("03c identity reserved in exit memory", any(m["rule"] == R89 and m["action"] == "deleted" for m in memory)),
        ("03f delete: pending removed and reported, index invalidated, document not fully stored",
         not (p / PENDING / f"{R89}.json").exists() and d["removed_pending"] == [R89]
         and d["invalidated_index"] == [DOC] and kcheck(p, DOC)[DOC] == "not_fully_stored"),
        ("05d list shows the deleted identity as exited with reason and time; show → RULE_NOT_FOUND + exited",
         any(x["rule"] == R89 and x["action"] == "deleted" and x["reason"] == REASON and TIME.fullmatch(x["at"])
             for x in lst["data"]["exited"])
         and code_of(shown) == "RULE_NOT_FOUND" and shown["data"]["exited"]["action"] == "deleted"),
    ]
    checks += after_exit_checks("deleted", f, "deleted", None, hist0)
    return checks


# ---------------------------------------------------------------- TC-D-04 dependency-free rule, text output
def tc_dependency_free():
    p = new_project()
    must(imp(p, item("CWE/4.14/CWE-5")), "import")
    r5 = "CWE/4.14/CWE-5"
    all0 = tree(p)
    code, pv, _, _ = preview(p, r5, "delete")
    tcode, _, text, _ = preview(p, r5, "delete", json_=False)
    imp_ = pv["data"]["impact"]
    c1, o1, _, _ = confirm(p, r5, "delete", None)
    all1 = tree(p)
    lines = text.splitlines()
    tc_, _, ctext, _ = confirm(p, r5, "deactivate", must(preview(p, r5, "deactivate"), "pv")["data"]["impact_digest"],
                                json_=False)
    return [
        ("02e every supported impact list explicitly empty", code == 0
         and all(imp_[k]["count"] == 0 and imp_[k]["items"] == [] for k in KINDS)),
        ("02b unsupported kinds stated as not checked, never empty", all(imp_[k] == NOT_CHECKED for k in UNSUPPORTED)),
        ("02e the action still needs the confirmation step (no digest → refused, rule unchanged)",
         c1 == 1 and code_of(o1) == "IMPACT_DIGEST_REQUIRED" and "exit-preview" in step_of(o1)
         and all0 == all1 and (p / LOCAL / r5).is_dir()),
        ("text: impact leads the preview, grouped by kind with counts; empty lists '(none)'; unsupported "
         "'not checked in this version'",
         tcode == 0 and lines[0] == "knowledge exit-preview: OK" and lines[1] == "impact:"
         and "    count: 0" in lines and any(x.strip() == "(none)" for x in lines)
         and f"  presets: {NOT_CHECKED}" in lines and f"  tags: {NOT_CHECKED}" in lines
         and f"  reference_cache: {NOT_CHECKED}" in lines and any(x.startswith("impact_digest: sha256:")
                                                                  for x in lines)),
        ("text: confirm output (envelope without --json)", tc_ == 0
         and ctext.startswith("knowledge exit-confirm: OK") and "outcome: deactivated" in ctext),
    ]


# ---------------------------------------------------------------- TC-D-05 stale impact
def base_project() -> Path:
    p = new_project()
    must(imp(p, item(R79), item(R89, **R89_ITEM), item(R20, relations=[R89], source_document_digest=DOC)),
         "import")
    return p


def tc_stale_impact():
    base = base_project()
    out = must(resolve(base, R79, R89), "resolve")
    sdoc = decisions_doc(out, (R79, R89))
    pend_over = {k: v for k, v in R89_ITEM.items() if k != "source_document_digest"}
    deltas = [
        ("rule changed (knowledge update)", "deactivate",
         lambda p: must(kupdate(p, R89, item_digest(p, R89), content="Changed body.\n"), "update")),
        ("relation to it added (new rule)", "delete",
         lambda p: must(imp(p, item("CWE/4.14/CWE-22", relations=[R89])), "import")),
        ("relation to it removed (CWE-20 updated)", "rename",
         lambda p: must(kupdate(p, R20, item_digest(p, R20), relations=[]), "update")),
        ("scope adopting it saved", "deactivate", lambda p: must(save(p, sdoc), "save")),
        ("pending decision created", "delete", lambda p: make_pending(p, R89, **pend_over)),
        ("index entry changed (same item from another document)", "rename",
         lambda p: must(imp(p, item(R89, **{**R89_ITEM, "source_document_digest": DOC2})), "import")),
    ]
    checks = []
    for label, action, change in deltas:
        p = work_dir("fat-d-stale-") / "proj ü"
        shutil.copytree(base, p, symlinks=True)
        to = R89SQL if action == "rename" else None
        pv = must(preview(p, R89, action, to), "preview")
        change(p)
        before = tree(p)
        c, o, _, _ = confirm(p, R89, action, pv["data"]["impact_digest"], to)
        after = tree(p)
        fresh = must(preview(p, R89, action, to), "fresh preview")["data"]
        provider_delta = label.startswith("rule changed") or o["data"].get("impact") != pv["data"]["impact"]
        checks.append((f"02c {label} ({action}) → STALE_IMPACT with the new impact; nothing changed",
                       c == 1 and code_of(o) == "STALE_IMPACT" and o["data"].get("impact") == fresh["impact"]
                       and "impact_digest" not in o["data"] and fresh["impact_digest"] != pv["data"]["impact_digest"]
                       and provider_delta and before == after and "preview" in step_of(o).lower()))
    return checks


# ---------------------------------------------------------------- TC-D-06 digest binding
def tc_digest_binding():
    p = base_project()
    pv = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    pr = must(preview(p, R89, "rename", to=R89SQL), "preview")["data"]["impact_digest"]
    all0 = tree(p)
    cases = [
        ("no digest", confirm(p, R89, "deactivate", None), "IMPACT_DIGEST_REQUIRED"),
        ("malformed digest", confirm(p, R89, "deactivate", "abc"), "IMPACT_DIGEST_REQUIRED"),
        ("digest of another rule", confirm(p, R79, "deactivate", pv), "STALE_IMPACT"),
        ("digest of another action", confirm(p, R89, "delete", pv), "STALE_IMPACT"),
        ("digest of another reason", confirm(p, R89, "deactivate", pv, reason="Another reason"), "STALE_IMPACT"),
        ("digest of another rename target", confirm(p, R89, "rename", pr, to="CWE/4.14/CWE-89-OTHER"),
         "STALE_IMPACT"),
        ("rule that does not exist", confirm(p, "CWE/4.14/CWE-404", "deactivate", pv), "RULE_NOT_FOUND"),
    ]
    checks = [(f"02d {label} → {want} with reason and next step to preview", c == 1 and code_of(o) == want
               and bool(msg_of(o)) and "preview" in step_of(o).lower()) for label, (c, o, _, _), want in cases]
    checks.append(("02d nothing changed by any refused confirmation", tree(p) == all0))
    return checks


# ---------------------------------------------------------------- TC-D-07 rename target refusals
def tc_rename_targets():
    p = new_project()
    rules = ["CWE/4.14/CWE-22", "CWE/4.14/CWE-77", "CWE/4.14/CWE-78"]
    must(imp(p, item(R89), item(R79), *[item(r) for r in rules]), "import")
    do_exit(p, "CWE/4.14/CWE-22", "deactivate")
    do_exit(p, "CWE/4.14/CWE-77", "delete")
    do_exit(p, "CWE/4.14/CWE-78", "rename", to="CWE/4.14/CWE-78-X")
    make_pending(p, R89)
    good = must(preview(p, R89, "rename", to=R89SQL), "preview")["data"]["impact_digest"]
    must(imp(p, item("CWE/4.14/CWE-90"), item("CWE/4.14/CWE-91")), "import")
    # a pending decision for a would-be target identity (new identity held as needs_decision)
    out = imp(p, item("CWE/4.14/CWE-91-P", body=SECRET))[1]
    assert out["data"]["items"][0]["outcome"] == "needs_decision", out
    targets = [
        ("existing active ID", R79, {"RENAME_TARGET_EXISTS"}),
        ("existing deactivated ID", "CWE/4.14/CWE-22", {"RENAME_TARGET_EXISTS"}),
        ("deleted identity", "CWE/4.14/CWE-77", {"IDENTITY_RESERVED"}),
        ("renamed-away identity", "CWE/4.14/CWE-78", {"IDENTITY_RESERVED"}),
        ("case variant of an active ID", "CWE/4.14/cwe-79", {"IDENTITY_COLLISION"}),
        ("case variant of a deactivated ID", "CWE/4.14/cwe-22", {"IDENTITY_COLLISION"}),
        ("case variant of a deleted identity", "CWE/4.14/cwe-77", {"IDENTITY_RESERVED"}),
        ("case variant of a renamed-away identity", "CWE/4.14/cwe-78", {"IDENTITY_RESERVED"}),
        ("another namespace", "CAPEC/4.14/CWE-89-SQL", {"RENAME_TARGET_INVALID"}),
        ("another source version", "CWE/4.13/CWE-89-SQL", {"RENAME_TARGET_INVALID"}),
        ("invalid ID", "CWE/4.14/bad id!", {"IDENTITY_INVALID"}),
        ("the same ID", R89, {"RENAME_TARGET_INVALID"}),
        ("only letter case of itself", "CWE/4.14/cwe-89", {"IDENTITY_COLLISION"}),
        ("identity held as a pending decision", "CWE/4.14/CWE-91-P", {"RENAME_TARGET_EXISTS"}),
    ]
    all0 = tree(p)
    checks = []
    for label, target, want in targets:
        c1, o1, _, _ = preview(p, R89, "rename", to=target)
        c2, o2, _, _ = confirm(p, R89, "rename", good, to=target)
        checks.append((f"03e rename to {label} ({target}) refused in preview and confirm with reason "
                       f"{sorted(want)}", c1 == 1 and c2 == 1 and code_of(o1) in want and code_of(o2) in want
                       and bool(msg_of(o1)) and bool(step_of(o1))))
    checks.append(("03e nothing changed by any refusal", tree(p) == all0))
    return checks


# ---------------------------------------------------------------- TC-D-08 reasons
def tc_reasons():
    p = base_project()
    good = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    all0 = tree(p)
    cases = [
        ("preview without reason", preview(p, R89, "deactivate", reason=None), {"REASON_REQUIRED"}),
        ("confirm without reason", confirm(p, R89, "deactivate", good, reason=None), {"REASON_REQUIRED"}),
        ("confirm with blank reason", confirm(p, R89, "deactivate", good, reason="   "), {"REASON_REQUIRED"}),
        ("confirm with empty reason", confirm(p, R89, "deactivate", good, reason=""), {"REASON_REQUIRED"}),
        ("confirm with multi-line reason", confirm(p, R89, "deactivate", good, reason="a\nb"), {"REASON_INVALID"}),
    ]
    checks = [(f"03g {label} → refused {sorted(w)}", c == 1 and code_of(o) in w and bool(step_of(o)))
              for label, (c, o, _, _), w in cases]
    checks.append(("03g nothing changed", tree(p) == all0))
    return checks


# ---------------------------------------------------------------- TC-D-09 inconsistent / unreadable rules
def tc_inconsistent():
    p = base_project()
    canary = p.parent / "canary.txt"
    canary.write_text("outside canary\n")
    canary_hash = hashlib.sha256(canary.read_bytes()).hexdigest()
    d89, d79 = p / LOCAL / R89, p / LOCAL / R79
    (d89 / "content.md").write_text("tampered by hand\n")
    (d79 / "content.md").write_bytes(b"\xff\xfe not utf-8")
    checks = []
    for rule, label in ((R89, "inconsistent"), (R79, "unreadable")):
        for action, to in (("deactivate", None), ("reactivate", None), ("rename", f"{rule}-NEW")):
            c, o, _, _ = preview(p, rule, action, to)
            checks.append((f"03h {label} rule: {action} preview refused with restore-or-delete next step",
                           c == 1 and code_of(o) == "RULE_INCONSISTENT" and "restore" in step_of(o).lower()
                           and "delete" in step_of(o).lower() and "version control" in step_of(o).lower()))
    os.symlink(canary, d89 / "link-to-outside")
    (d89 / ".content.md.tmp-123").write_text("atomic residue\n")
    c1, pv1, _, _ = preview(p, R89, "delete")
    (d89 / ".content.md.tmp-123").write_text("atomic residue changed\n")
    c2, pv2, _, _ = preview(p, R89, "delete")
    found = tree(p, prefixes=(f"{LOCAL}/{R89}",))
    cs, stale, _, _ = confirm(p, R89, "delete", pv1["data"]["impact_digest"])
    cc, cf, _, _ = confirm(p, R89, "delete", pv2["data"]["impact_digest"])
    tomb = cf["data"]["tombstone"] if cc == 0 else "missing"
    moved = {k.replace(f"{tomb}/rule", f"{LOCAL}/{R89}"): v for k, v in tree(p, prefixes=(f"{tomb}/rule",)).items()}
    rec = rjson(p, f"{tomb}/exit-record.json") if cc == 0 else {}
    cu, pu, _, _ = preview(p, R79, "delete")
    cuc, cuf, _, _ = confirm(p, R79, "delete", pu["data"]["impact_digest"])
    utomb = p / (cuf["data"].get("tombstone") or "missing") / "rule" / "content.md"
    checks += [
        ("03h delete preview allowed; digest binds the folder as found (consistent false, fingerprint)",
         c1 == 0 and pv1["data"]["rule_state"]["consistent"] is False
         and bool(DIG.fullmatch(pv1["data"]["rule_state"]["fingerprint"]))),
        ("03h residue change alters the digest; the earlier digest is refused as stale",
         c2 == 0 and pv2["data"]["impact_digest"] != pv1["data"]["impact_digest"] and cs == 1
         and code_of(stale) == "STALE_IMPACT"),
        ("03h after confirmation the files are moved to the tombstone as found (link not followed)",
         cc == 0 and moved == found and not (p / LOCAL / R89).exists()
         and os.readlink(p / tomb / "rule" / "link-to-outside") == str(canary)),
        ("03h exit record states that the rule was inconsistent", rec.get("consistent") is False
         and rec.get("folder_fingerprint") == pv2["data"]["rule_state"]["fingerprint"]),
        ("NFR-1 outside canary unchanged", hashlib.sha256(canary.read_bytes()).hexdigest() == canary_hash),
        ("03h unreadable (non-UTF-8) rule deleted as found", cu == 0 and cuc == 0
         and utomb.read_bytes() == b"\xff\xfe not utf-8"),
    ]
    return checks


# ---------------------------------------------------------------- TC-D-10 resolve explicit / all / version-less
def tc_resolve_reasons():
    p = new_project()
    r1, r2, r3, r4, r4n = (f"CWE/4.14/CWE-{n}" for n in ("1", "2", "3", "4", "4-NEW"))
    old79, r77 = "CWE/4.13/CWE-79", "CWE/4.14/CWE-77"
    must(imp(p, *[item(r) for r in (r1, r2, r3, r4, R79, old79, r77)]), "import")
    do_exit(p, r2, "deactivate")
    do_exit(p, r3, "delete")
    do_exit(p, r4, "rename", to=r4n)
    do_exit(p, R79, "delete")
    do_exit(p, r77, "delete")
    _, ex, text, _ = resolve(p, r2, r3, r4, R79)
    e2, e3, e4, e79 = (entry(ex, r) for r in (r2, r3, r4, R79))
    ca, al, _, _ = resolve(p, all_=True)
    _, vl, _, _ = resolve(p, "CWE/CWE-79", "CWE/CWE-77")
    v79, v77 = entry(vl, "CWE/CWE-79"), entry(vl, "CWE/CWE-77")
    q = new_project()
    must(imp(q, item(r1)), "import")
    do_exit(q, r1, "deactivate")
    cq, aq, _, _ = resolve(q, all_=True)
    return [
        ("04a deactivated / deleted / renamed explicit references missing with the reason",
         [(e["availability"], e["reason"]) for e in (e2, e3, e4, e79)]
         == [("missing", "deactivated"), ("missing", "deleted"), ("missing", "renamed"), ("missing", "deleted")]),
        ("04a renamed carries the new ID as information only; no content or source evidence returned",
         e4.get("renamed_to") == r4n and all("requirement" not in e and "source_evidence" not in e
                                             for e in (e2, e3, e4, e79))
         and "Rule CWE-4 body" not in text),
        ("04a the new ID's rule and another stored version are never returned in place",
         all(e.get("rule") in (None, e["requested"]) for e in (e2, e3, e4, e79))
         and "candidates" not in e79 and old79 not in json.dumps(e79)),
        ("04b all: only active formal rules resolved", ca == 0
         and sorted(e["requested"] for e in al["data"]["entries"]) == sorted([r1, r4n, old79])),
        ("04b deactivated and exited identities are separate informational counts",
         al["data"]["inactive"] == {"deactivated": 1, "deleted": 3, "renamed": 1}
         and al["data"]["status"] == "complete" and al["data"]["counts"]["missing"] == 0),
        ("04a/v1.2 version-less ref with a remaining version resolves as before and lists the exited identity",
         v79["availability"] == "available" and v79["rule"] == old79
         and v79.get("exited") == [{"rule": R79, "reason": "deleted", "renamed_to": None}]),
        ("04a/v1.2 version-less ref with no stored version: missing with the exit reason and exited info",
         v77["availability"] == "missing" and v77["reason"] == "deleted"
         and [x["rule"] for x in v77.get("exited", [])] == [r77]),
        ("04b all rules deactivated → maintenance needed with reactivate/import next step",
         cq == 1 and aq["data"]["status"] == "maintenance_needed" and "reactivate" in step_of(aq).lower()
         and aq["data"]["inactive"]["deactivated"] == 1),
    ]


# ---------------------------------------------------------------- TC-D-11 use after exit
def tc_use_after_exit():
    p = new_project()
    r22, r30, r31, r77, r78, r78x = (f"CWE/4.14/CWE-{n}" for n in ("22", "30", "31", "77", "78", "78-X"))
    must(imp(p, item(R89), item(r22), item(r77), item(r78)), "import")
    pre = item_digest(p, R89)
    do_exit(p, R89, "deactivate")
    do_exit(p, r77, "delete")
    do_exit(p, r78, "rename", to=r78x)
    sd = must(kshow(p, R89), "show")["data"]["state_digest"]
    before_stale = tree(p)
    cs, stale, _, _ = kupdate(p, R89, pre, content="Prepared before the deactivation.\n")
    after_stale = tree(p)
    cu, upd, _, _ = kupdate(p, R89, sd, content="Updated while deactivated.\n")
    _, sh, _, _ = kshow(p, R89)
    exits0 = tree(p, prefixes=(EXITS,))
    cb, b, _, _ = imp(p, item(R89, body="Re-import.\n"), item(r30))
    items_b = {i["rule"]: i for i in b["data"]["items"]}
    cr, r, _, _ = imp(p, item(r77), item(r78), item(r31))
    cv, v, _, _ = imp(p, item("CWE/4.14/cwe-77"), item("CWE/4.14/cwe-78"), item("CWE/4.14/CWE-32"))
    items_r = r["data"]["items"][:2] + v["data"]["items"][:2] + [r["data"]["items"][2], v["data"]["items"][2]]
    exits1 = tree(p, prefixes=(EXITS,))
    _, lst, _, _ = klist(p)
    rules = {x["rule"]: x for x in lst["data"]["rules"]}
    ex = {x["rule"]: x for x in lst["data"]["exited"]}
    _, s77, _, _ = kshow(p, r77)
    return [
        ("05a update with the base state of the deactivated revision recorded; rule stays deactivated",
         cu == 0 and sh["data"]["state"] == "deactivated" and sh["data"]["content"] == "Updated while deactivated.\n"
         and "Updated while deactivated" in sh["data"]["changelog"]),
        ("06b/05a update whose base predates the deactivation refused as stale; nothing written",
         cs == 1 and code_of(stale) == "STATE_CONFLICT" and before_stale == after_stale),
        ("05b import item of a deactivated identity refused with the next step to reactivate first",
         cb == 1 and items_b[R89]["outcome"] == "refused" and items_b[R89]["code"] == "RULE_DEACTIVATED"
         and any("reactivate" in s.lower() and R89 in s for s in b["next_steps"])),
        ("05b other items follow the partial-import rules", items_b[r30]["outcome"] == "stored"
         and r30 in rules),
        ("05c deleted / renamed-away identities and their case variants refused as reserved",
         [(i["outcome"], i.get("code")) for i in items_r[:4]] == [("refused", "IDENTITY_RESERVED")] * 4),
        ("05c tombstone and exit memory unchanged; other items stored (partial import)", exits0 == exits1
         and items_r[4]["outcome"] == "stored" and items_r[5]["outcome"] == "stored" and cr == 1 and cv == 1),
        ("05d list marks deactivated rules", rules[R89]["state"] == "deactivated"
         and rules[r22]["state"] == "active" and rules[r78x]["state"] == "active"),
        ("05d deleted and renamed identities listed separately as exited with reason and time",
         ex[r77]["action"] == "deleted" and ex[r78]["action"] == "renamed" and ex[r78]["renamed_to"] == r78x
         and all(ex[x]["reason"] == REASON and TIME.fullmatch(ex[x]["at"]) for x in (r77, r78))
         and r77 not in rules and r78 not in rules),
        ("05d show of an exited identity: RULE_NOT_FOUND with exit reason and time",
         code_of(s77) == "RULE_NOT_FOUND" and s77["data"]["exited"]["reason"] == REASON
         and bool(TIME.fullmatch(s77["data"]["exited"]["at"]))),
    ]


# ---------------------------------------------------------------- TC-D-12 exit / scope-save serialization
def pause_env(tag: Path, point: str) -> dict[str, str]:
    return env_with(SECURE_CODE_TEST_PAUSE_AT=f"{point}={tag}")


def blocked(spawned, seconds: float = 3.0) -> bool:
    """The contender has not finished while the other command holds the lock (no fixed outcome sleep)."""
    time.sleep(seconds)
    return spawned[0].poll() is None


def save_args(p: Path, doc: dict) -> list[str]:
    return ["scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed", "--json"]


def scope_files(p: Path) -> list[str]:
    return sorted(x.name for x in (p / SCOPES).glob("*.json")) if (p / SCOPES).is_dir() else []


def tc_scope_save_race():
    checks = []
    for action, to in (("deactivate", None), ("rename", R89SQL)):
        p = base_project()
        out = must(resolve(p, R79, R89), "resolve")
        doc = decisions_doc(out, (R79,), {R89: "not relevant for this change"})
        do_exit(p, R89, action, to)
        c, o, _, _ = save(p, doc)
        checks.append((f"02f exit ({action}) committed first; the user's decision already marked CWE-89 not "
                       "adopted → scope published with only the confirmed adoption",
                       c == 0 and o["data"]["adopted_rules"] == [R79] and o["data"]["created"] is True
                       and "not relevant for this change" in json.dumps(o["data"]["not_adopted"])
                       and R89SQL not in o["data"]["adopted_rules"]))
    p = base_project()
    out = must(resolve(p, R79, R89), "resolve")
    adopt_both = decisions_doc(out, (R79, R89))
    do_exit(p, R89, "deactivate")
    c, o, _, _ = save(p, adopt_both)
    checks.append(("02f exit committed first, rule adopted in the decision → STALE_CONFIRMATION, no scope",
                   c == 1 and code_of(o) == "STALE_CONFIRMATION" and scope_files(p) == []))
    # process race 1: the confirmation holds the locks; a concurrent scope save waits and re-checks
    p = base_project()
    out = must(resolve(p, R79, R89), "resolve")
    adopt_both = decisions_doc(out, (R79, R89))
    digest = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    tag = p.parent / "exit.pause"
    conf = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, REASON, digest, True),
                 env=pause_env(tag, "exit_locked"))
    ready = wait_file(tag.with_suffix(".ready"))
    sv = spawn(*save_args(p, adopt_both))
    waited = blocked(sv)
    tag.with_suffix(".go").write_text("go\n")
    cc, co, _, _ = finish(conf)
    cs, so, _, _ = finish(sv)
    checks.append(("02f race (exit first): scope save serialized behind the confirmation, then refused "
                   "STALE_CONFIRMATION; no scope published",
                   ready and waited and cc == 0 and co["data"]["outcome"] == "deactivated" and cs == 1
                   and code_of(so) == "STALE_CONFIRMATION" and scope_files(p) == []))
    # process race 2: the scope save holds the knowledge lock; the confirmation waits and is refused as stale
    p = base_project()
    out = must(resolve(p, R79, R89), "resolve")
    adopt_both = decisions_doc(out, (R79, R89))
    digest = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    tag = p.parent / "save.pause"
    sv = spawn(*save_args(p, adopt_both), env=pause_env(tag, "scope_save_locked"))
    ready = wait_file(tag.with_suffix(".ready"))
    conf = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, REASON, digest, True))
    waited = blocked(conf)
    tag.with_suffix(".go").write_text("go\n")
    cs, so, _, _ = finish(sv)
    cc, co, _, _ = finish(conf)
    checks.append(("02f race (save first): confirmation serialized behind the scope save, then STALE_IMPACT "
                   "naming the new scope; rule unchanged",
                   ready and waited and cs == 0 and so["data"]["created"] is True and cc == 1
                   and code_of(co) == "STALE_IMPACT"
                   and [i["scope_id"] for i in co["data"]["impact"]["scopes"]["items"]] == [so["data"]["scope_id"]]
                   and must(kshow(p, R89), "show")["data"]["state"] == "active"))
    # Guard / Copilot opened while the confirmation holds the lock: existing Policy-change handling
    p = base_project()
    sid = save_scope(p, (R79, R89))
    digest = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    tag = p.parent / "open.pause"
    conf = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, REASON, digest, True),
                 env=pause_env(tag, "exit_locked"))
    ready = wait_file(tag.with_suffix(".ready"))
    gop = spawn("guard", "open", "--project", str(p), "--request", jfile(p, guard_open_doc(sid)), "--json")
    cop = spawn("copilot", "open", "--project", str(p), "--request", jfile(p, copilot_open_doc(sid)), "--json")
    waited = blocked(gop) and cop[0].poll() is None
    tag.with_suffix(".go").write_text("go\n")
    cc, co, _, _ = finish(conf)
    cg, go_, _, _ = finish(gop)
    ck, ko, _, _ = finish(cop)
    checks.append(("02f Guard verification and Copilot collaboration opened during the confirmation wait, then "
                   "report the change through their Policy handling (SCOPE_PARTIAL listing CWE-89 missing)",
                   ready and waited and cc == 0 and cg == 1 and code_of(go_) == "SCOPE_PARTIAL"
                   and go_["data"]["missing"] == [R89] and ck == 1 and code_of(ko) == "SCOPE_PARTIAL"
                   and ko["data"]["missing"] == [R89]))
    return checks


# ---------------------------------------------------------------- TC-D-13 crash at every journal step
CRASH_STEPS = {
    "deactivate": ["journal", "record", "changelog", "index", "transitions", "before_journal_delete"],
    "reactivate": ["journal", "record", "changelog", "transitions", "before_journal_delete"],
    "delete": ["journal", "tombstone_dir", "move", "tombstone_record", "pending", "index", "memory",
               "transitions", "before_journal_delete"],
    "rename": ["journal", "record", "changelog", "move", "pending", "index", "memory", "transitions",
               "before_journal_delete"],
}


def crash_point(step: str) -> str:
    return "exit_before_journal_delete" if step == "before_journal_delete" else f"exit_after_{step}"


def crash_template() -> dict:
    t = base_project()
    make_pending(t, R89, **{k: v for k, v in R89_ITEM.items() if k != "source_document_digest"})
    sid = save_scope(t, (R79, R89))
    d79 = decisions_doc(must(resolve(t, R79), "resolve"), (R79,))
    base79 = item_digest(t, R79)
    deact = work_dir("fat-d-tpl-") / "proj ü"
    shutil.copytree(t, deact, symlinks=True)
    do_exit(deact, R89, "deactivate")
    return {"active": t, "deactivated": deact, "sid": sid, "d79": d79, "base79": base79}


def next_commands(t: dict) -> list:
    def raw_check(p):
        doc = {"schema": "ai-secure-code-toolkit/knowledge-check/v1", "items": [], "source_documents": [DOC]}
        return sc("knowledge", "check", "--project", str(p), "--input", jfile(p, doc), "--json")
    return [
        ("import", lambda p: imp(p, item("CWE/4.14/CWE-40"))),
        ("update", lambda p: kupdate(p, R79, t["base79"], content="Next command edit.\n")),
        ("exit-preview", lambda p: preview(p, R79, "deactivate")),
        ("check", raw_check),
        ("list", klist),
        ("show", lambda p: kshow(p, R79)),
        ("links", links),
        ("resolve", lambda p: resolve(p, R79)),
        ("scope save", lambda p: save(p, t["d79"])),
        ("scope show", lambda p: scope_show(p, t["sid"])),
    ]


def exit_temporaries(p: Path) -> list[str]:
    return [k for k in tree(p) if Path(k).name.startswith(".exit-")]


def invariants(p: Path, action: str) -> bool:
    common = not (p / EXITS / "journal.json").exists() and not exit_temporaries(p)
    transitions = rjson(p, f"{EXITS}/transitions.json")["entries"]
    folder = p / LOCAL / R89
    index = rjson(p, INDEX)[DOC]
    invalidated = R89 not in json.dumps(index["items"]) and R89 in index["failed"]
    pending = (p / PENDING / f"{R89}.json").is_file()
    if action in ("deactivate", "reactivate"):
        rec = json.loads((folder / "record.json").read_text())
        log = (folder / "changelog.md").read_text()
        want = {"deactivate": ("deactivated", 1, 1), "reactivate": ("active", 2, 2)}[action]
        shown = must(kshow(p, R89), "show")["data"]
        return (common and rec.get("lifecycle") == {"state": want[0], "revision": want[1]}
                and len(transitions) == want[2] and f"— {action}d" in log and pending and invalidated
                and shown["state"] == want[0] and shown["consistent"] is True
                and kcheck(p, DOC)[DOC] == "not_fully_stored")
    memory = rjson(p, f"{EXITS}/memory.json")["exited"]
    outcome = {"delete": "deleted", "rename": "renamed"}[action]
    gone = (not folder.exists() and not pending and invalidated and len(transitions) == 1
            and [m["action"] for m in memory if m["rule"] == R89] == [outcome]
            and kcheck(p, DOC)[DOC] == "not_fully_stored"
            and code_of(must_refused(kshow(p, R89))) == "RULE_NOT_FOUND")
    if action == "delete":
        tombs = list((p / EXITS / "tombstones").iterdir())
        return (common and gone and len(tombs) == 1 and (tombs[0] / "rule" / "record.json").is_file()
                and (tombs[0] / "exit-record.json").is_file())
    new = p / LOCAL / R89SQL
    rec = json.loads((new / "record.json").read_text())
    return (common and gone and rec["rule_id"] == "CWE-89-SQL" and rec["lifecycle"]["revision"] == 1
            and "— renamed" in (new / "changelog.md").read_text())


def must_refused(res) -> dict:
    return res[1]


def folder_bytes(d: Path) -> dict[str, bytes | str]:
    """Every entry below a folder (no links followed): file bytes, link text or kind."""
    out: dict[str, bytes | str] = {}
    if not d.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(d).as_posix()
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode):
                out[rel] = "link:" + os.readlink(full)
            elif stat.S_ISDIR(info.st_mode):
                out[rel] = "dir"
            elif stat.S_ISREG(info.st_mode):
                out[rel] = full.read_bytes()
            else:
                out[rel] = f"special:{oct(info.st_mode)}"
    return out


def _json_or(p: Path, rel: str, key: str):
    f = p / rel
    return json.loads(f.read_text(encoding="utf-8"))[key] if f.is_file() else None


def pre_exit_state(p: Path, preview_data: dict) -> dict:
    """Complete pre-exit snapshot of the rule and the private state an exit may touch (AC-001D-06a)."""
    pend = p / PENDING / f"{R89}.json"
    return {
        "folder": folder_bytes(p / LOCAL / R89),
        "record": json.loads((p / LOCAL / R89 / "record.json").read_text(encoding="utf-8")),
        "pending": pend.read_bytes() if pend.is_file() else None,
        "index": rjson(p, INDEX),
        "memory": _json_or(p, f"{EXITS}/memory.json", "exited"),
        "transitions": _json_or(p, f"{EXITS}/transitions.json", "entries") or [],
        "rule_state": preview_data["rule_state"],
        "others": tree(p, prefixes=(f"{LOCAL}/{R20}",)),
        "scopes": tree(p, prefixes=(SCOPES,)),
    }


NON_IDENTITY = ("name", "applicability", "source_location", "source_documents", "relations", "created_at",
                "namespace", "version", "schema", "examples", "kind")


def full_invariants(p: Path, action: str, pre: dict) -> list[str]:
    """Byte-level proof that the interrupted exit is fully done; returns the names of failed sub-checks."""
    bad: list[str] = []

    def need(name: str, ok) -> None:
        if not ok:
            bad.append(name)

    need("no journal", not (p / EXITS / "journal.json").exists())
    need("no exit temporaries", not exit_temporaries(p))
    need("CWE-20 rule untouched", tree(p, prefixes=(f"{LOCAL}/{R20}",)) == pre["others"])
    need("earlier scope records untouched",
         all(tree(p, prefixes=(SCOPES,)).get(k) == v for k, v in pre["scopes"].items()))
    trans = _json_or(p, f"{EXITS}/transitions.json", "entries") or []
    need("one transition appended, earlier entries unchanged",
         len(trans) == len(pre["transitions"]) + 1 and trans[:-1] == pre["transitions"])
    last = trans[-1] if trans else {}
    exit_id = last.get("exit_id") or ""
    need("transition entry for this action", last.get("action") == action and last.get("rule") == R89
         and last.get("target") == (R89SQL if action == "rename" else None) and bool(EXIT_ID.fullmatch(exit_id))
         and bool(TIME.fullmatch(last.get("at") or "")) and bool(DIG.fullmatch(last.get("digest") or ""))
         and R89 in (last.get("identities") or {})
         and (action != "rename" or R89SQL in last["identities"]))
    pend = p / PENDING / f"{R89}.json"
    if action in ("deactivate", "reactivate"):
        need("pending decision kept byte-identical", pend.is_file() and pend.read_bytes() == pre["pending"])
    else:
        need("pending decision removed", not pend.exists() and pre["pending"] is not None)
    index = rjson(p, INDEX)
    if action == "reactivate":
        need("index unchanged by reactivation", index == pre["index"])
    else:
        old, new = pre["index"][DOC], index.get(DOC, {})
        need("index edge moved to failed", new.get("items") == [i for i in old["items"] if i["rule"] != R89]
             and sorted(new.get("failed", [])) == sorted(set(old.get("failed", [])) | {R89})
             and new.get("complete") is False
             and {k: v for k, v in index.items() if k != DOC} == {k: v for k, v in pre["index"].items() if k != DOC})
    need("document not fully stored", kcheck(p, DOC)[DOC] == "not_fully_stored")
    memory = _json_or(p, f"{EXITS}/memory.json", "exited")
    log_pre = pre["folder"]["changelog.md"]
    rev = pre["rule_state"]["revision"]
    if action in ("deactivate", "reactivate"):
        need("exit memory unchanged", memory == pre["memory"])
        post = folder_bytes(p / LOCAL / R89)
        need("same file set", set(post) == set(pre["folder"]))
        need("content and examples byte-identical",
             all(post.get(k) == v for k, v in pre["folder"].items() if k not in ("record.json", "changelog.md")))
        rec = json.loads(post.get("record.json", b"{}"))
        diff = {k for k in set(rec) | set(pre["record"]) if rec.get(k) != pre["record"].get(k)}
        state = "deactivated" if action == "deactivate" else "active"
        need("record: only lifecycle (and updated_at) changed", "lifecycle" in diff
             and diff <= {"lifecycle", "updated_at"} and rec.get("lifecycle") == {"state": state, "revision": rev + 1})
        log = post.get("changelog.md", b"")
        tail = log[len(log_pre):].decode("utf-8", "replace")
        need("changelog: earlier history kept, one entry appended", log.startswith(log_pre)
             and tail.startswith("## ") and ("\n" + tail).count("\n## ") == 1 and f"— {action}d" in tail
             and REASON in tail and exit_id in tail)
        shown = must(kshow(p, R89), "show")["data"]
        need("show: consistent with the new state", shown["state"] == state and shown["consistent"] is True
             and shown["lifecycle_revision"] == rev + 1)
        return bad
    need("source folder gone", not (p / LOCAL / R89).exists())
    entries = memory or []
    added = [m for m in entries if m not in (pre["memory"] or [])]
    want_tomb = f"{EXITS}/tombstones/{exit_id}" if action == "delete" else None
    need("exit memory: earlier entries kept, one full entry added",
         len(entries) == len(pre["memory"] or []) + 1 and len(added) == 1
         and added[0].get("rule") == R89
         and added[0].get("action") == {"delete": "deleted", "rename": "renamed"}[action]
         and added[0].get("renamed_to") == (R89SQL if action == "rename" else None)
         and added[0].get("at") == last.get("at") and added[0].get("reason") == REASON
         and added[0].get("exit_id") == exit_id and added[0].get("tombstone") == want_tomb
         and added[0].get("transition") == last.get("digest"))
    need("show of the old ID: RULE_NOT_FOUND with the exit", code_of(kshow(p, R89)[1]) == "RULE_NOT_FOUND")
    if action == "delete":
        tombs = sorted(x.name for x in (p / EXITS / "tombstones").iterdir())
        need("exactly this exit's tombstone", tombs == [exit_id])
        need("tombstoned rule/ equals the pre-exit folder byte for byte",
             folder_bytes(p / EXITS / "tombstones" / exit_id / "rule") == pre["folder"])
        er_file = p / f"{want_tomb}/exit-record.json"
        er = json.loads(er_file.read_text(encoding="utf-8")) if er_file.is_file() else {}
        need("exit record: action, rule, time, reason, last state, revision, binding",
             bool(er) and er.get("action") == "delete" and er.get("rule") == R89 and er.get("reason") == REASON
             and er.get("at") == last.get("at") and er.get("exit_id") == exit_id and er.get("consistent") is True
             and er.get("state_digest") == pre["rule_state"]["state_digest"]
             and er.get("lifecycle_revision") == {"from": rev, "to": rev + 1}
             and er.get("transition") == last.get("digest") and er.get("removed_pending") == [R89]
             and er.get("invalidated_index") == [DOC])
        return bad
    post = folder_bytes(p / LOCAL / R89SQL)
    need("destination: same file set", set(post) == set(pre["folder"]))
    need("destination: content and examples byte-identical",
         all(post.get(k) == v for k, v in pre["folder"].items() if k not in ("record.json", "changelog.md")))
    rec = json.loads(post.get("record.json", b"{}"))
    diff = {k for k in set(rec) | set(pre["record"]) if rec.get(k) != pre["record"].get(k)}
    need("destination record: only rule_id, item_digest, updated_at, lifecycle changed",
         {"rule_id", "item_digest", "lifecycle"} <= diff <= {"rule_id", "item_digest", "updated_at", "lifecycle"}
         and rec.get("rule_id") == "CWE-89-SQL" and rec.get("lifecycle") == {"state": "active", "revision": rev + 1}
         and all(rec.get(k) == pre["record"].get(k) for k in NON_IDENTITY))
    log = post.get("changelog.md", b"")
    tail = log[len(log_pre):].decode("utf-8", "replace")
    need("destination changelog: history kept, one renamed entry (old → new, reason)",
         log.startswith(log_pre) and tail.startswith("## ") and ("\n" + tail).count("\n## ") == 1
         and "— renamed" in tail and R89 in tail
         and R89SQL in tail and REASON in tail and exit_id in tail)
    return bad


def full_check(p: Path, action: str, pre: dict) -> tuple[bool, str]:
    bad = full_invariants(p, action, pre)
    return not bad, (" [failed: " + "; ".join(bad) + "]") if bad else ""


def tc_crash_recovery():
    t = crash_template()
    rotation = next_commands(t)
    checks, n = [], 0
    for action, steps in CRASH_STEPS.items():
        src = t["deactivated"] if action == "reactivate" else t["active"]
        to = R89SQL if action == "rename" else None
        for step in steps:
            p = work_dir("fat-d-crash-") / "proj ü"
            shutil.copytree(src, p, symlinks=True)
            pdata = must(preview(p, R89, action, to), "preview")["data"]
            digest = pdata["impact_digest"]
            pre = pre_exit_state(p, pdata)
            cc, _, cout, _ = confirm(p, R89, action, digest, to,
                                     env=env_with(SECURE_CODE_TEST_CRASH_AT=crash_point(step)))
            journal = (p / EXITS / "journal.json").is_file()
            label, command = rotation[n % len(rotation)]
            n += 1
            code, out, _, err = command(p)
            rec = (out or {}).get("data", {}).get("recovered_exit") or {}
            checks.append((f"06a {action} crash {crash_point(step)} → never success; next `{label}` completes the "
                           "exit; fully exited, consistent state",
                           cc == 86 and cout == "" and journal and "Traceback" not in err
                           and rec.get("outcome") == "completed" and rec.get("rule") == R89
                           and rec.get("action") == action and invariants(p, action)))
            ok, why = full_check(p, action, pre)
            checks.append((f"06a {action} crash {crash_point(step)}: byte-level state equals the fully exited "
                           "pre-exit snapshot (rule files, record, changelog, memory, transition, pending, "
                           f"index){why}",
                           ok))
    # recovery cannot run while another process holds the knowledge lock → LOCKED, never a half state
    import fcntl

    p = work_dir("fat-d-crash-") / "proj ü"
    shutil.copytree(t["active"], p, symlinks=True)
    pdata = must(preview(p, R89, "rename", R89SQL), "preview")["data"]
    digest = pdata["impact_digest"]
    pre = pre_exit_state(p, pdata)
    confirm(p, R89, "rename", digest, R89SQL, env=env_with(SECURE_CODE_TEST_CRASH_AT="exit_after_move"))
    half = tree(p)
    fd = os.open(p / KLOCK, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        cl, lo, _, le = klist(p)
        cr, ro, _, _ = resolve(p, R89)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    held_tree = tree(p)
    c2, o2, _, _ = resolve(p, R89)
    checks.append(("06a recovery cannot take the lock → LOCKED with next step (list and resolve); nothing shown",
                   cl == 1 and code_of(lo) == "LOCKED" and bool(lo["next_steps"]) and "rules" not in lo["data"]
                   and cr == 1 and code_of(ro) == "LOCKED" and "Traceback" not in le and half == held_tree))
    checks.append(("06a after the lock is free the next command completes the exit",
                   o2["data"].get("recovered_exit", {}).get("outcome") == "completed"
                   and entry(o2, R89)["reason"] == "renamed" and invariants(p, "rename")))
    ok, why = full_check(p, "rename", pre)
    checks.append((f"06a LOCKED case after completion: byte-level state equals the fully exited pre-exit snapshot{why}",
                   ok))
    return checks


# ---------------------------------------------------------------- TC-D-14 concurrent knowledge writes
def tc_concurrency():
    checks = []
    p = base_project()
    base = item_digest(p, R89)
    files0 = rule_files(p, R89)
    digest = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    tag = p.parent / "exit.pause"
    conf = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, REASON, digest, True),
                 env=pause_env(tag, "exit_locked"))
    ready = wait_file(tag.with_suffix(".ready"))
    doc = {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": "Concurrent edit.\n"}
    upd = spawn("knowledge", "update", "--project", str(p), "--rule", R89, "--base-state", base,
                "--input", jfile(p, doc), "--json")
    waited = blocked(upd)
    tag.with_suffix(".go").write_text("go\n")
    cc, co, _, _ = finish(conf)
    cu, uo, _, _ = finish(upd)
    shown = must(kshow(p, R89), "show")["data"]
    checks.append(("06b exit + update: serialized; the update (base before the deactivation) is refused as "
                   "stale; nothing half-written",
                   ready and waited and cc == 0 and cu == 1 and code_of(uo) == "STATE_CONFLICT"
                   and shown["state"] == "deactivated" and shown["consistent"] is True
                   and rule_files(p, R89)["content.md"] == files0["content.md"]
                   and not (p / EXITS / "journal.json").exists()))
    p = base_project()
    d1 = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    d2 = must(preview(p, R89, "rename", R89SQL), "preview")["data"]["impact_digest"]
    tag = p.parent / "exit2.pause"
    first = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, REASON, d1, True),
                  env=pause_env(tag, "exit_locked"))
    ready = wait_file(tag.with_suffix(".ready"))
    second = spawn(*exit_args("exit-confirm", p, R89, "rename", R89SQL, REASON, d2, True))
    waited = blocked(second)
    tag.with_suffix(".go").write_text("go\n")
    c1, o1, _, _ = finish(first)
    c2, o2, _, _ = finish(second)
    shown = must(kshow(p, R89), "show")["data"]
    checks.append(("06b two exits: serialized; the second is evaluated against the first (STALE_IMPACT); no "
                   "half state",
                   ready and waited and c1 == 0 and c2 == 1 and code_of(o2) == "STALE_IMPACT"
                   and shown["state"] == "deactivated" and not (p / LOCAL / R89SQL).exists()
                   and not (p / EXITS / "memory.json").exists() and not (p / EXITS / "journal.json").exists()))
    p = base_project()
    do_exit(p, R89, "deactivate")
    deact = must(kshow(p, R89), "show")["data"]["state_digest"]
    do_exit(p, R89, "reactivate")
    before = tree(p)
    cu, uo, _, _ = kupdate(p, R89, deact, content="Prepared while deactivated.\n")
    checks.append(("06b update whose base predates a reactivation refused as stale (base includes revision)",
                   cu == 1 and code_of(uo) == "STATE_CONFLICT" and tree(p) == before))
    return checks


# ---------------------------------------------------------------- TC-D-15 skill package (structured)
def tc_skill_package():
    raw = (FRAMEWORK / "SKILL.md").read_text(encoding="utf-8")
    low = raw.lower()
    start, end = low.index("## exiting knowledge"), low.index("## selecting policies")
    text = " ".join(low[start:end].split())
    contract = (FRAMEWORK / "references" / "cli-contract.md").read_text(encoding="utf-8")
    return [
        ("06c section 'Exiting Knowledge' follows 'Maintaining Knowledge'",
         low.index("## maintaining knowledge") < start < end),
        ("06c preview the impact and show it to the Maintainer before confirming",
         "exit-preview" in text and "show the whole impact to the maintainer first" in text
         and "only after the maintainer explicitly confirms" in text),
        ("06c never confirm on the Maintainer's behalf without a real request",
         "never confirm on the maintainer's behalf" in text and "real request of the maintainer" in text
         and "never on your own initiative" in text),
        ("06c never repair references automatically", "never repair references automatically" in text),
        ("06c state that references do not block the decision", "references do not block the decision" in text),
        ("06c stale impact: preview again and show the new impact",
         "on `stale_impact`, preview again and show the new impact" in text),
        ("CLI contract documents the exit commands", all(x in contract for x in ("exit-preview", "exit-confirm",
                                                                                "knowledge links"))),
    ]


# ---------------------------------------------------------------- TC-D-16 authorization (container, last)
APP = Path.home() / ".config" / "ai-secure-code-toolkit"


def role() -> str:
    return must(sc("auth", "status", "--json"), "auth status")["data"].get("role")


def unauthorized(res) -> bool:
    c, o, _, err = res
    return c == 1 and code_of(o) == "NOT_AUTHORIZED" and bool(o["next_steps"]) and "impact" not in o["data"] \
        and "Traceback" not in err


def tc_authorization():
    p = base_project()
    make_pending(p, R89, **{k: v for k, v in R89_ITEM.items() if k != "source_document_digest"})
    q = base_project()
    digest = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    all0 = tree(p)
    checks = []
    aside = APP.with_name(APP.name + ".aside")
    APP.rename(aside)
    try:
        r_missing = role()
        checks += [("01b missing authorization: preview NOT_AUTHORIZED, no impact, nothing written",
                    r_missing != "maintainer" and unauthorized(preview(p, R89, "deactivate"))),
                   ("01c missing authorization: confirm NOT_AUTHORIZED",
                    unauthorized(confirm(p, R89, "deactivate", digest)))]
    finally:
        aside.rename(APP)
    grant = sorted((APP / "trust" / "grants").glob("*.json"))[0]
    original = grant.read_bytes()
    doc = json.loads(original)
    doc["signature"] = ("A" if doc["signature"][0] != "A" else "B") + doc["signature"][1:]
    grant.write_text(json.dumps(doc))
    try:
        r_invalid = role()
        checks += [("01b invalid authorization: preview NOT_AUTHORIZED, no impact",
                    r_invalid != "maintainer" and unauthorized(preview(p, R89, "deactivate"))),
                   ("01c invalid authorization: confirm NOT_AUTHORIZED",
                    unauthorized(confirm(p, R89, "deactivate", digest)))]
    finally:
        grant.write_bytes(original)
    checks.append(("authorization restored between cases", role() == "maintainer"))
    qd = must(preview(q, R89, "deactivate"), "preview")["data"]["impact_digest"]
    qc = confirm(q, R89, "deactivate", qd, env=env_with(SECURE_CODE_TEST_CRASH_AT="exit_after_record"))[0]
    rc, _ = sc_pty([(b"passphrase", PASS)], "auth", "revoke")
    r_revoked = role()
    checks += [
        ("01c valid at preview, revoked before confirmation → confirm re-verifies and refuses",
         rc == 0 and r_revoked != "maintainer" and unauthorized(confirm(p, R89, "deactivate", digest))),
        ("01b revoked authorization: preview NOT_AUTHORIZED, no impact", unauthorized(preview(p, R89, "deactivate"))),
        ("01b/01c nothing written by the refused requests", tree(p) == all0),
    ]
    res = preview(q, R89, "deactivate")
    shown = must(kshow(q, R89), "show")["data"]
    checks.append(("01b bounded exception: the refused preview first completed an earlier authorized "
                   "interrupted exit (recovered_exit), returning no impact",
                   qc == 86 and unauthorized(res) and res[1]["data"]["recovered_exit"]["outcome"] == "completed"
                   and shown["state"] == "deactivated" and not (q / EXITS / "journal.json").exists()))
    return checks


# ---------------------------------------------------------------- TC-D-17 never-authorized User (host)
def tc_host_user():
    p = new_project()
    all0 = tree(p)
    _, auth, _, _ = sc("auth", "status", "--json")
    pv = preview(p, R89, "deactivate")
    cf = confirm(p, R89, "rename", "sha256:" + "0" * 64, to=R89SQL)
    tc, _, text, _ = preview(p, R89, "deactivate", json_=False)
    cl, lk, _, _ = links(p)
    cs, ls, _, _ = klist(p)
    return [
        ("host role is User (never authorized)", auth["data"].get("role") == "user"),
        ("01b preview refused NOT_AUTHORIZED with next step; no impact data", unauthorized(pv)),
        ("01c confirm refused NOT_AUTHORIZED", unauthorized(cf)),
        ("text: refusal rendered as an envelope (shared authorization header, as for knowledge import)",
         tc == 1 and text.splitlines()[0].endswith(": REFUSED") and "action: knowledge.exit-preview" in text
         and "[NOT_AUTHORIZED]" in text and "Next steps:" in text),
        ("04e links is read-only and needs no authorization", cl == 0 and lk["data"]["broken_relations"] == []
         and lk["data"]["scopes"] == []),
        ("05d list works for the User (no exited identities)", cs == 0 and ls["data"]["exited"] == []),
        ("01b/01c nothing written", tree(p) == all0),
    ]


# ---------------------------------------------------------------- main
def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    only = set(sys.argv[2:])
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(APP, ignore_errors=True)
        assert sc_pty([(b"passphrase", PASS), (b"passphrase", PASS)], "auth", "init")[0] == 0
        plan = [
            ("TC-D-01", ["AC-001D-01a", "AC-001D-02a", "AC-001D-02b", "AC-001D-03d", "AC-001D-03f", "AC-001D-04a",
                         "AC-001D-04c", "AC-001D-04e", "AC-001D-04f", "AC-001D-05d"], tc_rename_scenario),
            ("TC-D-02", ["AC-001D-01a", "AC-001D-02a", "AC-001D-02b", "AC-001D-03a", "AC-001D-03b", "AC-001D-03f",
                         "AC-001D-04a", "AC-001D-04c", "AC-001D-04d", "AC-001D-04e", "AC-001D-04f", "AC-001D-05d"],
             tc_deactivate_reactivate),
            ("TC-D-03", ["AC-001D-01a", "AC-001D-02a", "AC-001D-02b", "AC-001D-03c", "AC-001D-03f", "AC-001D-04a",
                         "AC-001D-04c", "AC-001D-04e", "AC-001D-04f", "AC-001D-05d"], tc_delete),
            ("TC-D-04", ["AC-001D-02b", "AC-001D-02e"], tc_dependency_free),
            ("TC-D-05", ["AC-001D-02c"], tc_stale_impact),
            ("TC-D-06", ["AC-001D-02d"], tc_digest_binding),
            ("TC-D-07", ["AC-001D-03e"], tc_rename_targets),
            ("TC-D-08", ["AC-001D-03g"], tc_reasons),
            ("TC-D-09", ["AC-001D-03h"], tc_inconsistent),
            ("TC-D-10", ["AC-001D-04a", "AC-001D-04b"], tc_resolve_reasons),
            ("TC-D-11", ["AC-001D-05a", "AC-001D-05b", "AC-001D-05c", "AC-001D-05d", "AC-001D-06b"],
             tc_use_after_exit),
            ("TC-D-12", ["AC-001D-02f"], tc_scope_save_race),
            ("TC-D-13", ["AC-001D-06a"], tc_crash_recovery),
            ("TC-D-14", ["AC-001D-06b"], tc_concurrency),
            ("TC-D-15", ["AC-001D-06c"], tc_skill_package),
            ("TC-D-16", ["AC-001D-01b", "AC-001D-01c"], tc_authorization),  # last: revokes the authorization
        ]
    else:
        plan = [("TC-D-17", ["AC-001D-01b", "AC-001D-01c"], tc_host_user),
                ("TC-D-15", ["AC-001D-06c"], tc_skill_package)]
    for tc, acs, fn in plan:
        if not only or tc in only:
            case(tc, acs, fn)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
