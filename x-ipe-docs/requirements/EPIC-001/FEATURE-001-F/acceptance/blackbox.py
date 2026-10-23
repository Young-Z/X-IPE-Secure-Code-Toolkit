"""Black-box acceptance scenarios for FEATURE-001-F Presets & Tags (TASK-070).

Calls the real CLI only: `uvx --from <framework>/scripts secure-code ...`. Never imports toolkit code.
Knowledge, Policy, exit, Guard and Copilot helpers follow the FEATURE-001-C / 001-D / 002-A / 003-A runners.

  python3 blackbox.py host                         # never-authorized User path + skill text (no trust writes)
  FAT_ISOLATED=1 python3 blackbox.py container     # Maintainer-prepared scenarios (disposable HOME only!)

Environment: TOOLKIT_ROOT (toolkit folder), FAT_WORK (folder for disposable projects), PRE001F_SCRIPTS
(container only: `scripts` folder of the reconstructed pre-001-F revision, see run.sh), DESIGN_FILE (host
only: technical-design.md, for the verbatim skill-text comparison).

Fixtures (disclosed):
- Container: owner authorization (`auth init` at a pseudo-terminal), `knowledge import` of placeholder rules
  (CWE/4.14 and ACME/v1 namespaces), `knowledge update`, exits through `exit-preview`/`exit-confirm`.
- Agent role: this runner writes the request/decisions files an agent would write after the user's
  confirmation (`--confirmed` is the user's confirmation flag) and derives recompute candidates itself.
- Hand edits standing in for damaged files: malformed / schema-invalid / deeply nested Preset and tag files,
  symbolic links, an inconsistent rule (edited `content.md`), dot-files.
- Held knowledge lock (02j): this runner holds `flock` on the knowledge lock file.
- Races / interrupted writes use the documented test-only hooks SECURE_CODE_TEST_PAUSE_AT /
  SECURE_CODE_TEST_FAIL_AT, set only on the one CLI subprocess concerned.
- Non-Maintainer User in the container (07a-07d): the trust folder is moved aside and restored.
- Pre-001-F comparison (06e byte identity, 06j, 09a, 04e Apply All): the reconstructed pre-001-F revision
  (current source minus the five 001-F payload files, with the hash-verified originals of the changed files).
"""

from __future__ import annotations

import fcntl
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
PRE = os.environ.get("PRE001F_SCRIPTS")
LOCAL = "x-ipe-docs/secure-code/knowledge/local"
PRESETS = "x-ipe-docs/secure-code/presets"
TAGS = "x-ipe-docs/secure-code/tags"
SCOPES = "x-ipe-docs/secure-code/scopes"
REPORTS = "x-ipe-docs/secure-code/reports"
PRIVATE = ".x-ipe/private/secure-code"
PENDING = f"{PRIVATE}/pending"
LOCKS = f"{PRIVATE}/locks"
KLOCK = f"{LOCKS}/knowledge.lock"
PASS = "acceptance passphrase 42"
R20, R79, R89, R89SQL = "CWE/4.14/CWE-20", "CWE/4.14/CWE-79", "CWE/4.14/CWE-89", "CWE/4.14/CWE-89-SQL"
R89OLD, R798, R352, A1 = "CWE/4.13/CWE-89", "CWE/4.14/CWE-798", "CWE/4.14/CWE-352", "ACME/v1/A-1"
SECRET = 'password = "Zq8vLr2mNp4tXw9yKp"\n'
REASON = "Superseded by a narrower rule"
NOT_CHECKED = "not checked in this version"
PREQ, PREC, TREQ = ("ai-secure-code-toolkit/preset-request/v1", "ai-secure-code-toolkit/preset-recompute/v1",
                    "ai-secure-code-toolkit/tag-request/v1")
PRESET_KEYS = {"applicability_summary", "name", "query_intent", "rules", "schema", "snapshot_at"}
HOOKS = ("SECURE_CODE_TEST_CRASH_AT", "SECURE_CODE_TEST_PAUSE_AT", "SECURE_CODE_TEST_FAIL_AT")
CLAIMS = re.compile(r"tamper|verif|\bbound\b|\bbinds?\b|guarantee", re.I)
MARK_DIR = Path(os.environ.get("FAT_WORK") or tempfile.gettempdir())
MARKERS = [MARK_DIR / f"fat-001f-pwned-{i}" for i in range(4)]
INTENT = (f"injection rules for HTTP input; $(touch {MARKERS[0]}); `touch {MARKERS[1]}`; "
          f"__import__('os').system('touch {MARKERS[2]}'); import subprocess; subprocess.run(['touch', "
          f"'{MARKERS[3]}'])")
APP = Path.home() / ".config" / "ai-secure-code-toolkit"
RESULTS: list[dict] = []
INFO: dict[str, object] = {}


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


def _cmd(args, scripts=None) -> list[str]:
    return ["uvx", "--from", str(scripts or SCRIPTS), "secure-code", *args]


def sc(*args: str, env: dict[str, str] | None = None, scripts: str | None = None):
    proc = subprocess.run(_cmd(args, scripts), capture_output=True, text=True, env=env or env_with(),
                          stdin=subprocess.DEVNULL, timeout=600)
    return proc.returncode, _parse(args, proc.stdout), proc.stdout, proc.stderr


def pre(*args: str):
    return sc(*args, scripts=PRE)


def spawn(*args: str, env: dict[str, str] | None = None, scripts: str | None = None):
    proc = subprocess.Popen(_cmd(args, scripts), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=env or env_with(), stdin=subprocess.DEVNULL)
    return proc, args


def finish(spawned):
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


def pause_env(tag: Path, point: str) -> dict[str, str]:
    return env_with(SECURE_CODE_TEST_PAUSE_AT=f"{point}={tag}")


def blocked(spawned, seconds: float = 3.0) -> bool:
    time.sleep(seconds)
    return spawned[0].poll() is None


def sc_pty(answers: list[tuple[bytes, str]], *args: str) -> tuple[int, str]:
    import pty

    cmd = _cmd(args)
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


def steps(out: dict | None) -> str:
    return " ".join(out.get("next_steps") or []) if out else ""


def refused(res, code: str) -> bool:
    c, o, _, err = res
    return c != 0 and code_of(o) == code and bool(o.get("next_steps")) and "Traceback" not in err


def ok(res) -> bool:
    c, o, _, err = res
    return c == 0 and bool(o) and o.get("ok") is True and "Traceback" not in err


def case(tc: str, acs: list[str], fn) -> None:
    INFO.clear()
    try:
        checks = fn()
        failed = [n for n, good in checks if not good]
        detail = {"status": "Pass" if not failed else "Fail", "checks": [n for n, _ in checks], "failed": failed}
        if failed and INFO:
            detail["info"] = {k: str(v)[:1500] for k, v in INFO.items()}
    except Exception as exc:  # noqa: BLE001 - every unexpected error is a failed case
        import traceback

        detail = {"status": "Fail", "error": f"{type(exc).__name__}: {exc}"[:3000],
                  "where": traceback.format_exc().strip().splitlines()[-4:]}
    RESULTS.append({"tc": tc, "acs": acs, **detail})
    print(json.dumps(RESULTS[-1]), flush=True)


def tree(root: Path, prefixes: tuple[str, ...] = (), skip: tuple[str, ...] = ()) -> dict[str, str]:
    """Every entry (no links followed): directory, link text, file SHA-256 or special kind."""
    out: dict[str, str] = {}
    if not root.exists() and not root.is_symlink():
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


def changed(before: dict[str, str], after: dict[str, str]) -> set[str]:
    return {k for k in set(before) | set(after) if before.get(k) != after.get(k)}


def work_dir(prefix: str) -> Path:
    base = os.environ.get("FAT_WORK")
    if base:
        Path(base).mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base or None))


def jfile(project: Path, doc) -> str:
    path = Path(tempfile.mkstemp(suffix=".json", dir=project.parent)[1])
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc, encoding="utf-8")
    return str(path)


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def must(res, what: str) -> dict:
    code, out, _, err = res
    assert code == 0, (what, out, err[-600:])
    return out


# ---------------------------------------------------------------- knowledge / Policy / exit fixtures
def item(rule: str, body: str | None = None, **over) -> dict:
    ns, ver, rid = rule.split("/")
    data = {"namespace": ns, "version": ver, "rule_id": rid, "content": body or f"Rule {rid} body.\n",
            "source_location": f"https://example.org/{rid}"}
    data.update(over)
    return data


def new_project(prefix: str = "fat-f-") -> Path:
    root = work_dir(prefix) / "proj ü"
    root.mkdir()
    must(sc("init", "--project", str(root), "--env", "github-copilot", "--json"), "init")
    (root / "src").mkdir()
    (root / "src" / "login.py").write_text("def login(u):\n    return '<p>' + u\n")
    (root / "README.md").write_text("# readme\n")
    return root


def imp(p: Path, *items: dict, accept: tuple[str, ...] = ()):
    doc = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": list(items)}
    extra = [x for a in accept for x in ("--accept-update", a)]
    return sc("knowledge", "import", "--project", str(p), "--batch", jfile(p, doc), *extra, "--json")


def base_project(extra: bool = False) -> Path:
    """CWE-20 (relates to CWE-89), CWE-79, CWE-89 and ACME/v1/A-1 (second Local namespace); with `extra`
    also CWE/4.13/CWE-89 (two versions), CWE-352 (made inconsistent by a hand edit) and a pending CWE-798."""
    p = new_project()
    must(imp(p, item(R79), item(R89), item(R20, relations=[R89]), item(A1)), "import")
    if extra:
        must(imp(p, item(R89OLD), item(R352)), "import extra")
        imp(p, item(R798, body=SECRET))
        assert (p / PENDING).is_dir() and any((p / PENDING).iterdir()), "pending decision expected"
        (p / LOCAL / R352 / "content.md").write_text("tampered by hand\n")
    return p


def klist(p: Path):
    return sc("knowledge", "list", "--project", str(p), "--json")


def item_digest(p: Path, rule: str) -> str:
    return next(r["item_digest"] for r in must(klist(p), "list")["data"]["rules"] if r["rule"] == rule)


def kupdate(p: Path, rule: str, content: str):
    doc = {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": content}
    return sc("knowledge", "update", "--project", str(p), "--rule", rule, "--base-state", item_digest(p, rule),
              "--input", jfile(p, doc), "--json")


def kshow(p: Path, rule: str):
    return sc("knowledge", "show", "--project", str(p), "--rule", rule, "--json")


def resolve(p: Path, *rules: str, all_: bool = False, scripts: str | None = None, json_: bool = True):
    args = ["policy", "resolve", "--project", str(p)] + (["--json"] if json_ else [])
    args += ["--all"] if all_ else [x for r in rules for x in ("--rule", r)]
    return sc(*args, scripts=scripts)


def entry(out: dict, requested: str) -> dict:
    return next(e for e in out["data"]["entries"] if e["requested"] == requested)


def decisions(out: dict, clues: str, mode: str = "clues") -> dict:
    items = []
    for e in out["data"]["entries"]:
        if e["availability"] == "available":
            items.append({"ref": e["requested"], "decision": "adopted",
                          "state_digest": e["source_evidence"]["state_digest"]})
        else:
            items.append({"ref": e["requested"], "decision": "not_adopted", "reason": "not available"})
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": mode,
           "proposal_digest": out["data"]["proposal_digest"], "clues": clues, "language_context": [],
           "decisions": items, "confirmation_note": "user confirmed"}
    if mode == "clues":
        doc["considered"] = [e["requested"] for e in out["data"]["entries"]]
    return doc


def scope_save(p: Path, doc: dict, scripts: str | None = None):
    return sc("scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed", "--json",
              scripts=scripts)


def scope_show(p: Path, sid: str):
    return sc("scope", "show", "--project", str(p), "--scope", sid, "--json")


def sfile(scope_id: str) -> str:
    return scope_id.split(":")[-1] + ".json"


def scope_files(p: Path) -> dict[str, str]:
    return tree(p, prefixes=(SCOPES,))


def exit_args(cmd: str, p: Path, rule: str, action: str, to: str | None, digest: str | None,
              json_: bool = True) -> list[str]:
    args = ["knowledge", cmd, "--project", str(p), "--rule", rule, "--action", action, "--reason", REASON]
    if to is not None:
        args += ["--to", to]
    if digest is not None:
        args += ["--impact-digest", digest]
    return args + (["--json"] if json_ else [])


def preview(p: Path, rule: str, action: str, to: str | None = None, json_: bool = True,
            scripts: str | None = None):
    return sc(*exit_args("exit-preview", p, rule, action, to, None, json_), scripts=scripts)


def confirm(p: Path, rule: str, action: str, digest: str | None, to: str | None = None):
    return sc(*exit_args("exit-confirm", p, rule, action, to, digest))


def do_exit(p: Path, rule: str, action: str, to: str | None = None) -> dict:
    pv = must(preview(p, rule, action, to), f"preview {action}")
    return must(confirm(p, rule, action, pv["data"]["impact_digest"], to), f"confirm {action}")


def links(p: Path, json_: bool = True, scripts: str | None = None):
    return sc("knowledge", "links", "--project", str(p), *(["--json"] if json_ else []), scripts=scripts)


def names(impact: dict, kind: str) -> list[str]:
    return [i["name"] for i in impact[kind]["items"]]


# ---------------------------------------------------------------- Preset / tag helpers
def preq(name: str | None, rules=None, qi=None, summ=None, **extra) -> dict:
    doc: dict = {"schema": PREQ}
    if name is not None:
        doc["name"] = name
    if rules is not None:
        doc["rules"] = list(rules)
    if qi is not None:
        doc["query_intent"] = qi
    if summ is not None:
        doc["applicability_summary"] = summ
    doc.update(extra)
    return doc


def psave(p: Path, doc: dict, confirmed: bool = True, env: dict | None = None):
    return sc("preset", "save", "--project", str(p), "--request", jfile(p, doc),
              *(["--confirmed"] if confirmed else []), "--json", env=env)


def pnew(p: Path, name: str, rules, qi=None, summ="Web request handlers") -> dict:
    return must(psave(p, preq(name, rules, qi, summ)), f"preset save {name}")


def pupdate(p: Path, name: str, doc: dict, digest: str | None = "current", confirmed: bool = True):
    digest = pdig(p, name) if digest == "current" else digest
    return sc("preset", "update", name, "--project", str(p), "--request", jfile(p, doc),
              *(["--digest", digest] if digest else []), *(["--confirmed"] if confirmed else []), "--json")


def pdelete(p: Path, name: str, digest: str | None = "current", confirmed: bool = True):
    digest = pdig(p, name) if digest == "current" else digest
    return sc("preset", "delete", name, "--project", str(p), *(["--digest", digest] if digest else []),
              *(["--confirmed"] if confirmed else []), "--json")


def pshow(p: Path, name: str, json_: bool = True):
    return sc("preset", "show", name, "--project", str(p), *(["--json"] if json_ else []))


def plist(p: Path, json_: bool = True):
    return sc("preset", "list", "--project", str(p), *(["--json"] if json_ else []))


def presolve(p: Path, name: str | None, json_: bool = True):
    target = [name] if name else ["--default"]
    return sc("preset", "resolve", *target, "--project", str(p), *(["--json"] if json_ else []))


def precompute(p: Path, name: str, cands, json_: bool = True):
    return sc("preset", "recompute", name, "--project", str(p), "--request",
              jfile(p, {"schema": PREC, "candidates": list(cands)}), *(["--json"] if json_ else []))


def pconfirm(p: Path, name: str, doc: dict, confirmed: bool = True):
    return sc("preset", "recompute-confirm", name, "--project", str(p), "--request", jfile(p, {"schema": PREC, **doc}),
              *(["--confirmed"] if confirmed else []), "--json")


def pscope(p: Path, name: str, doc: dict, confirmed: bool = True):
    return sc("preset", "scope-save", name, "--project", str(p), "--decisions", jfile(p, doc),
              *(["--confirmed"] if confirmed else []), "--json")


def pfile(p: Path, name: str) -> Path:
    return p / PRESETS / f"{name}.json"


def pdig(p: Path, name: str) -> str:
    return sha(pfile(p, name).read_bytes())


def pjson(p: Path, name: str) -> dict:
    return json.loads(pfile(p, name).read_text(encoding="utf-8"))


def prules(p: Path, name: str) -> list[str]:
    return [r["rule"] for r in pjson(p, name)["rules"]]


def treq(name: str | None, members) -> dict:
    doc: dict = {"schema": TREQ, "members": list(members)}
    if name is not None:
        doc["name"] = name
    return doc


def tsave(p: Path, name: str, members, confirmed: bool = True):
    return sc("tag", "save", "--project", str(p), "--request", jfile(p, treq(name, members)),
              *(["--confirmed"] if confirmed else []), "--json")


def tfile(p: Path, name: str) -> Path:
    return p / TAGS / f"{name}.json"


def tdig(p: Path, name: str) -> str:
    return sha(tfile(p, name).read_bytes())


def tupdate(p: Path, name: str, members, digest: str | None = "current", confirmed: bool = True):
    digest = tdig(p, name) if digest == "current" else digest
    return sc("tag", "update", name, "--project", str(p), "--request", jfile(p, treq(None, members)),
              *(["--digest", digest] if digest else []), *(["--confirmed"] if confirmed else []), "--json")


def tdelete(p: Path, name: str, digest: str | None = "current", confirmed: bool = True):
    digest = tdig(p, name) if digest == "current" else digest
    return sc("tag", "delete", name, "--project", str(p), *(["--digest", digest] if digest else []),
              *(["--confirmed"] if confirmed else []), "--json")


def tshow(p: Path, name: str, json_: bool = True):
    return sc("tag", "show", name, "--project", str(p), *(["--json"] if json_ else []))


def tlist(p: Path):
    return sc("tag", "list", "--project", str(p), "--json")


def store_trees(p: Path) -> dict[str, str]:
    return tree(p, prefixes=(PRESETS, TAGS))


def knowledge_trees(p: Path) -> dict[str, str]:
    return tree(p, prefixes=(LOCAL, PENDING))


def lock_listing(p: Path) -> list[str]:
    d = p / LOCKS
    return sorted(x.name for x in d.iterdir()) if d.is_dir() else []


def no_markers() -> bool:
    return not any(m.exists() for m in MARKERS)


def preset_scope(p: Path, name: str) -> tuple[dict, dict]:
    """preset resolve → decisions (generated clue, considered = proposed refs) → preset scope-save."""
    out = must(presolve(p, name), "preset resolve")
    saved = must(pscope(p, name, decisions(out, out["data"]["preset"]["clue"])), "preset scope-save")
    return out, saved


def role() -> str:
    return must(sc("auth", "status", "--json"), "auth status")["data"].get("role")


def unauthorized(res) -> bool:
    c, o, _, err = res
    return c == 1 and code_of(o) == "NOT_AUTHORIZED" and bool(o["next_steps"]) and "Traceback" not in err


# ---------------------------------------------------------------- Guard / Copilot helpers (002-A / 003-A shape)
def guard_open(p: Path, scope: str):
    doc = {"schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope,
           "targets": [{"path": "src/login.py", "change": "modified"}], "context": [{"path": "README.md"}]}
    return sc("guard", "open", "--project", str(p), "--request", jfile(p, doc), "--json")


def copilot_open(p: Path, scope: str):
    doc = {"schema": "ai-secure-code-toolkit/copilot-open/v1", "scope_id": scope, "stage": "implementation",
           "task": "Harden the login page", "artifacts": [{"path": "src/login.py", "change": "modified"}]}
    return sc("copilot", "open", "--project", str(p), "--request", jfile(p, doc), "--json")


# ---------------------------------------------------------------- TC-F-01 save content (01a, 01c, 08b, 02g default)
def canonical(raw: bytes) -> bool:
    return raw == (json.dumps(json.loads(raw), sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def tc_save_content():
    from datetime import datetime

    p = base_project()
    t0 = tree(p)
    start = time.time()
    summ = "Web request handlers in Python services — Überprüfung"
    res = psave(p, preq("web-input", [R89, "CWE/CWE-79", A1], INTENT, summ))
    end = time.time()
    raw = pfile(p, "web-input").read_bytes()
    doc = json.loads(raw)
    snap = datetime.fromisoformat(doc["snapshot_at"])
    listing, chg = sorted(x.name for x in (p / PRESETS).iterdir()), changed(t0, tree(p))
    INFO.update(save=res[1], doc=doc, changed=chg)
    q = base_project()
    must(psave(q, preq("web-input", [A1, R79, "CWE/4.14/CWE-89"], INTENT, summ)), "save q")
    raw_q = pfile(q, "web-input").read_bytes()
    same_but_time = raw_q.replace(json.loads(raw_q)["snapshot_at"].encode(), doc["snapshot_at"].encode()) == raw
    d = must(psave(p, preq("default", [R79])), "save default")
    shown = must(pshow(p, "web-input"), "show")["data"]
    return [
        ("01a confirmed save succeeds", ok(res)),
        ("01a exactly one JSON file for the Preset under presets/ (nothing else written)",
         listing == ["web-input.json"] and chg == {f"{PRESETS}/web-input.json"}),
        ("01a membership = fully qualified concrete references (source kind, namespace/version/rule id; "
         "version-less input stored qualified)",
         doc["rules"] == [{"rule": A1, "source": "local"}, {"rule": R79, "source": "local"},
                          {"rule": R89, "source": "local"}]),
        ("01a no rule content, example or rule state digest stored",
         set(doc) == PRESET_KEYS and all(set(r) == {"rule", "source"} for r in doc["rules"])
         and b"body" not in raw and b"sha256" not in raw and b"example" not in raw),
        ("01c query intent and applicability summary stored exactly as given",
         doc["query_intent"] == INTENT and doc["applicability_summary"] == summ),
        ("01c snapshot_at = confirmation time with timezone offset",
         snap.utcoffset() is not None and start - 2 <= snap.timestamp() <= end + 2
         and res[1]["data"]["snapshot_at"] == doc["snapshot_at"]),
        ("01a result names the path and the file digest of the written bytes",
         res[1]["data"]["path"] == f"{PRESETS}/web-input.json" and res[1]["data"]["file_digest"] == sha(raw)
         and res[1]["data"]["rule_count"] == 3),
        ("08b serialization is canonical (sorted keys, 2-space indent, UTF-8, trailing newline, sorted refs)",
         canonical(raw) and canonical(raw_q) and "Überprüfung".encode() in raw),
        ("08b same content (references given in another order) → identical bytes apart from the snapshot_at "
         "value", same_but_time),
        ("02g identity `default` accepted only as the default Preset and the output says so",
         d["data"].get("becomes_default") is True and "default preset" in json.dumps(d).lower()),
        ("01e/UI show prints snapshot note and query intent marked not run",
         shown["snapshot_note"] == "last confirmed list change; does not freeze rule content"
         and shown["query_intent_note"].startswith("intent text only") and "not run" in shown["query_intent_note"]),
        ("03b intent text with shell/Python code never executed (no marker files)", no_markers()),
    ]


# ---------------------------------------------------------------- TC-F-02 save refusals (01b, 01f, 02b, 02d, 02f, 02g)
def tc_save_refusals():
    p = base_project(extra=True)
    pnew(p, "web", [R79])
    t0 = tree(p)
    checks = []
    for sel in ("injection", "tag:injection", "CWE/*", "CWE/4.14/CWE-79 or CWE-89",
                "preset:web@sha256:" + "a" * 64, "CWE/4.14/CWE-[0-9]*", "CWE/{4.13,4.14}/CWE-89"):
        res = psave(p, preq("dyn", [R79, sel]))
        refs = (res[1] or {}).get("data", {}).get("references", [])
        checks.append((f"01b dynamic selector {sel!r} refused with reason, nothing written",
                       refused(res, "REFERENCES_INVALID") and [r["reason"] for r in refs] == ["dynamic_selector"]
                       and refs[0]["requested"] == sel))
    res = psave(p, preq("mix", [R79, "CWE/4.14/CWE-1", R798, R352, "CWE/CWE-89"]))
    refs = {r["requested"]: r for r in (res[1] or {}).get("data", {}).get("references", [])}
    INFO["mix"] = res[1]
    checks += [
        ("01f each unusable reference listed with its 001-C reason (not_found, pending_decision, inconsistent, "
         "multiple_versions with both candidates); the available one is not listed",
         refused(res, "REFERENCES_INVALID") and {k: v["reason"] for k, v in refs.items()} == {
             "CWE/4.14/CWE-1": "not_found", R798: "pending_decision", R352: "inconsistent",
             "CWE/CWE-89": "multiple_versions"}
         and sorted(c if isinstance(c, str) else c.get("rule") for c in refs["CWE/CWE-89"].get("candidates", []))
         == [R89OLD, R89]),
        ("01f pending content not returned", SECRET.strip() not in res[2]),
    ]
    res = psave(p, preq("refs", ["reference:OWASP/2021/A03"]))
    checks.append(("Reference reference refused invalid_reference until 001-E (with next step)",
                   refused(res, "REFERENCES_INVALID")
                   and res[1]["data"]["references"][0]["reason"] == "invalid_reference"
                   and "001-E" in res[1]["data"]["references"][0].get("detail", "")))
    checks.append(("02f empty membership refused", refused(psave(p, preq("empty", [])), "MEMBERSHIP_EMPTY")))
    checks.append(("02b save without the confirmation flag refused",
                   refused(psave(p, preq("noconf", [R79]), confirmed=False), "CONFIRMATION_REQUIRED")))
    for bad in ("CON", "lpt1", "con", "com9", "nul", "a/b", "a\\b", "My_Preset", "Default", "-web", "web-", "wéb",
                "x" * 65):
        res = psave(p, preq(bad, [R79]))
        checks.append((f"02g Preset identity {bad!r} refused with the reason", refused(res, "IDENTITY_INVALID")
                       and bool(msg(res[1]))))
    for bad in ("default", "Default", "CON", "a/b"):
        checks.append((f"02g tag identity {bad!r} refused", refused(tsave(p, bad, [R79]), "IDENTITY_INVALID")))
    res = psave(p, preq("web", [R89]))
    checks.append(("02d existing identity refused with next step update / another name",
                   refused(res, "PRESET_EXISTS") and "update" in steps(res[1]).lower()
                   and "another name" in steps(res[1]).lower()))
    checks.append(("02b-02g refusals wrote nothing (tree byte-identical)", tree(p) == t0))
    (p / PRESETS / "Shop-List.json").write_text('{"hand": "placed"}\n')
    t1 = tree(p)
    res = psave(p, preq("shop-list", [R79]))
    INFO["case"] = res[1]
    checks.append(("02d/02g identity equal to an existing entry ignoring case refused with next step, nothing "
                   "written", res[0] != 0 and code_of(res[1]) in ("PRESET_EXISTS", "IDENTITY_INVALID")
                   and "update" in steps(res[1]).lower() and tree(p) == t1))
    return checks


def msg(out: dict | None) -> str:
    return out["problems"][0]["message"] if out and out.get("problems") else ""


# ---------------------------------------------------------------- TC-F-03 update / delete (02b, 02c, 02e, 02h, 02i, 01g)
def tc_update_delete():
    from datetime import datetime

    p = base_project()
    pnew(p, "web", [R79, R89], qi="injection rules", summ="Web handlers")
    d0, raw0, t0 = pdig(p, "web"), pfile(p, "web").read_bytes(), tree(p)
    locks0 = lock_listing(p)
    checks = [
        ("02b update without the confirmation flag refused, nothing written",
         refused(pupdate(p, "web", preq(None, [R79], summ="x"), confirmed=False), "CONFIRMATION_REQUIRED")),
        ("02b delete without the confirmation flag refused",
         refused(pdelete(p, "web", confirmed=False), "CONFIRMATION_REQUIRED")),
    ]
    for label, call in (("update without digest", lambda: pupdate(p, "web", preq(None, [R79], summ="x"), None)),
                        ("update with a stale digest",
                         lambda: pupdate(p, "web", preq(None, [R79], summ="x"), "sha256:" + "0" * 64)),
                        ("delete without digest", lambda: pdelete(p, "web", None)),
                        ("delete with a stale digest", lambda: pdelete(p, "web", "sha256:" + "1" * 64))):
        res = call()
        checks.append((f"02h {label} refused STALE_DIGEST with the current digest",
                       refused(res, "STALE_DIGEST") and res[1]["data"].get("current_digest") == d0))
    res = pupdate(p, "web", preq(None, [R79, R89, R20]))
    checks.append(("02i membership change without a new or kept summary refused",
                   refused(res, "SUMMARY_DECISION_REQUIRED")))
    res = pupdate(p, "web", preq(None, [], summ="x"))
    checks.append(("02f update to an empty membership refused", refused(res, "MEMBERSHIP_EMPTY")))
    res = pupdate(p, "web", preq("web-2", qi="x"))
    checks.append(("02c identity change (rename) refused", refused(res, "REQUEST_INVALID")
                   and not pfile(p, "web-2").exists()))
    checks.append(("02b/02h/02i refusals: file and tree byte-identical; no new lock file",
                   pfile(p, "web").read_bytes() == raw0 and tree(p) == t0 and lock_listing(p) == locks0))
    time.sleep(1.2)
    res = pupdate(p, "web", preq(None, [R20, R89], summ="Input validation for handlers"))
    doc1 = pjson(p, "web")
    INFO["upd1"] = res[1]
    checks += [
        ("02c confirmed membership update stores exactly the confirmed membership",
         ok(res) and prules(p, "web") == [R20, R89] and res[1]["data"]["membership_changed"] is True),
        ("02c snapshot_at set to the new confirmation time",
         datetime.fromisoformat(doc1["snapshot_at"]) > datetime.fromisoformat(json.loads(raw0)["snapshot_at"])
         and res[1]["data"]["snapshot_at"] == doc1["snapshot_at"]),
        ("02i new summary stored (summary replaced)", doc1["applicability_summary"] == "Input validation for handlers"
         and res[1]["data"].get("summary") == "replaced"),
        ("02h matching digest → write; result carries previous and new digest",
         res[1]["data"].get("previous_digest") == d0 and res[1]["data"].get("file_digest") == pdig(p, "web")),
    ]
    time.sleep(1.2)
    res = pupdate(p, "web", preq(None, [R79, R89], keep_summary=True))
    doc2 = pjson(p, "web")
    checks.append(("02i explicitly kept summary unchanged and output says kept",
                   ok(res) and doc2["applicability_summary"] == doc1["applicability_summary"]
                   and res[1]["data"].get("summary") == "kept" and doc2["snapshot_at"] != doc1["snapshot_at"]))
    res = pupdate(p, "web", preq(None, qi="changed intent"))
    doc3 = pjson(p, "web")
    res2 = pupdate(p, "web", preq(None, summ="changed summary"))
    doc4 = pjson(p, "web")
    checks.append(("02c query-intent-only / summary-only change: membership and snapshot_at unchanged",
                   ok(res) and ok(res2) and doc3["rules"] == doc2["rules"] == doc4["rules"]
                   and doc2["snapshot_at"] == doc3["snapshot_at"] == doc4["snapshot_at"]
                   and doc3["query_intent"] == "changed intent" and doc4["applicability_summary"] == "changed summary"
                   and res[1]["data"]["membership_changed"] is False))
    shown = must(pshow(p, "web"), "show")["data"]
    checks += [
        ("01g show returns only the current membership and the latest snapshot_at",
         [r["rule"] for r in shown["rules"]] == [R79, R89] and shown["snapshot_at"] == doc4["snapshot_at"]
         and not any(k for k in shown if "history" in k and k != "history_note")),
        ("01g output states no toolkit history (version control is the history; snapshot_at is not a history)",
         "no preset/tag change history" in shown["history_note"].lower()
         and "version control is the history" in shown["history_note"]
         and "snapshot_at is not a history" in shown["history_note"]),
        ("01g no history or backup file written by the toolkit (only the Preset file changed)",
         changed(t0, tree(p)) == {f"{PRESETS}/web.json"} and lock_listing(p) == locks0),
    ]
    out, saved = preset_scope(p, "web")
    sid = saved["data"]["scope_id"]
    rec = scope_files(p)
    res = pdelete(p, "web")
    checks += [
        ("02e confirmed deletion removes the Preset file", ok(res) and not pfile(p, "web").exists()
         and res[1]["data"].get("removed") is True),
        ("02e scope records saved from it byte-identical and still load",
         scope_files(p) == rec and ok(scope_show(p, sid))),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-04 read purity, show (01d, 01e, 03a, 03b)
def tc_reads():
    p = base_project()
    pnew(p, "web", [R79, R89, A1], qi=INTENT, summ="Web handlers")
    raw0, snap0 = pfile(p, "web").read_bytes(), pjson(p, "web")["snapshot_at"]
    t0 = tree(p)
    outs = [plist(p), plist(p, False), pshow(p, "web"), pshow(p, "web", False), presolve(p, "web"),
            presolve(p, "web", False), preview(p, R89, "deactivate"), preview(p, R89, "deactivate", json_=False),
            preview(p, R89, "rename", R89SQL), preview(p, R89, "delete"), links(p), links(p, False)]
    res_out = outs[4][1]
    checks = [
        ("01d list/show/resolve/exit-preview/links all succeed", all(o[0] == 0 for o in outs)),
        ("01d Preset file byte-identical afterwards and snapshot_at unchanged",
         pfile(p, "web").read_bytes() == raw0 and pjson(p, "web")["snapshot_at"] == snap0),
        ("01d/NFR-3 reads wrote nothing in the project", tree(p) == t0),
        ("03a query not evaluated (no marker files) and resolve considers exactly the stored list",
         no_markers() and [e["requested"] for e in res_out["data"]["entries"]] == [A1, R79, R89]
         and res_out["data"]["counts"]["requested"] == 3),
        ("03a query intent shown as text only", res_out["data"]["preset"]["query_intent"] == INTENT
         and "not run" in res_out["data"]["preset"]["query_intent_note"]),
    ]
    before = {r["rule"]: r for r in must(pshow(p, "web"), "show")["data"]["rules"]}
    must(kupdate(p, R89, "Rule CWE-89 body, updated after the snapshot.\n"), "knowledge update")
    shown = must(pshow(p, "web"), "show")["data"]
    after = {r["rule"]: r for r in shown["rules"]}
    _, _, text, _ = pshow(p, "web", False)
    checks += [
        ("01e show states snapshot_at is the last confirmed list change and does not freeze rule content",
         shown["snapshot_note"] == "last confirmed list change; does not freeze rule content"
         and "does not freeze rule content" in text),
        ("01e current availability of each reference shown (updated rule available with its current state)",
         all(r["availability"] == "available" for r in shown["rules"])
         and after[R89]["state_digest"] != before[R89]["state_digest"]
         and after[R79]["state_digest"] == before[R79]["state_digest"]),
        ("01e snapshot_at unchanged and file unchanged by the rule update",
         shown["snapshot_at"] == snap0 and pfile(p, "web").read_bytes() == raw0),
        ("03b executable-looking intent never run", no_markers()),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-05 recompute (03b-03f, 02i)
def tc_recompute():
    from datetime import datetime

    p = base_project(extra=True)
    pnew(p, "web", [R79, R89], qi=INTENT, summ="Web handlers")
    raw0, t0 = pfile(p, "web").read_bytes(), tree(p)
    cands = [R79, R20, "CWE/4.14/CWE-1", R798, "CWE/*", R352]
    res = precompute(p, "web", cands)
    d = (res[1] or {}).get("data", {})
    _, _, text, _ = precompute(p, "web", cands, json_=False)
    INFO["recompute"] = res[1]
    inv = {i["requested"]: i["reason"] for i in d.get("invalid", [])}
    checks = [
        ("03c diff: rules to add, rules to remove, unchanged count against the stored list",
         ok(res) and [a["rule"] for a in d["add"]] == [R20] and [r["rule"] for r in d["remove"]] == [R89]
         and d["unchanged_count"] == 1 and d["stored_count"] == 2 and d["unchanged"] is False),
        ("03c each candidate's availability shown and a recompute digest returned",
         d["add"][0]["availability"] == "available" and d["add"][0].get("state_digest", "").startswith("sha256:")
         and d["remove"][0]["availability"] == "available" and d["recompute_digest"].startswith("sha256:")),
        ("03f invalid candidates listed with reasons and excluded from confirmable additions",
         inv == {"CWE/4.14/CWE-1": "not_found", R798: "pending_decision", "CWE/*": "dynamic_selector",
                 R352: "inconsistent"}),
        ("UI recompute text prints + additions, - removals and counts",
         f"+ {R20}" in text and f"- {R89}" in text and "+1 -1 =1" in text),
        ("03c Preset file unchanged until confirmation; recompute wrote nothing",
         pfile(p, "web").read_bytes() == raw0 and tree(p) == t0),
        ("03b/03f query text never evaluated or executed (no marker files)", no_markers()),
    ]
    dig = d["recompute_digest"]
    base = {"candidates": cands, "recompute_digest": dig}
    checks += [
        ("03f an invalid candidate cannot be confirmed as an addition",
         refused(pconfirm(p, "web", {**base, "accept_add": ["CWE/4.14/CWE-1"], "keep_summary": True}),
                 "REQUEST_INVALID")),
        ("02i recompute confirmation changing membership without summary decision refused",
         refused(pconfirm(p, "web", base), "SUMMARY_DECISION_REQUIRED")),
        ("recompute-confirm without the confirmation flag refused",
         refused(pconfirm(p, "web", {**base, "keep_summary": True}, confirmed=False), "CONFIRMATION_REQUIRED")),
        ("refused confirmations wrote nothing", tree(p) == t0),
    ]
    must(pupdate(p, "web", preq(None, summ="Web handlers (edited)")), "metadata edit")
    res = pconfirm(p, "web", {**base, "keep_summary": True})
    INFO["stale1"] = res[1]
    t1 = tree(p)
    checks.append(("03d Preset changed since the recompute → confirmation refused stale with the new diff",
                   refused(res, "STALE_RECOMPUTE") and res[1]["data"].get("recompute_digest", dig) != dig
                   and [a["rule"] for a in res[1]["data"].get("add", [])] == [R20]
                   and prules(p, "web") == [R79, R89]))
    dig2 = must(precompute(p, "web", cands), "recompute 2")["data"]["recompute_digest"]
    must(kupdate(p, R20, "Rule CWE-20 body, changed after the recompute.\n"), "candidate changed")
    t2 = tree(p)
    res = pconfirm(p, "web", {"candidates": cands, "recompute_digest": dig2, "keep_summary": True})
    checks.append(("03d candidate rule changed since the recompute → refused stale, nothing changed",
                   refused(res, "STALE_RECOMPUTE") and tree(p) == t2 and t1 != t2
                   and prules(p, "web") == [R79, R89]))
    snap_before = pjson(p, "web")["snapshot_at"]
    time.sleep(1.2)
    dig3 = must(precompute(p, "web", cands), "recompute 3")["data"]["recompute_digest"]
    res = pconfirm(p, "web", {"candidates": cands, "recompute_digest": dig3, "accept_add": "all",
                              "accept_remove": [], "keep_summary": True})
    INFO["subset"] = res[1]
    checks.append(("03d confirmed subset (additions only) → stored membership exactly the confirmed result; "
                   "snapshot_at updated; summary kept",
                   ok(res) and prules(p, "web") == [R20, R79, R89]
                   and datetime.fromisoformat(pjson(p, "web")["snapshot_at"]) > datetime.fromisoformat(snap_before)
                   and res[1]["data"].get("summary") == "kept"
                   and pjson(p, "web")["applicability_summary"] == "Web handlers (edited)"))
    raw1 = pfile(p, "web").read_bytes()
    res = precompute(p, "web", [R20, R79, R89])
    d = res[1]["data"]
    _, _, text, _ = precompute(p, "web", [R20, R79, R89], json_=False)
    res2 = pconfirm(p, "web", {"candidates": [R20, R79, R89], "recompute_digest": d["recompute_digest"]})
    checks.append(("03e no difference → states the list is unchanged; confirmation without re-confirm writes "
                   "nothing (snapshot_at not updated)",
                   ok(res) and d["unchanged"] is True and d["add"] == [] and d["remove"] == []
                   and "unchanged" in text.lower() and ok(res2) and res2[1]["data"].get("changed") is False
                   and pfile(p, "web").read_bytes() == raw1))
    time.sleep(1.2)
    res3 = pconfirm(p, "web", {"candidates": [R20, R79, R89], "recompute_digest": d["recompute_digest"],
                               "reconfirm": True})
    checks.append(("03e explicit re-confirmation updates only snapshot_at",
                   ok(res3) and prules(p, "web") == [R20, R79, R89]
                   and pjson(p, "web")["snapshot_at"] != json.loads(raw1)["snapshot_at"]))
    dz = must(precompute(p, "web", [R352]), "recompute to nothing")["data"]
    t3 = tree(p)
    res = pconfirm(p, "web", {"candidates": [R352], "recompute_digest": dz["recompute_digest"], "accept_remove": "all",
                              "keep_summary": True})
    checks.append(("02f recompute confirmation that would empty the membership refused, nothing written",
                   refused(res, "MEMBERSHIP_EMPTY") and tree(p) == t3 and dz["unchanged_count"] == 0))
    pnew(p, "noq", [R79], qi=None)
    checks.append(("edge: recompute of a Preset without query intent refused with next step",
                   refused(precompute(p, "noq", [R79]), "QUERY_INTENT_MISSING")))
    checks.append(("03b never executed across recompute/confirm", no_markers()))
    return checks


# ---------------------------------------------------------------- TC-F-06 Preset as scope input (04a-04c, 04i-04k, 09e, 09g)
def tc_preset_scope():
    p = base_project()
    pnew(p, "web", [R79, R89, A1], qi="injection rules", summ="Web handlers")
    raw0 = pfile(p, "web").read_bytes()
    res = presolve(p, "web")
    d = res[1]["data"]
    plain = must(resolve(p, A1, R79, R89), "policy resolve")["data"]
    pr = d.get("preset", {})
    INFO["resolve"] = {k: v for k, v in d.items() if k != "entries"}
    checks = [
        ("04a considered references are exactly the stored membership",
         ok(res) and [e["requested"] for e in d["entries"]] == [A1, R79, R89]),
        ("04a follows the 001-C proposal contract (library size, availability, proposal digest, nothing adopted)",
         d["mode"] == "clues" and d["library_size"] == plain["library_size"] and d["adopted"] == []
         and "nothing adopted" in d["adoption"] and all(e["availability"] == "available" for e in d["entries"])),
        ("04a proposal digest is the unchanged 001-C digest (equal to policy resolve of the same references)",
         d["proposal_digest"] == plain["proposal_digest"] and d["entries"] == plain["entries"]),
        ("04a names the Preset, its snapshot_at and applicability summary",
         pr.get("name") == "web" and pr.get("snapshot_at") == json.loads(raw0)["snapshot_at"]
         and pr.get("applicability_summary") == "Web handlers"),
        ("04a/04i toolkit-generated clue preset:<slug>@sha256:<file digest of the file read>",
         pr.get("clue") == f"preset:web@{sha(raw0)}"),
        ("04a next step names preset scope-save", "preset scope-save web" in steps(res[1])),
        ("09g provenance shown only as information clue text; no bound/verified/tamper-evident claim",
         "information-only" in pr.get("clue_note", "") and not CLAIMS.search(json.dumps(pr))
         and not CLAIMS.search(json.dumps(d.get("notices", [])))),
    ]
    q = p.parent.parent / "copy"
    shutil.copytree(p.parent, q, symlinks=True)
    qp = q / p.name
    doc = decisions(res[1], pr["clue"])
    a = spawn("preset", "scope-save", "web", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed",
              "--json")
    b = spawn("scope", "save", "--project", str(qp), "--decisions", jfile(qp, doc), "--confirmed", "--json")
    ca, sa, _, ea = finish(a)
    cb, sb, _, _ = finish(b)
    sid = sa["data"]["scope_id"]
    rec_raw = (p / SCOPES / sfile(sid)).read_bytes()
    rec = json.loads(rec_raw)
    rec_b = json.loads((qp / SCOPES / sfile(sb['data']['scope_id'])).read_bytes())
    same_time = rec.get("created_at") == rec_b.get("created_at")
    INFO.update(record=rec, plain_record=rec_b, scope_save=sa)
    checks += [
        ("04c/09e saved through the 001-C confirmation path as a clues-mode record whose clue is the generated "
         "clue", ca == 0 and sa["data"]["mode"] == "clues" and rec["mode"] == "clues"
         and pr["clue"] in json.dumps(rec.get("clues"))),
        ("04c record holds the adopted references with their confirmed rule state digests",
         sorted(x["ref"] if "ref" in x else x.get("rule") for x in rec["adopted"]) == [A1, R79, R89]
         and all(x["state_digest"] == entry(res[1], x.get("ref", x.get("rule")))["source_evidence"]["state_digest"]
                 for x in rec["adopted"])),
        ("09e no new field: same record keys as an ordinary 001-C scope save of the same decisions",
         set(rec) == set(rec_b) and cb == 0),
        ("09e identifier by the unchanged 001-C rule: same decisions + same created_at → same id and bytes "
         f"(parallel ordinary scope save in a copy; created_at equal: {same_time})",
         (not same_time) or (sid == sb["data"]["scope_id"] and rec == rec_b)),
        ("09g scope-save output and record make no binding claim; result names the Preset clue as information",
         not CLAIMS.search(json.dumps(sa["data"].get("preset", {}))) and not CLAIMS.search(rec_raw.decode())),
    ]
    INFO["same_created_at"] = same_time
    must(pupdate(p, "web", preq(None, [R79], keep_summary=True)), "later membership change")
    after_change = scope_files(p)
    must(pdelete(p, "web"), "later delete")
    checks.append(("04c later Preset change or deletion never changes the scope record; it still loads",
                   (p / SCOPES / sfile(sid)).read_bytes() == rec_raw and scope_files(p) == after_change
                   and ok(scope_show(p, sid))))
    # 04i look-alike user clue through the ordinary 001-C path
    fake = "preset:ghost@sha256:" + "b" * 64
    out = must(resolve(p, R79), "resolve")
    res = scope_save(p, decisions(out, fake))
    checks.append(("04i look-alike user clue is ordinary clue text: not refused, not verified, no Preset loaded",
                   ok(res) and "preset" not in res[1]["data"] and not pfile(p, "ghost").exists()
                   and fake in json.dumps(json.loads((p / SCOPES / sfile(res[1]['data']['scope_id']))
                                                     .read_text()).get("clues"))
                   and "PRESET_PROPOSED" not in json.dumps(out)))
    pnew(p, "api", [R79, R89], summ="API handlers")
    out = must(presolve(p, "api"), "resolve api")
    bad = decisions(out, "preset:api@sha256:" + "z" * 64)
    other = decisions(out, out["data"]["preset"]["clue"].replace("preset:api@", "preset:web@"))
    s0 = scope_files(p)
    checks.append(("A8 preset scope-save refuses a clue not in the generated format / naming another Preset",
                   refused(pscope(p, "api", bad), "DECISIONS_INVALID")
                   and refused(pscope(p, "api", other), "DECISIONS_INVALID") and scope_files(p) == s0))
    # 04j drift of concrete references / rule content between proposal and save
    for label, delta in (
            ("a rule added to the Preset", lambda: pupdate(p, "api", preq(None, [R20, R79, R89], keep_summary=True))),
            ("a rule removed from the Preset", lambda: pupdate(p, "api", preq(None, [R79], keep_summary=True))),
            ("a referenced rule's content changed", lambda: kupdate(p, R79, f"Rule CWE-79 body {time.time()}.\n"))):
        out = must(presolve(p, "api"), "resolve api")
        doc = decisions(out, out["data"]["preset"]["clue"])
        must(delta(), label)
        s0 = scope_files(p)
        res = pscope(p, "api", doc)
        checks.append((f"04j {label} before the save → STALE_CONFIRMATION, nothing written",
                       refused(res, "STALE_CONFIRMATION") and scope_files(p) == s0))
    # 04k metadata-only change is not detected (documented known limit)
    must(pupdate(p, "api", preq(None, [R79, R89], keep_summary=True)), "restore api")
    for label, change in (("applicability summary", preq(None, summ="Changed after the proposal")),
                          ("query intent", preq(None, qi="changed after the proposal"))):
        out = must(presolve(p, "api"), "resolve api")
        clue = out["data"]["preset"]["clue"]
        doc = decisions(out, clue)
        must(pupdate(p, "api", change), f"edit {label}")
        res = pscope(p, "api", doc)
        r = json.loads((p / SCOPES / sfile(res[1]['data']['scope_id'])).read_text()) if ok(res) else {}
        checks.append((f"04k only the {label} changed → save succeeds (change not detected, known limit); "
                       "adopted references and digests exactly as confirmed",
                       ok(res) and clue in json.dumps(r.get("clues")) and clue != f"preset:api@{pdig(p, 'api')}"
                       and sorted((x.get("ref", x.get("rule")), x["state_digest"]) for x in r["adopted"])
                       == sorted((i["ref"], i["state_digest"]) for i in doc["decisions"])))
    out = must(presolve(p, "api"), "resolve")
    time.sleep(1.2)
    must(precompute(p, "api", [R79, R89]), "recompute")
    reconf = must(precompute(p, "api", [R79, R89]), "recompute")["data"]["recompute_digest"]
    must(pconfirm(p, "api", {"candidates": [R79, R89], "recompute_digest": reconf, "reconfirm": True}), "reconfirm")
    res = pscope(p, "api", decisions(out, out["data"]["preset"]["clue"]))
    checks.append(("04k only snapshot_at changed → save succeeds (not detected)", ok(res)))
    sid2 = res[1]["data"]["scope_id"]
    shown = must(scope_show(p, sid2), "scope show")
    checks.append(("09g scope show presents provenance only as clue text (no structured Preset field)",
                   "preset" not in shown["data"] or not isinstance(shown["data"].get("preset"), dict)))
    # 04b mixed availability
    m = base_project()
    pnew(m, "mix", [R79, R89, R20])
    rawm = pfile(m, "mix").read_bytes()
    do_exit(m, R20, "delete")
    must(kupdate(m, R89, "Rule CWE-89 changed but available.\n"), "update")
    res = presolve(m, "mix")
    dm = res[1]["data"]
    INFO["mixed"] = {k: v for k, v in dm.items() if k != "entries"}
    checks += [
        ("04b availability per 001-C: available, changed-but-available, missing (deleted) with reason",
         res[0] == 0 and entry(res[1], R79)["availability"] == "available"
         and entry(res[1], R89)["availability"] == "available"
         and (entry(res[1], R20)["availability"], entry(res[1], R20).get("reason")) == ("missing", "deleted")),
        ("04b overall status follows 001-C BR-11 (partial, never complete)", dm["status"] == "partial"
         and dm["counts"] == {"requested": 3, "available": 2, "missing": 1, "unclear": 0}),
        ("04b Preset file unchanged", pfile(m, "mix").read_bytes() == rawm),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-07 default Preset branch (04e, 04g)
def no_apply_all(out: dict | None) -> bool:
    data = (out or {}).get("data", {})
    return data.get("mode") != "apply_all" and "APPLY_ALL_PROPOSED" not in json.dumps(out)


REPAIR = "repair the default preset or choose another scope"


def tc_default():
    p = base_project()
    t0 = tree(p)
    res = presolve(p, None)
    all_ = must(resolve(p, all_=True), "apply all")
    checks = [
        ("04e no default Preset → nothing proposed; next step is the unchanged Apply All proposal",
         ok(res) and res[1]["data"]["status"] == "no_default_preset" and res[1]["data"]["adopted"] == []
         and "proposal_digest" not in res[1]["data"] and "policy resolve --all" in steps(res[1])),
        ("04e Apply All (001-C) proposal reports no default Preset", all_["data"]["mode"] == "apply_all"
         and '"default_preset_exists": false' in json.dumps(all_).replace("False", "false")),
        ("04e default branch read wrote nothing", tree(p) == t0),
    ]
    sv = must(psave(p, preq("default", [R79, R89], summ="Default web scope")), "save default")
    res = presolve(p, None)
    d = res[1]["data"]
    note = next((n for n in d.get("notices", []) if n.get("code") == "DEFAULT_PRESET_PROPOSED"), {})
    INFO["default"] = {k: v for k, v in d.items() if k != "entries"}
    checks += [
        ("02g/04e saving `default` announces the default Preset", sv["data"].get("becomes_default") is True),
        ("04e highlighted notice: default Preset proposed because no clues were given",
         ok(res) and note.get("highlight") is True and "no clues" in note.get("message", "").lower()),
        ("04e built through the same Preset path (canonical clue for default + its references), nothing adopted",
         d["mode"] == "clues" and d["preset"]["clue"] == f"preset:default@{pdig(p, 'default')}"
         and [e["requested"] for e in d["entries"]] == [R79, R89] and d["adopted"] == [] and no_apply_all(res[1])),
    ]
    saved = must(pscope(p, "default", decisions(res[1], d["preset"]["clue"])), "scope-save default")
    rec = json.loads((p / SCOPES / sfile(saved['data']['scope_id'])).read_text())
    checks.append(("04e adopted only on the confirmed save, stored in clues mode",
                   rec["mode"] == "clues" and d["preset"]["clue"] in json.dumps(rec["clues"])))
    all2 = must(resolve(p, all_=True), "apply all")
    checks.append(("04e/001-C Apply All notice now reports default_preset_exists (agent goes back to the default)",
                   '"default_preset_exists": true' in json.dumps(all2)))
    outside = p.parent / "outside-default.json"
    outside.write_bytes(pfile(p, "default").read_bytes())
    variants = [
        ("malformed", lambda q: pfile(q, "default").write_bytes(b"{not json"), "PRESET_INVALID"),
        ("schema-invalid", lambda q: pfile(q, "default").write_text('{"schema": "x", "name": "default"}\n'),
         "PRESET_INVALID"),
        ("path-unsafe (symbolic link)", lambda q: (pfile(q, "default").unlink(),
                                                   pfile(q, "default").symlink_to(outside)), "PATH_UNSAFE"),
        ("all references missing", lambda q: (do_exit(q, R79, "delete"), do_exit(q, R89, "deactivate")),
         "MAINTENANCE_NEEDED"),
    ]
    for label, breaker, code in variants:
        q = base_project()
        must(psave(q, preq("default", [R79, R89])), "default")
        breaker(q)
        t1 = tree(q)
        res = presolve(q, None)
        INFO[f"default-{label}"] = res[1]
        status = (res[1] or {}).get("data", {}).get("status")
        refused_or_maint = res[0] != 0 and code_of(res[1]) == code or status == "maintenance_needed"
        checks.append((f"04g unusable default ({label}) → refused / maintenance_needed with the reason; next step "
                       "repair or choose another scope, Apply All only on explicit choice; no Apply All proposal",
                       refused_or_maint and REPAIR in steps(res[1]).lower()
                       and "explicitly" in steps(res[1]).lower() and no_apply_all(res[1]) and tree(q) == t1))
        explicit = resolve(q, all_=True)
        checks.append((f"04g ({label}) Apply All proposed only when the user then explicitly chooses it",
                       ok(explicit) and explicit[1]["data"]["mode"] == "apply_all"))
    return checks


# ---------------------------------------------------------------- TC-F-08 listing order, stored file integrity (04f, 08a)
def tc_listing_integrity():
    p = base_project()
    for name in ("zeta", "alpha", "mid", "default"):
        pnew(p, name, [R79], summ=f"summary of {name}")
    lists = [must(plist(p), "list")["data"] for _ in range(3)]
    _, _, text, _ = plist(p, False)
    checks = [
        ("04f Preset list name-sorted on every call, no ranking",
         all([x["name"] for x in d["presets"]] == ["alpha", "default", "mid", "zeta"] for d in lists)
         and not re.search(r"rank|score", json.dumps(lists))),
        ("04f each entry shows its applicability summary", [x["applicability_summary"] for x in lists[0]["presets"]]
         == ["summary of alpha", "summary of default", "summary of mid", "summary of zeta"]),
        ("04f text output in the same order", text.find("alpha") < text.find("mid") < text.find("zeta")),
    ]
    pnew(p, "good", [R79, R89])
    tsave(p, "good-tag", [R79])
    d = p / PRESETS
    (d / "bad.json").write_bytes(b"{not json")
    (d / "schema.json").write_text('{"schema": "ai-secure-code-toolkit/preset/v1", "name": "schema"}\n')
    (d / "named.json").write_bytes(pfile(p, "good").read_bytes())
    (d / "deep.json").write_text("[" * 100000)
    (d / "link.json").symlink_to(d / "good.json")
    (d / ".hidden.json").write_text("{}")
    (d / "notes.txt").write_text("not a preset")
    td = p / TAGS
    (td / "bad-tag.json").write_bytes(b"\xff\xfe")
    (td / "deep-tag.json").write_text("[" * 100000)
    (td / "link-tag.json").symlink_to(td / "good-tag.json")
    t0 = tree(p)
    res = plist(p)
    data = res[1]["data"]
    inv = {i["file"].split("/")[-1]: i for i in data.get("invalid", [])}
    INFO["list"] = data
    checks += [
        ("08a list: valid Presets still listed; invalid/linked/deep files reported invalid with next step",
         ok(res) and [x["name"] for x in data["presets"]] == ["alpha", "default", "good", "mid", "zeta"]
         and set(inv) == {"bad.json", "schema.json", "named.json", "deep.json", "link.json"}
         and all(i.get("next_step") for i in inv.values())),
        ("T-01 dot-files and non-JSON entries ignored", sorted(data.get("ignored", [])) == [".hidden.json",
                                                                                        "notes.txt"]),
    ]
    for name, code in (("bad", "PRESET_INVALID"), ("schema", "PRESET_INVALID"), ("named", "PRESET_INVALID"),
                       ("deep", "PRESET_INVALID"), ("link", "PATH_UNSAFE")):
        shown, resolved = pshow(p, name), presolve(p, name)
        checks.append((f"08a {name}.json: show and resolve refused ({code}) with restore/re-save next step; no "
                       "Policies proposed",
                       refused(shown, code) and refused(resolved, code)
                       and ("restore" in steps(shown[1]).lower() or "re-save" in steps(shown[1]).lower())
                       and "entries" not in resolved[1]["data"] and "proposal_digest" not in resolved[1]["data"]))
    out = presolve(p, "good")
    checks.append(("08a other Presets still work (show/resolve good)", ok(pshow(p, "good")) and ok(out)))
    tl = tlist(p)
    tinv = {i["file"].split("/")[-1] for i in tl[1]["data"].get("invalid", [])}
    checks += [
        ("08a tag list: valid tag listed, invalid/deep/linked tag files reported invalid",
         ok(tl) and [t["name"] for t in tl[1]["data"]["tags"]] == ["good-tag"]
         and tinv == {"bad-tag.json", "deep-tag.json", "link-tag.json"}),
        ("08a tag show of invalid/linked files refused with next step; good tag works",
         refused(tshow(p, "bad-tag"), "TAG_INVALID") and refused(tshow(p, "deep-tag"), "TAG_INVALID")
         and refused(tshow(p, "link-tag"), "PATH_UNSAFE") and ok(tshow(p, "good-tag"))),
        ("08a reads of invalid files wrote nothing", tree(p) == t0),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-09 tags (05a-05f, 07c Maintainer, 02b/02h tags)
def tc_tags():
    p = base_project(extra=True)
    k0 = knowledge_trees(p)
    t0 = tree(p)
    res = tsave(p, "injection", [R89, A1, R20])
    raw = tfile(p, "injection").read_bytes()
    doc = json.loads(raw)
    checks = [
        ("05a/07c Maintainer tag save with members from two Local sources (namespaces) succeeds",
         ok(res) and res[1]["data"]["member_count"] == 3),
        ("05a exactly one visible JSON file under tags/ (no leading dot)",
         changed(t0, tree(p)) == {f"{TAGS}/injection.json"} and sorted(x.name for x in (p / TAGS).iterdir())
         == ["injection.json"]),
        ("05a members are concrete references (source kind, namespace/version/rule id); no rule content",
         set(doc) == {"members", "name", "schema"} and doc["members"] == [
             {"rule": A1, "source": "local"}, {"rule": R20, "source": "local"}, {"rule": R89, "source": "local"}]
         and b"body" not in raw and b"sha256" not in raw and canonical(raw)),
    ]
    res = tsave(p, "refx", [R79, "reference:OWASP/2021/A03"])
    checks.append(("05a a Reference member refused invalid_reference with the next step (until 001-E)",
                   refused(res, "REFERENCES_INVALID")
                   and [r["reason"] for r in res[1]["data"]["references"]] == ["invalid_reference"]))
    t1 = tree(p)
    for label, member, reason in (("not found", "CWE/4.14/CWE-1", "not_found"),
                                  ("pending item", R798, "pending_decision"),
                                  ("inconsistent rule", R352, "inconsistent"),
                                  ("several versions", "CWE/CWE-89", "multiple_versions")):
        res = tsave(p, "x-" + reason.replace("_", "-"), [R79, member])
        checks.append((f"05b tag member {label} refused with the 001-C reason {reason}",
                       refused(res, "REFERENCES_INVALID")
                       and [r["reason"] for r in res[1]["data"]["references"]] == [reason]))
    checks += [
        ("02b tag save without confirmation refused", refused(tsave(p, "noconf", [R79], confirmed=False),
                                                               "CONFIRMATION_REQUIRED")),
        ("02h tag update without / with stale digest refused STALE_DIGEST",
         refused(tupdate(p, "injection", [R79], None), "STALE_DIGEST")
         and refused(tupdate(p, "injection", [R79], "sha256:" + "2" * 64), "STALE_DIGEST")
         and refused(tdelete(p, "injection", "sha256:" + "3" * 64), "STALE_DIGEST")),
        ("05b/02b/02h refusals wrote nothing", tree(p) == t1),
    ]
    pnew(p, "web", [R79, R89])
    praw = pfile(p, "web").read_bytes()
    pres0 = must(presolve(p, "web"), "resolve")["data"]
    r1 = tupdate(p, "injection", [R79, R20, A1])
    r2 = tupdate(p, "injection", [R79, R89])
    pres1 = must(presolve(p, "web"), "resolve")["data"]
    checks += [
        ("07c Maintainer tag updates succeed", ok(r1) and ok(r2)),
        ("05c Preset membership unchanged and file byte-identical after tag member changes",
         pfile(p, "web").read_bytes() == praw and prules(p, "web") == [R79, R89]
         and [e["requested"] for e in pres1["entries"]] == [e["requested"] for e in pres0["entries"]]
         and pres1["proposal_digest"] == pres0["proposal_digest"]),
    ]
    q = base_project()
    before = must(resolve(q, R79, R89), "resolve")
    must(tsave(q, "sev", [R89]), "tag")
    after = must(resolve(q, R79, R89), "resolve")
    checks.append(("05d requirement, institutional marking and every attribute identical with and without tags "
                   "(whole proposal equal)", before["data"] == after["data"]))
    # 05e tag as clue: agent expands at proposal time
    shown = must(tshow(p, "injection"), "tag show")
    members = [m["rule"] for m in shown["data"]["members"]]
    prop = must(resolve(p, *members), "resolve members")
    saved = must(scope_save(p, decisions(prop, "tag:injection")), "scope save")
    srec = (p / SCOPES / sfile(saved['data']['scope_id'])).read_bytes()
    rec = json.loads(srec)
    must(tupdate(p, "injection", [A1]), "tag change")
    checks += [
        ("05e tag expanded into concrete references at proposal time; record holds only those references",
         sorted(x.get("ref", x.get("rule")) for x in rec["adopted"]) == sorted(members)
         and "next_steps" in shown and "policy resolve --rule" in steps(shown)),
        ("05e later tag change does not change the scope record", (p / SCOPES / sfile(saved['data']['scope_id']))
         .read_bytes() == srec and ok(scope_show(p, saved["data"]["scope_id"]))),
    ]
    t2 = tree(p)
    ls, sh = tlist(p), tshow(p, "injection")
    checks += [
        ("05f list/show show members with current availability", ok(ls) and ok(sh)
         and [m["availability"] for m in sh[1]["data"]["members"]] == ["available"]
         and ls[1]["data"]["tags"][0]["name"] == "injection"
         and "never change severity" in sh[1]["data"]["note"]),
        ("05f reading writes nothing", tree(p) == t2),
    ]
    res = tdelete(p, "injection")
    checks += [
        ("07c Maintainer tag delete with confirmation succeeds", ok(res) and not tfile(p, "injection").exists()),
        ("07c Maintainer tag writes never wrote knowledge or pending store", knowledge_trees(p) == k0
         or changed(k0, knowledge_trees(p)) == set()),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-10 exit impact (06a-06e, 06h, 01d)
def impact_project() -> Path:
    p = base_project()
    pnew(p, "p1", [R89, R79])
    pnew(p, "p2", [R89])
    pnew(p, "p3", [R79])
    must(tsave(p, "t1", [R89]), "t1")
    must(tsave(p, "t2", [R89, A1]), "t2")
    must(tsave(p, "t3", [A1]), "t3")
    return p


def tc_exit_impact():
    p = impact_project()
    s0 = store_trees(p)
    checks = []
    for action, to in (("deactivate", None), ("rename", R89SQL), ("delete", None)):
        res = preview(p, R89, action, to)
        imp_ = res[1]["data"]["impact"]
        checks.append((f"06a {action} preview lists exactly the referencing Presets (p1, p2) and tags (t1, t2) by "
                       "identity; no longer 'not checked'",
                       ok(res) and names(imp_, "presets") == ["p1", "p2"] and names(imp_, "tags") == ["t1", "t2"]
                       and imp_["presets"]["count"] == 2 and imp_["tags"]["count"] == 2
                       and imp_["reference_cache"] == NOT_CHECKED
                       and all(len(i["file_digest"]) == 71 for i in imp_["presets"]["items"])))
    q = p.parent.parent / "react"
    shutil.copytree(p.parent, q, symlinks=True)
    qp = q / p.name
    do_exit(qp, R89, "deactivate")
    res = preview(qp, R89, "reactivate")
    imp_ = res[1]["data"]["impact"]
    checks.append(("06a reactivate preview lists the same referencing Presets and tags",
                   ok(res) and names(imp_, "presets") == ["p1", "p2"] and names(imp_, "tags") == ["t1", "t2"]))
    res = preview(p, R20, "deactivate")
    imp_ = res[1]["data"]["impact"]
    _, _, text, _ = preview(p, R20, "deactivate", json_=False)
    block = text[text.find("  presets:"):text.find("  reference_cache:")]
    checks += [
        ("06b no referencing Preset/tag → presets and tags explicitly empty; Reference cache still not checked",
         ok(res) and imp_["presets"] == {"count": 0, "items": [], "unreadable": []}
         and imp_["tags"] == {"count": 0, "items": [], "unreadable": []} and imp_["reference_cache"] == NOT_CHECKED),
        ("UI exit preview text prints presets and tags groups with counts ('none' when empty)",
         "presets:" in block and "tags:" in block and "count: 0" in block and "(none)" in block
         and f"reference_cache: {NOT_CHECKED}" in text),
        ("01d previews left Preset/tag files byte-identical", store_trees(p) == s0),
    ]
    deltas = [
        ("a referencing Preset added", lambda: pnew(p, "p4", [R89])),
        ("a referencing Preset changed", lambda: must(pupdate(p, "p1", preq(None, summ="changed")), "upd")),
        ("a referencing Preset removed", lambda: must(pdelete(p, "p2"), "del")),
        ("a referencing tag added", lambda: must(tsave(p, "t4", [R89]), "tsave")),
        ("a referencing tag changed", lambda: must(tupdate(p, "t1", [R89, R79]), "tupd")),
        ("a referencing tag removed", lambda: must(tdelete(p, "t2"), "tdel")),
    ]
    for label, delta in deltas:
        dig = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
        delta()
        t1 = tree(p)
        res = confirm(p, R89, "deactivate", dig)
        state = must(kshow(p, R89), "show")["data"]["state"]
        checks.append((f"06c {label} after the preview → confirmation refused as stale; nothing changed",
                       refused(res, "STALE_IMPACT") and state == "active" and tree(p) == t1))
    s1 = store_trees(p)
    do_exit(p, R89, "rename", R89SQL)
    do_exit(p, R79, "deactivate")
    do_exit(p, A1, "delete")
    checks.append(("06d confirmed rename, deactivation and delete of referenced rules → every Preset and tag file "
                   "byte-identical (no cascade edit, no substitution)", store_trees(p) == s1))
    sh = must(pshow(p, "p1"), "show p1")["data"]
    br = {b["target"]: b for b in sh["broken"]}
    INFO["p1"] = sh
    checks += [
        ("06e preset show reports broken references with owner, target and reason (renamed with new ID as "
         "information; deactivated)",
         br.get(R89, {}).get("owner") == "preset" and br[R89]["name"] == "p1" and br[R89]["reason"] == "renamed"
         and br[R89].get("renamed_to") == R89SQL and br.get(R79, {}).get("reason") == "deactivated"),
        ("06e the new ID is never used in place of the old one", prules(p, "p1") == [R79, R89]
         and [r["rule"] for r in sh["rules"]] == [R79, R89] and sh["status"] != "complete"),
    ]
    rp = presolve(p, "p1")[1]
    checks.append(("06e preset resolve reports the references missing with their reasons, never substituted",
                   entry(rp, R89).get("reason") == "renamed" and entry(rp, R79).get("reason") == "deactivated"
                   and entry(rp, R89)["availability"] == "missing" and R89SQL not in [e["requested"]
                                                                                       for e in rp["data"]["entries"]]))
    ts = must(tshow(p, "t3"), "tag show")["data"]
    lk = must(links(p), "links")["data"]
    ext = lk.get("preset_tag_links", {})
    INFO["links"] = ext
    checks += [
        ("06e tag show reports the broken member (deleted)",
         [(b["owner"], b["name"], b["target"], b["reason"]) for b in ts["broken"]] == [("tag", "t3", A1, "deleted")]),
        ("06e knowledge links reports broken Preset and tag references with owner, target, reason, renamed_to",
         {(x["name"], x["target"], x["reason"]) for x in ext.get("presets", [])}
         >= {("p1", R89, "renamed"), ("p1", R79, "deactivated"), ("p4", R89, "renamed")}
         and {(x["name"], x["target"], x["reason"]) for x in ext.get("tags", [])}
         >= {("t1", R89, "renamed"), ("t3", A1, "deleted"), ("t4", R89, "renamed")}
         and all(x.get("renamed_to") == R89SQL for x in ext["presets"] if x["reason"] == "renamed")
         and list(lk)[-1] == "preset_tag_links"),
    ]
    h = base_project()
    pnew(h, "h", [R79, R89])
    hraw = pfile(h, "h").read_bytes()
    do_exit(h, R79, "deactivate")
    mid = must(pshow(h, "h"), "show")["data"]
    do_exit(h, R79, "reactivate")
    sh = must(pshow(h, "h"), "show")["data"]
    rs = must(presolve(h, "h"), "resolve")["data"]
    checks += [
        ("06h while deactivated the reference is reported missing (deactivated)",
         [(r["rule"], r["availability"]) for r in mid["rules"]][0] == (R79, "missing")),
        ("06h after reactivation the reference is available again under the same identity",
         [(r["rule"], r["availability"]) for r in sh["rules"]] == [(R79, "available"), (R89, "available")]
         and sh["broken"] == [] and sh["status"] == "complete" and rs["status"] == "complete"),
        ("06h the Preset file was never changed", pfile(h, "h").read_bytes() == hraw),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-11 unreadable files in exit impact / links (06f, 06e, 08a)
def tc_unreadable():
    p = base_project()
    pnew(p, "good", [R89])
    must(tsave(p, "good-tag", [R89]), "tag")
    (p / PRESETS / "bad.json").write_bytes(b"{not json")
    (p / TAGS / "bad-tag.json").write_text('{"schema": "wrong"}')
    res = preview(p, R89, "deactivate")
    imp_ = res[1]["data"]["impact"]
    d1 = res[1]["data"]["impact_digest"]
    INFO["impact"] = imp_
    checks = [
        ("06f malformed Preset/tag file reported as an unreadable finding in its kind (never an empty list)",
         ok(res) and [u["file"].split("/")[-1] for u in imp_["presets"]["unreadable"]] == ["bad.json"]
         and [u["file"].split("/")[-1] for u in imp_["tags"]["unreadable"]] == ["bad-tag.json"]
         and names(imp_, "presets") == ["good"] and names(imp_, "tags") == ["good-tag"]),
    ]
    (p / PRESETS / "bad.json").write_bytes(b"[1, 2")
    d2 = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    t1 = tree(p)
    stale = confirm(p, R89, "deactivate", d1)
    checks.append(("06f unreadable file bound into the impact digest (content change → new digest, stale confirm)",
                   d1 != d2 and refused(stale, "STALE_IMPACT") and tree(p) == t1))
    (p / PRESETS / "deep.json").write_text("[" * 100000)
    (p / TAGS / "deep-tag.json").write_text("[" * 100000)
    res = preview(p, R89, "deactivate")
    lk = links(p)
    pl, tl = plist(p), tlist(p)
    imp_ = res[1]["data"]["impact"]
    ext = lk[1]["data"].get("preset_tag_links", {})
    checks += [
        ("06f/review fix: deeply nested Preset/tag files are unreadable findings, preview not crashed",
         ok(res) and "deep.json" in [u["file"].split("/")[-1] for u in imp_["presets"]["unreadable"]]
         and "deep-tag.json" in [u["file"].split("/")[-1] for u in imp_["tags"]["unreadable"]]),
        ("06e links reports unreadable Preset/tag files as findings (incl. deeply nested)",
         ok(lk) and {u["file"].split("/")[-1] for u in ext.get("unreadable", [])}
         >= {"bad.json", "bad-tag.json", "deep.json", "deep-tag.json"}),
        ("08a list commands survive deeply nested files", ok(pl) and ok(tl)),
    ]
    q = p.parent / "tags-outside"
    q.mkdir()
    shutil.rmtree(p / TAGS)
    (p / TAGS).symlink_to(q)
    t2 = tree(p)
    res = preview(p, R89, "deactivate")
    lk = links(p)
    tun = res[1]["data"]["impact"]["tags"]["unreadable"] if ok(res) else []
    INFO["storelink"] = res[1]
    checks += [
        ("A9 linked tags/ store becomes one unreadable finding in the preview (not followed, not refused)",
         ok(res) and len(tun) == 1 and "tags" in tun[0]["file"]),
        ("A10 links reports the linked store as a finding (not refused)", ok(lk)
         and any("tags" in u["file"] for u in lk[1]["data"]["preset_tag_links"]["unreadable"])),
        ("previews/links wrote nothing and never followed the link", tree(p) == t2 and list(q.iterdir()) == []),
    ]
    return checks


# ---------------------------------------------------------------- TC-F-12 lock and serialization (02j, 06g, 06i)
def tc_concurrency():
    p = base_project()
    pnew(p, "web", [R79])
    must(tsave(p, "inj", [R79]), "tag")
    t0, locks0 = tree(p), lock_listing(p)
    fd = os.open(p / KLOCK, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    timings, results = [], []
    try:
        for label, call in (("preset save", lambda: psave(p, preq("new", [R79]))),
                            ("preset update", lambda: pupdate(p, "web", preq(None, summ="x"))),
                            ("preset delete", lambda: pdelete(p, "web")),
                            ("tag save", lambda: tsave(p, "new-tag", [R79])),
                            ("tag update", lambda: tupdate(p, "inj", [R79, R89])),
                            ("tag delete", lambda: tdelete(p, "inj"))):
            start = time.time()
            res = call()
            timings.append(time.time() - start)
            results.append((label, res))
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    checks = [(f"02j {label} waits for the existing knowledge lock and is refused LOCKED (waited "
               f"{t:.1f}s ≥ LOCK_TIMEOUT 10 s)", refused(res, "LOCKED") and t >= 9.5)
              for (label, res), t in zip(results, timings, strict=True)]
    checks.append(("02j nothing written, never proceeded without the lock, no new lock file",
                   tree(p) == t0 and lock_listing(p) == locks0))
    races = [("preset", "create"), ("preset", "update"), ("preset", "delete"), ("tag", "create")]
    for kind, op in races:
        for first in ("exit", "write"):
            checks.append(race(kind, op, first))
    return checks


def write_args(p: Path, kind: str, op: str) -> list[str]:
    if kind == "tag":
        return ["tag", "save", "--project", str(p), "--request", jfile(p, treq("beta", [R89])), "--confirmed",
                "--json"]
    if op == "create":
        return ["preset", "save", "--project", str(p), "--request", jfile(p, preq("beta", [R89])), "--confirmed",
                "--json"]
    if op == "update":
        return ["preset", "update", "alpha", "--project", str(p), "--request",
                jfile(p, preq(None, [R79, R89], keep_summary=True)), "--digest", pdig(p, "alpha"), "--confirmed",
                "--json"]
    return ["preset", "delete", "alpha", "--project", str(p), "--digest", pdig(p, "alpha"), "--confirmed", "--json"]


def race(kind: str, op: str, first: str):
    p = base_project()
    pnew(p, "alpha", [R89] if op == "delete" else [R79])
    scopes0 = scope_files(p)
    dig = must(preview(p, R89, "deactivate"), "preview")["data"]["impact_digest"]
    wargs = write_args(p, kind, op)
    tag = p.parent / f"{kind}-{op}-{first}.pause"
    start = time.time()
    if first == "exit":
        holder = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, dig), env=pause_env(tag, "exit_locked"))
        ready = wait_file(tag.with_suffix(".ready"))
        contender = spawn(*wargs)
    else:
        holder = spawn(*wargs, env=pause_env(tag, f"{kind}_write_locked"))
        ready = wait_file(tag.with_suffix(".ready"))
        contender = spawn(*exit_args("exit-confirm", p, R89, "deactivate", None, dig))
    waited = blocked(contender)
    tag.with_suffix(".go").write_text("go\n")
    h = finish(holder)
    c = finish(contender)
    elapsed = time.time() - start
    exit_res, write_res = (h, c) if first == "exit" else (c, h)
    state = must(kshow(p, R89), "show")["data"]["state"]
    target = (tfile(p, "beta") if kind == "tag" else pfile(p, "beta" if op == "create" else "alpha"))
    if first == "write":
        good = ok(write_res) and refused(exit_res, "STALE_IMPACT") and state == "active"
        outcome = "write publishes first → exit confirmation refused stale (impact digest changed)"
    elif op == "delete":
        good = ok(exit_res) and state == "deactivated" and ok(write_res) and not target.exists()
        outcome = "exit commits first → the delete then removes only the Preset file"
    else:
        refs = (write_res[1] or {}).get("data", {}).get("references", [])
        good = (ok(exit_res) and state == "deactivated" and refused(write_res, "REFERENCES_INVALID")
                and [r["reason"] for r in refs] == ["deactivated"]
                and (not target.exists() if op == "create" else prules(p, "alpha") == [R79]))
        outcome = "exit commits first → the write re-checks the rule and is refused with its reason"
    INFO[f"{kind}-{op}-{first}"] = (exit_res[1], write_res[1])
    return (f"06g/06i {kind} {op} vs exit-confirm ({first} first): serialized by the knowledge lock, no deadlock "
            f"({elapsed:.1f}s); {outcome}; scope records unchanged",
            ready and waited and good and scope_files(p) == scopes0 and elapsed < 120)


# ---------------------------------------------------------------- TC-F-13 write-path safety, interrupted writes (02k, 08c)
def tc_path_safety():
    checks = []

    def outside_tree(o: Path) -> dict[str, str]:
        return tree(o) if o.is_dir() else {"file": hashlib.sha256(o.read_bytes()).hexdigest()}

    def setup_file_link(p: Path, kind: str) -> Path:
        f = (pfile if kind == "preset" else tfile)(p, "web")
        o = p.parent / f"outside-{kind}.json"
        o.write_bytes(f.read_bytes())
        f.unlink()
        f.symlink_to(o)
        return o

    def setup_dir_link(p: Path, rel: str) -> Path:
        o = p.parent / ("outside-" + rel.replace("/", "-"))
        shutil.move(str(p / rel), str(o))
        (p / rel).symlink_to(o)
        return o

    cases = [
        ("Preset file is a link", "preset", lambda p: setup_file_link(p, "preset"),
         lambda p, d: [pupdate(p, "web", preq(None, summ="x"), d), pdelete(p, "web", d),
                       psave(p, preq("web", [R79]))]),
        ("tag file is a link", "tag", lambda p: setup_file_link(p, "tag"),
         lambda p, d: [tupdate(p, "web", [R89], d), tdelete(p, "web", d), tsave(p, "web", [R79])]),
        ("presets/ is a link", "preset", lambda p: setup_dir_link(p, PRESETS),
         lambda p, d: [psave(p, preq("new", [R79])), pupdate(p, "web", preq(None, summ="x"), d),
                       pdelete(p, "web", d)]),
        ("tags/ is a link", "tag", lambda p: setup_dir_link(p, TAGS),
         lambda p, d: [tsave(p, "new", [R79]), tupdate(p, "web", [R89], d), tdelete(p, "web", d)]),
        ("x-ipe-docs/secure-code is a link", "preset", lambda p: setup_dir_link(p, "x-ipe-docs/secure-code"),
         lambda p, d: [psave(p, preq("new", [R79])), pdelete(p, "web", d), tsave(p, "new", [R79])]),
        ("x-ipe-docs is a link", "preset", lambda p: setup_dir_link(p, "x-ipe-docs"),
         lambda p, d: [psave(p, preq("new", [R79])), pupdate(p, "web", preq(None, summ="x"), d),
                       tsave(p, "new", [R79])]),
    ]
    for label, kind, setup, calls in cases:
        p = base_project()
        pnew(p, "web", [R79])
        must(tsave(p, "web", [R79]), "tag")
        d = pdig(p, "web") if kind == "preset" else tdig(p, "web")
        o = setup(p)
        t0, o0 = tree(p), outside_tree(o)
        results = calls(p, d)
        INFO[label] = [r[1] for r in results]
        checks.append((f"02k {label}: create/update/delete refused PATH_UNSAFE; nothing written inside or outside "
                       "the project; previous file byte-identical; link unchanged",
                       all(refused(r, "PATH_UNSAFE") for r in results) and tree(p) == t0 and outside_tree(o) == o0))
    p = base_project()
    pnew(p, "web", [R79, R89])
    must(tsave(p, "inj", [R79, R89]), "tag")
    for kind in ("preset", "tag"):
        for point in ("temp_fsync", "replace", "dir_fsync"):
            f = pfile(p, "web") if kind == "preset" else tfile(p, "inj")
            old = f.read_bytes()
            new_members = [R20, R79] if json.loads(old)["rules" if kind == "preset" else "members"][0]["rule"] != R20 \
                else [R79, R89]
            env = env_with(SECURE_CODE_TEST_FAIL_AT=f"{point}:{kind}_write")
            if kind == "preset":
                args = ["preset", "update", "web", "--request", jfile(p, preq(None, new_members, keep_summary=True)),
                        "--digest", sha(old)]
            else:
                args = ["tag", "update", "inj", "--request", jfile(p, treq(None, new_members)), "--digest", sha(old)]
            res = sc(*args, "--project", str(p), "--confirmed", "--json", env=env)
            now = f.read_bytes()
            try:
                members = [r["rule"] for r in json.loads(now)["rules" if kind == "preset" else "members"]]
                complete = canonical(now)
            except (ValueError, KeyError):
                members, complete = [], False
            prev_or_new = now == old or (complete and members == sorted(new_members))
            checks.append((f"08c {kind} write interrupted at {point}: refused IO_ERROR; store reads back the previous "
                           "or the new complete version, never partial; no temp file left",
                           res[0] != 0 and code_of(res[1]) == "IO_ERROR" and prev_or_new and complete
                           and not [n for n in os.listdir(f.parent) if n.endswith(".tmp")]
                           and (ok(pshow(p, "web")) if kind == "preset" else ok(tshow(p, "inj")))))
    return checks


# ---------------------------------------------------------------- TC-F-14 comparison with the pre-001-F revision (06j, 09a, 06e, 04e)
def tc_pre_upgrade():
    assert PRE, "PRE001F_SCRIPTS not set"
    checks = []
    p = base_project()
    pnew(p, "web", [R89])
    sid = must(scope_save(p, decisions(must(resolve(p, R79, R89), "resolve"), "login change")), "scope")["data"]
    for label, proj in (("with a Preset", p), ("without Presets/tags", base_project())):
        hist0, store0 = tree(proj, prefixes=(SCOPES, REPORTS)), store_trees(proj)
        old = pre(*exit_args("exit-preview", proj, R89, "deactivate", None, None))
        t0 = tree(proj)
        res = confirm(proj, R89, "deactivate", old[1]["data"]["impact_digest"])
        INFO[f"06j {label}"] = res[1]
        again = must(preview(proj, R89, "deactivate"), "re-preview")
        checks += [
            (f"06j ({label}) the pre-001-F revision reports presets/tags 'not checked' (genuine old preview)",
             old[0] == 0 and old[1]["data"]["impact"]["presets"] == NOT_CHECKED
             and old[1]["data"]["impact"]["tags"] == NOT_CHECKED),
            (f"06j ({label}) confirmation of the pre-upgrade preview refused once as stale, next step re-preview, "
             "nothing confirmed or written",
             refused(res, "STALE_IMPACT") and "preview" in steps(res[1]).lower() and tree(proj) == t0
             and must(kshow(proj, R89), "show")["data"]["state"] == "active"),
            (f"06j ({label}) re-preview gives a new digest that confirms; stored reports, scope records and Preset "
             "files byte-identical",
             again["data"]["impact_digest"] != old[1]["data"]["impact_digest"]
             and ok(confirm(proj, R89, "deactivate", again["data"]["impact_digest"]))
             and tree(proj, prefixes=(SCOPES, REPORTS)) == hist0 and store_trees(proj) == store0),
        ]
    checks.append(("06j scope record saved before still loads", ok(scope_show(p, sid["scope_id"]))))
    q = base_project()
    for label, args in (("clues proposal", (R79, R89, "CWE/CWE-20")), ("missing reference", (R79, "CWE/4.14/CWE-1"))):
        a, b = resolve(q, *args), resolve(q, *args, scripts=PRE)
        ta, tb = resolve(q, *args, json_=False), resolve(q, *args, scripts=PRE, json_=False)
        checks.append((f"09a {label}: policy resolve JSON and text stdout byte-identical to the pre-001-F revision",
                       a[0] == b[0] == 0 and a[2] == b[2] and ta[2] == tb[2]))
    for label, prep in (("no default Preset", lambda: None),
                        ("default Preset present", lambda: pnew(q, "default", [R79]))):
        prep()
        a, b = resolve(q, all_=True), resolve(q, all_=True, scripts=PRE)
        checks.append((f"04e/09a Apply All proposal ({label}) byte-identical to the pre-001-F revision "
                       "(AC-001C-04a unchanged)", a[0] == b[0] == 0 and a[2] == b[2]))
    for mode, out in (("clues", must(resolve(q, R79, R89), "resolve")), ("apply_all", must(resolve(q, all_=True),
                                                                                           "all"))):
        doc = decisions(out, "login change", mode)
        recs = {}
        for _attempt in range(3):
            copies = []
            for who in ("pre", "post"):
                c = q.parent.parent / f"{mode}-{who}-{_attempt}"
                shutil.copytree(q.parent, c, symlinks=True)
                copies.append(c / q.name)
            procs = [spawn("scope", "save", "--project", str(copies[0]), "--decisions", jfile(copies[0], doc),
                           "--confirmed", "--json", scripts=PRE),
                     spawn("scope", "save", "--project", str(copies[1]), "--decisions", jfile(copies[1], doc),
                           "--confirmed", "--json")]
            outs = [finish(x) for x in procs]
            recs = {who: (o[1], (c / SCOPES / sfile(o[1]['data']['scope_id'])).read_bytes() if o[0] == 0 else b"")
                    for who, o, c in zip(("pre", "post"), outs, copies, strict=True)}
            if json.loads(recs["pre"][1] or b"{}").get("created_at") == json.loads(recs["post"][1] or b"{}").get(
                    "created_at"):
                break
        pre_rec, post_rec = json.loads(recs["pre"][1]), json.loads(recs["post"][1])
        same = pre_rec.get("created_at") == post_rec.get("created_at")
        INFO[f"09a {mode}"] = {"same_created_at": same, "pre": recs["pre"][0], "post": recs["post"][0]}
        checks.append((f"09a {mode} scope save: same schema, mode and keys; with equal created_at the scope "
                       "identifier and record bytes are byte-identical to the pre-001-F revision",
                       set(pre_rec) == set(post_rec) and pre_rec["mode"] == post_rec["mode"] == mode
                       and same and recs["pre"][1] == recs["post"][1]
                       and recs["pre"][0]["data"]["scope_id"] == recs["post"][0]["data"]["scope_id"]))
    # 06e: links output byte-identical without Preset/tag files; only an appended key with them
    lp = new_project()
    must(imp(lp, item(R89), item(R20, relations=[R89])), "import")
    must(scope_save(lp, decisions(must(resolve(lp, R89), "resolve"), "login change")), "scope")
    do_exit(lp, R89, "delete")
    variants = (("init state (empty presets/ and tags/)", lambda: None),
                ("dot temp file only", lambda: (lp / PRESETS / ".web.json.tmp").write_text("{")),
                ("stores absent", lambda: (shutil.rmtree(lp / PRESETS), shutil.rmtree(lp / TAGS))))
    for label, prep in variants:
        prep()
        a, b = links(lp), links(lp, scripts=PRE)
        ta, tb = links(lp, False), links(lp, False, scripts=PRE)
        checks.append((f"06e/DAO-007(2a) knowledge links JSON and text byte-identical to pre-001-F ({label})",
                       a[0] == b[0] and a[2] == b[2] and ta[2] == tb[2] and "preset_tag_links" not in a[2]))
    (lp / PRESETS).mkdir(parents=True, exist_ok=True)
    (lp / TAGS).mkdir(parents=True, exist_ok=True)
    (lp / PRESETS / "old.json").write_text(json.dumps({
        "applicability_summary": None, "name": "old", "query_intent": None,
        "rules": [{"rule": R89, "source": "local"}], "schema": "ai-secure-code-toolkit/preset/v1",
        "snapshot_at": "2026-10-23T08:00:00+00:00"}, sort_keys=True, indent=2) + "\n")
    a, b = links(lp), links(lp, scripts=PRE)
    da, db = a[1]["data"], b[1]["data"]
    ext = da.get("preset_tag_links", {})
    checks.append(("06e/DAO-007(2b,c) with Preset files only `preset_tag_links` is appended last; every delivered "
                   "key, order, count and next step unchanged",
                   list(da)[:-1] == list(db) and list(da)[-1] == "preset_tag_links"
                   and {k: v for k, v in da.items() if k != "preset_tag_links"} == db
                   and a[1]["next_steps"] == b[1]["next_steps"]
                   and [(x["name"], x["target"], x["reason"]) for x in ext.get("presets", [])]
                   == [("old", R89, "deleted")]))
    return checks


# ---------------------------------------------------------------- TC-F-15 consumers load Preset-based scopes (09f)
def tc_consumers():
    p = base_project()
    pnew(p, "web", [R79, R89])
    _, saved = preset_scope(p, "web")
    sid = saved["data"]["scope_id"]
    must(pdelete(p, "web"), "delete Preset")
    shown = scope_show(p, sid)
    g, c = guard_open(p, sid), copilot_open(p, sid)
    INFO.update(guard=g[1], copilot=c[1], show=shown[1])
    return [
        ("09f 001-C scope show loads the Preset-based clues record after the Preset was deleted",
         ok(shown) and shown[1]["data"].get("mode", "clues") == "clues"),
        ("09f Guard verification (002-A) opens with the Preset-based scope", ok(g)),
        ("09f Copilot collaboration (003-A) opens with the Preset-based scope", ok(c)),
    ]


# ---------------------------------------------------------------- TC-F-16 authorization separation (07a-07d), container
def tc_authorization():
    p = base_project()
    must(tsave(p, "inj", [R79, R89]), "Maintainer tag")
    k0 = knowledge_trees(p)
    aside = APP.parent / (APP.name + ".aside")
    checks = []
    APP.rename(aside)
    try:
        r_user = role()
        res = [psave(p, preq("u", [R79, R89], qi="injection rules", summ="Web handlers"))]
        res.append(pupdate(p, "u", preq(None, [R79, R89, R20], summ="Web and input validation")))
        rc = precompute(p, "u", [R79, A1])
        res.append(rc)
        res.append(pconfirm(p, "u", {"candidates": [R79, A1], "recompute_digest": rc[1]["data"]["recompute_digest"],
                                     "keep_summary": True}))
        res.append(pdelete(p, "u"))
        checks += [
            ("07a precondition: the User has no Maintainer authorization", r_user != "maintainer"),
            ("07a User save, update, recompute, recompute-confirm and delete of a Preset succeed",
             all(ok(r) for r in res)),
            ("07a nothing under the knowledge or pending store written", knowledge_trees(p) == k0),
        ]
        t0 = tree(p)
        checks += [
            ("07b after the Preset save a knowledge import is still refused NOT_AUTHORIZED",
             unauthorized(imp(p, item("CWE/4.14/CWE-22")))),
            ("07b knowledge update still refused NOT_AUTHORIZED",
             unauthorized(kupdate(p, R79, "User edit attempt.\n"))),
            ("07b nothing written", tree(p) == t0),
        ]
        for label, call in (("save", lambda: tsave(p, "user-tag", [R79])),
                            ("update", lambda: tupdate(p, "inj", [R79])),
                            ("delete", lambda: tdelete(p, "inj"))):
            r = call()
            checks.append((f"07c User tag {label} through the toolkit refused NOT_AUTHORIZED with the next step to "
                           "ask a Maintainer first; nothing written",
                           unauthorized(r) and "maintainer" in r[1]["next_steps"][0].lower() and tree(p) == t0))
        ls, sh = tlist(p), tshow(p, "inj")
        members = [m["rule"] for m in sh[1]["data"]["members"]]
        prop = resolve(p, *members)
        checks += [
            ("07d User lists and shows tags", ok(ls) and ok(sh) and members == [R79, R89]),
            ("07d User uses the tag as a clue in a scope proposal (members → policy resolve)",
             ok(prop) and [e["requested"] for e in prop[1]["data"]["entries"]] == [R79, R89]),
            ("07d reading and proposing wrote nothing", tree(p) == t0),
        ]
    finally:
        aside.rename(APP)
    checks.append(("authorization restored", role() == "maintainer"))
    res = [tsave(p, "mt", [R79]), tupdate(p, "mt", [R79, R89]), tdelete(p, "mt")]
    checks.append(("07c Maintainer tag create/update/delete with confirmation succeed; knowledge/pending untouched",
                   all(ok(r) for r in res) and knowledge_trees(p) == k0))
    tags0 = tree(p, prefixes=(TAGS,))
    tag = p.parent / "revoke.pause"
    proc = spawn("tag", "save", "--project", str(p), "--request", jfile(p, treq("late", [R79])), "--confirmed",
                 "--json", env=pause_env(tag, "tag_write_authorized"))
    ready = wait_file(tag.with_suffix(".ready"))
    APP.rename(aside)
    try:
        tag.with_suffix(".go").write_text("go\n")
        late = finish(proc)
    finally:
        aside.rename(APP)
    checks.append(("07c/A4 Maintainer qualification re-checked under the lock: revoked while waiting → "
                   "NOT_AUTHORIZED, nothing written",
                   ready and unauthorized(late) and tree(p, prefixes=(TAGS,)) == tags0 and role() == "maintainer"))
    return checks


# ---------------------------------------------------------------- TC-F-17 never-authorized host User (07c, 07d, 02g, 04e)
def tc_host_user():
    p = new_project()
    t0 = tree(p)
    r_role = role()
    res = [tsave(p, "inj", [R79]), tupdate(p, "inj", [R79], "sha256:" + "0" * 64),
           tdelete(p, "inj", "sha256:" + "0" * 64)]
    ls, sh = tlist(p), tshow(p, "inj")
    lk = links(p)
    plres = plist(p)
    t1 = tree(p)
    dres = presolve(p, None)
    t2 = tree(p)
    ps = psave(p, preq("web", [R79]))
    ci = psave(p, preq("CON", [R79]))
    t3 = tree(p)
    q = new_project()
    q0 = tree(q)
    resolve(q, all_=True)
    q_lock = changed(q0, tree(q))
    r = new_project()
    r0 = tree(r)
    psave(r, preq("web", [R79]))
    r_lock = changed(r0, tree(r))
    INFO.update(default_resolve=changed(t1, t2), refused_save=changed(t2, t3), policy_resolve=q_lock,
                refused_save_fresh=r_lock)
    return [
        ("host role is User (never authorized; no trust store written)", r_role == "user"),
        ("07c tag save/update/delete refused NOT_AUTHORIZED, next step ask a Maintainer first",
         all(unauthorized(r) and "maintainer" in r[1]["next_steps"][0].lower() for r in res)),
        ("07d tag list works for the User (empty), show of an absent tag → TAG_NOT_FOUND with next step",
         ok(ls) and ls[1]["data"]["tags"] == [] and refused(sh, "TAG_NOT_FOUND")),
        ("07a/01f the User is not refused for authorization when saving a Preset: only the reference check "
         "refuses (no knowledge on the host)",
         refused(ps, "REFERENCES_INVALID") and ps[1]["data"]["references"][0]["reason"] == "not_found"),
        ("02g IDENTITY_INVALID for a reserved device name", refused(ci, "IDENTITY_INVALID")),
        ("04e no default Preset → no_default_preset, next step Apply All via policy resolve --all",
         ok(dres) and dres[1]["data"]["status"] == "no_default_preset" and "policy resolve --all" in steps(dres[1])),
        ("preset list empty with the history note", ok(plres) and plres[1]["data"]["presets"] == []
         and "version control is the history" in plres[1]["data"]["history_note"]),
        ("06e/DAO-007(2a) links without Preset/tag files has no preset_tag_links key",
         ok(lk) and "preset_tag_links" not in lk[1]["data"]),
        ("refused tag writes (pre-lock Maintainer check), tag/preset list/show and links wrote nothing at all",
         t1 == t0),
        ("preset resolve --default on a fresh project: at most the delivered knowledge lock file appears, exactly "
         "as for the unchanged 001-C policy resolve (design A3/A7 'lock file only'; observation O-1)",
         changed(t1, t2) <= {LOCKS, KLOCK} and q_lock <= {LOCKS, KLOCK}),
        ("refused Preset saves wrote no Preset/tag file or folder; on a fresh project only the knowledge lock file "
         "(and its folder) appears (design A4; observation O-1)",
         changed(t2, t3) <= {LOCKS, KLOCK} and r_lock <= {LOCKS, KLOCK}
         and store_trees(p) == {k: v for k, v in t0.items() if k.startswith((PRESETS, TAGS))}),
    ]


# ---------------------------------------------------------------- TC-F-18 Framework skill text (structured)
POLICY_STEP1 = """1. **Collect clues.** Rule IDs, a description of the work, the artifact languages. If the user
   gives no clues, run `secure-code preset resolve --project . --default --json` first:
   - **A default Preset exists:** show its highlighted notice and propose it; nothing is adopted
     until the user confirms, then save with
     `secure-code preset scope-save default --decisions FILE --confirmed`.
   - **No default Preset** (`no_default_preset`): go to step 3 with `--all` (Apply All).
   - **The default Preset is unusable** (refused or `maintenance_needed`): explain the reason and
     offer to repair it or to choose another scope. Never propose Apply All automatically; go to
     step 3 with `--all` only when the user separately and explicitly chooses Apply All."""
SKILL_NO_CLUES = ("**No clues:** run `secure-code preset resolve --default`. If a default Preset exists, its "
                  "highlighted notice says it is proposed because no clues were given; propose it and adopt it "
                  "only after the user confirms (`secure-code preset scope-save default --decisions FILE "
                  "--confirmed`). If there is no default Preset, propose **Apply All** with `policy resolve --all` "
                  "and show its highlighted notice: Policy scope only, never all project files. If the default "
                  "Preset is unusable (refused or `maintenance_needed`), offer to repair it or choose another "
                  "scope; propose Apply All only when the user separately and explicitly chooses it.")
SKILL_EXIT = ("Presets and tags that reference it, and the kind \"not checked in this version\" (Reference cache).")


def norm(text: str) -> str:
    return " ".join(text.split())


def has(text: str, *phrases: str) -> bool:
    low = norm(text).lower()
    return all(norm(x).lower() in low for x in phrases)


def tc_skill_text():
    skill = (FRAMEWORK / "SKILL.md").read_text(encoding="utf-8")
    ref = (FRAMEWORK / "references" / "presets-and-tags.md").read_text(encoding="utf-8")
    pol = (FRAMEWORK / "references" / "policy-selection.md").read_text(encoding="utf-8")
    cli = (FRAMEWORK / "references" / "cli-contract.md").read_text(encoding="utf-8")
    package = {f.relative_to(FRAMEWORK).as_posix(): f.read_text(encoding="utf-8")
               for f in sorted(FRAMEWORK.rglob("*.md")) if "scripts" not in f.parts}
    claims = []
    for name, text in package.items():
        for sentence in re.split(r"(?<=[.;:])\s+", norm(text)):
            if re.search(r"tamper|\bbound\b|\bverified\b", sentence, re.I) and re.search(r"preset|clue|provenance",
                                                                                         sentence, re.I):
                claims.append((name, sentence, bool(re.search(r"\bnot\b|\bnever\b|\bno\b", sentence, re.I))))
    INFO["claims"] = claims
    design = os.environ.get("DESIGN_FILE")
    design_ok = True
    if design and Path(design).is_file():
        dtext = Path(design).read_text(encoding="utf-8")
        design_ok = POLICY_STEP1 in dtext and norm(SKILL_NO_CLUES) in norm(dtext)
    copilot_guard = [f for f in TOOLKIT.rglob("*.md") if "framework" not in f.as_posix()
                     and ("copilot" in f.as_posix() or "guard" in f.as_posix()) and ".venv" not in f.parts]
    cg_text = "\n".join(f.read_text(encoding="utf-8") for f in copilot_guard).lower()
    return [
        ("02a create a Preset only on the user's explicit request; show concrete list with reasons and the "
         "applicability summary first; save only after confirmation; clues otherwise stay a temporary scope",
         has(ref, "Create a Preset only when the user explicitly asks to make the clues reusable",
             "Clues without that request remain a temporary scope", "concrete list with the reason for each rule",
             "applicability summary", "Only after the user confirms the list and the summary")
         and has(skill, "Never create a Preset from clues unless the user explicitly asks to make them reusable",
                 "show the concrete list with reasons and the applicability summary",
                 "save only after the user confirms")
         and has(pol, "Never create a Preset from clues unless the user explicitly asks to make them reusable")),
        ("03g recompute: intent → candidates only via knowledge list/show, tag show, policy resolve; submit; show "
         "diff; explicit confirmation before any update; query never run",
         has(ref, "Recompute only when the user explicitly asks", "using only the existing read operations",
             "`secure-code knowledge list`", "`secure-code knowledge show`", "`secure-code tag show`",
             "`secure-code policy resolve`", "preset recompute NAME --request FILE",
             "Show the diff and ask for explicit confirmation", "never runs it as a program")),
        ("04d compare the applicability summary with the current task; on clear mismatch explain and wait for the "
         "continue/adjust decision before proposing confirmation",
         has(ref, "compare its applicability summary with the current task",
             "If they clearly mismatch, explain the difference and wait for the user's decision to continue or "
             "adjust before you propose the scope for confirmation")),
        ("04f matching Presets listed by name in fixed order, no ranking, with summary and mismatch; user picks",
         has(ref, "list all matching Presets by name in the fixed name order", "with no ranking of your own",
             "applicability summary and any clear mismatch with the current task", "the user picks")),
        ("04i the agent never composes the clue; a typed look-alike clue is ordinary text",
         has(ref, "Never compose this clue yourself", "a clue typed by a user that looks the same is ordinary clue "
                                                      "text")),
        ("04k/BR-17 known limit: metadata-only Preset change between resolve and scope-save not detected",
         has(ref, "A metadata-only change of the Preset", "is not detected",
             "the adopted scope is still exactly what the user confirmed")),
        ("09g no text claims the provenance is bound/verified/tamper-evident (every such sentence is negated)",
         all(neg for _, _, neg in claims) and has(ref, "not bound by the proposal digest",
                                                  "not re-checked when the scope is saved", "not tamper-evident")),
        ("05e tag clue expanded into concrete references at proposal time; record holds only those",
         has(ref, "A tag clue is expanded into concrete references at proposal time",
             "the scope record holds only those references")),
        ("07c tag writes Maintainer-only, toolkit-mediated only (no filesystem protection claim)",
         has(ref, "Creating, updating or deleting a tag needs a Maintainer", "NOT_AUTHORIZED",
             "toolkit-mediated operations only", "no filesystem-level protection")),
        ("01g/BR-12 no history beyond version control",
         has(ref, "no Preset/tag change history; version control is the history", "snapshot_at is not a history")),
        ("04e SKILL.md no-clues step has the decided default-Preset branches (DAO-007 (4))",
         norm(SKILL_NO_CLUES) in norm(skill)),
        ("04e policy-selection.md step 1 is the design's verbatim block (DAO-008 Q1)",
         POLICY_STEP1 in pol and design_ok),
        ("06b/DAO-008 Q1 SKILL.md exit step lists Presets and tags as checked; 'not checked' only the Reference "
         "cache", norm(SKILL_EXIT) in norm(skill)),
        ("DAO-008 consistency: no stale 'there are no Presets yet' or Presets/tags 'not checked' list in the "
         "Framework package",
         not any("there are no presets yet" in t.lower() for t in package.values())
         and not any(re.search(r"presets,\s*tags,\s*reference cache", t, re.I) for t in package.values())),
        ("001-C AC-001C-02e phrases still present ('never create a preset', 'apply all')",
         "never create a preset" in (skill + pol).lower() and "apply all" in (skill + pol).lower()),
        ("CLI contract lists the new commands and impact kinds",
         all(x in cli for x in ("preset resolve", "preset scope-save", "recompute-confirm", "tag save",
                                "preset_tag_links"))),
        ("Copilot and Guard skill text not changed by 001-F (no Preset command text)",
         bool(copilot_guard) and "preset resolve" not in cg_text and "presets-and-tags" not in cg_text),
    ]


# ---------------------------------------------------------------- main
def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    only = set(sys.argv[2:])
    for m in MARKERS:
        m.unlink(missing_ok=True)
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        shutil.rmtree(APP, ignore_errors=True)
        assert sc_pty([(b"passphrase", PASS), (b"passphrase", PASS)], "auth", "init")[0] == 0
        plan = [
            ("TC-F-01", ["AC-001F-01a", "AC-001F-01c", "AC-001F-08b", "AC-001F-02g", "AC-001F-03b"], tc_save_content),
            ("TC-F-02", ["AC-001F-01b", "AC-001F-01f", "AC-001F-02b", "AC-001F-02d", "AC-001F-02f", "AC-001F-02g"],
             tc_save_refusals),
            ("TC-F-03", ["AC-001F-02b", "AC-001F-02c", "AC-001F-02e", "AC-001F-02f", "AC-001F-02h", "AC-001F-02i",
                         "AC-001F-01g"],
             tc_update_delete),
            ("TC-F-04", ["AC-001F-01d", "AC-001F-01e", "AC-001F-03a", "AC-001F-03b"], tc_reads),
            ("TC-F-05", ["AC-001F-03b", "AC-001F-03c", "AC-001F-03d", "AC-001F-03e", "AC-001F-03f", "AC-001F-02i",
                         "AC-001F-02f"],
             tc_recompute),
            ("TC-F-06", ["AC-001F-04a", "AC-001F-04b", "AC-001F-04c", "AC-001F-04i", "AC-001F-04j", "AC-001F-04k",
                         "AC-001F-09e", "AC-001F-09g"], tc_preset_scope),
            ("TC-F-07", ["AC-001F-04e", "AC-001F-04g", "AC-001F-02g"], tc_default),
            ("TC-F-08", ["AC-001F-04f", "AC-001F-08a"], tc_listing_integrity),
            ("TC-F-09", ["AC-001F-05a", "AC-001F-05b", "AC-001F-05c", "AC-001F-05d", "AC-001F-05e", "AC-001F-05f",
                         "AC-001F-07c", "AC-001F-02b", "AC-001F-02h"], tc_tags),
            ("TC-F-10", ["AC-001F-06a", "AC-001F-06b", "AC-001F-06c", "AC-001F-06d", "AC-001F-06e", "AC-001F-06h",
                         "AC-001F-01d"], tc_exit_impact),
            ("TC-F-11", ["AC-001F-06f", "AC-001F-06e", "AC-001F-08a"], tc_unreadable),
            ("TC-F-12", ["AC-001F-02j", "AC-001F-06g", "AC-001F-06i"], tc_concurrency),
            ("TC-F-13", ["AC-001F-02k", "AC-001F-08c"], tc_path_safety),
            ("TC-F-14", ["AC-001F-06j", "AC-001F-09a", "AC-001F-06e", "AC-001F-04e"], tc_pre_upgrade),
            ("TC-F-15", ["AC-001F-09f"], tc_consumers),
            ("TC-F-18", ["AC-001F-02a", "AC-001F-03g", "AC-001F-04d", "AC-001F-04f", "AC-001F-04i", "AC-001F-04k",
                         "AC-001F-09g", "AC-001F-05e", "AC-001F-07c", "AC-001F-01g", "AC-001F-04e", "AC-001F-06b"],
             tc_skill_text),
            ("TC-F-16", ["AC-001F-07a", "AC-001F-07b", "AC-001F-07c", "AC-001F-07d"], tc_authorization),
        ]
    else:
        plan = [("TC-F-17", ["AC-001F-07c", "AC-001F-07d", "AC-001F-07a", "AC-001F-02g", "AC-001F-04e",
                             "AC-001F-06e"], tc_host_user),
                ("TC-F-18", ["AC-001F-02a", "AC-001F-03g", "AC-001F-04d", "AC-001F-04f", "AC-001F-04i", "AC-001F-04k",
                             "AC-001F-09g", "AC-001F-05e", "AC-001F-07c", "AC-001F-01g", "AC-001F-04e",
                             "AC-001F-06b"], tc_skill_text)]
    for tc, acs, fn in plan:
        if not only or tc in only:
            case(tc, acs, fn)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS),
                                  "checks": sum(len(r.get("checks", [])) for r in RESULTS),
                                  "failed_checks": sum(len(r.get("failed", [])) for r in RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
