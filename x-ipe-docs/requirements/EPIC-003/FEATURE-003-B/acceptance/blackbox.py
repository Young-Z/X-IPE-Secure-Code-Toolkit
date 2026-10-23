"""Black-box acceptance scenarios for FEATURE-003-B Single-source Host Integration Carriers (TASK-063).

Calls the real CLI only: `uvx --from <framework>/scripts secure-code ...` (and, for the pre-003B and
bumped-version cases, `uvx --from <toolkit copy>/.../scripts secure-code ...`). Never imports toolkit code.
Prints one JSON object per test case on stdout. Every carrier write happens in disposable sandbox
projects below FAT_WORK; nothing is written into the toolkit or any repository.

  python3 blackbox.py host        # macOS host (User path; no trust-store writes)
  FAT_ISOLATED=1 python3 blackbox.py container   # offline Linux container (disposable HOME)

Environment:
  TOOLKIT_ROOT  toolkit folder (default: the workspace's ai-secure-code-toolkit)
  FAT_WORK      folder for disposable sandbox projects (default: platform temp folder)
  FAT_OLD_PKG   folder `x_ipe_secure_code` of the pre-FEATURE-003-B code (taken from a uv cache build of
                the baseline revision; hashes in the acceptance report)
  FAT_TINY      (container only) a small tmpfs mount used to provoke a real ENOSPC write failure

Fixtures (disclosed):
- A "FEATURE-001-A-era payload" is a copy of the toolkit without `references/routing-definition.json`.
- A "pre-003B toolkit" is that copy with `scripts/src/x_ipe_secure_code` replaced by FAT_OLD_PKG, i.e. the
  baseline code (no carriers operation); it is built and run by uvx like any toolkit version.
- A "bumped toolkit" is a copy with version 0.2.0 (real second toolkit version).
- Maintainer edits of the installed routing definition, user edits of carriers, canary secrets,
  record edits (invalid member, lost digest) and symbolic links are plain file operations by this runner.
- The project lock is held by a helper Python process (not toolkit code) via flock on the project root.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOLKIT = (Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ
           else Path(__file__).resolve().parents[5] / "ai-secure-code-toolkit")
FW = "x-ipe-secure-code-toolkit-framework"
SKILLS = (FW, "x-ipe-secure-code-toolkit-copilot", "x-ipe-secure-code-toolkit-guard")
SCRIPTS = TOOLKIT / FW / "scripts"
OLD_PKG = Path(os.environ["FAT_OLD_PKG"]) if os.environ.get("FAT_OLD_PKG") else None
WORK = Path(os.environ.get("FAT_WORK") or tempfile.gettempdir()) / "fat-003b-run"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
MODE = sys.argv[1] if len(sys.argv) > 1 else "host"

GC, CC = "github-copilot", "claude-code"
BEGIN = "<!-- BEGIN ai-secure-code-toolkit: managed fragment, edits are reported not overwritten -->"
END = "<!-- END ai-secure-code-toolkit -->"
FM = '---\napplyTo: "**"\n---\n'
INSTR = ".github/instructions/x-ipe-secure-code-toolkit.instructions.md"
SP = ".x-ipe/private/secure-code/carriers/system-prompt.md"
RECORD = ".x-ipe/private/secure-code/install-record.json"
DEF_REL = f"{FW}/references/routing-definition.json"
RECORD_KEYS_001A = {"schema", "toolkit_version", "environment", "skills_dir", "host_entry",
                    "fragment_sha256", "initialized_at", "updated_at", "files"}
INIT_DATA_KEYS_001A = {"root", "environment", "skills_dir", "host_entry", "files", "fragment",
                       "layout_created", "record", "already_current"}
HOST_KEYS_001A = {"environment", "host_entry", "fragment", "host_effect", "next_step"}
HOST_EFFECT = "written / component-checked; host effect not verified"
MASK_LABEL = "secret-masked (pattern-based; not a complete data-loss-prevention guarantee)"
USER_CONTENT = "detected outside the managed boundaries (kept)"
SECTION_ORDER = ("copilot", "guard", "deduplication", "results", "roles", "handoff")
PROFILE = {GC: (".github/skills", "AGENTS.md"), CC: (".claude/skills", "CLAUDE.md")}
KINDS = {GC: ["host-entry", "github-instructions", "system-prompt"], CC: ["host-entry", "system-prompt"]}
CHOICES = ["keep (default)", "modify, then keep or accept", "change the routing definition",
           "regenerate (--regenerate {k})", "accept customization (--accept {k})"]

# FEATURE-001-A minimal fragment body (FEATURE-001-A `host_fragment.render_body`, text of the delivered
# FEATURE-001-A revision `a14b9b85…`); also compared byte-for-byte with what the pre-003B code writes.
GOLDEN_001A = (
    "## AI Secure Code Toolkit\n"
    "\n"
    "This project uses the AI secure-code toolkit skills in `{s}/`:\n"
    "\n"
    "- `x-ipe-secure-code-toolkit-copilot`: use during design, implementation, bug fix and "
    "refactor tasks for in-flow security suggestions and adoption review.\n"
    "- `x-ipe-secure-code-toolkit-guard`: use only for an explicit or authorized security "
    "verification request; it reports findings and does not fix.\n"
    "- `x-ipe-secure-code-toolkit-framework`: security knowledge, Policies, status and "
    "Maintainer authorization.\n"
    "\n"
    "Check status: `uvx --from {s}/x-ipe-secure-code-toolkit-framework/scripts "
    "secure-code status --project . --json`\n"
)

# Canary secrets, assembled from parts so this file holds no real-looking secret literal.
CAN_TOKEN = "ghp_" + "Fa7" * 13
CAN_AWS = "AKIA" + "ZB4Q" * 4
CAN_PEM_BODY = "kP8s" * 12
CAN_PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIB" + CAN_PEM_BODY + "\n-----END " + "PRIVATE KEY-----"
CAN_PASS = "Tr0ub4dor" + "Xq7Lm"
NEEDLES = [CAN_TOKEN, CAN_AWS, CAN_PEM_BODY, CAN_PASS]
MARKERS = ["[masked:credential.token]", "[masked:credential.cloud_key]",
           "[masked:credential.private_key]", "[masked:credential.assignment]"]

RESULTS: list[dict] = []
OUTPUTS: list[str] = []
CASE_ERR: list[str] = []
ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
_COUNTER = [0]
_CACHE: dict[str, Path] = {}


# ---------------------------------------------------------------- CLI
class R:
    def __init__(self, code, data, out, err, secs):
        self.code, self.data, self.out, self.err, self.secs = code, data, out, err, secs

    @property
    def text(self) -> str:
        return self.out + self.err

    def codes(self) -> list[str]:
        return [p["code"] for p in (self.data or {}).get("problems", [])]

    def dd(self) -> dict:
        return (self.data or {}).get("data", {}) or {}

    def states(self) -> dict:
        return {c["carrier"]: c["state"] for c in self.dd().get("carriers", [])}


def _cmd(args, scripts):
    return ["uvx", "--from", str(scripts or SCRIPTS), "secure-code", *map(str, args)]


def _finish(proc_out, proc_err, code, args, started) -> R:
    OUTPUTS.extend([proc_out, proc_err])
    CASE_ERR.append(proc_err)
    data = None
    if "--json" in args:
        try:
            data = json.loads(proc_out)
        except json.JSONDecodeError:
            data = None
    return R(code, data, proc_out, proc_err, time.time() - started)


def sc(*args, scripts: Path | None = None, timeout: int = 300) -> R:
    started = time.time()
    proc = subprocess.run(_cmd(args, scripts), capture_output=True, text=True, env=ENV, timeout=timeout)
    return _finish(proc.stdout, proc.stderr, proc.returncode, args, started)


def spawn(*args, scripts: Path | None = None):
    proc = subprocess.Popen(_cmd(args, scripts), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=ENV)
    return proc, args, time.time()


def join(spawned) -> R:
    proc, args, started = spawned
    out, err = proc.communicate(timeout=300)
    return _finish(out, err, proc.returncode, args, started)


def init(p: Path, *extra, env: str = GC, scripts: Path | None = None, json_: bool = True) -> R:
    return sc("init", "--project", p, "--env", env, *extra, *(["--json"] if json_ else []), scripts=scripts)


def car(p: Path, *extra, env: str = GC, scripts: Path | None = None, json_: bool = True) -> R:
    return sc("carriers", "--project", p, "--env", env, *extra, *(["--json"] if json_ else []),
              scripts=scripts)


def status(p: Path, json_: bool = True, scripts: Path | None = None) -> R:
    return sc("status", "--project", p, *(["--json"] if json_ else []), scripts=scripts)


ALL3 = ("--select", "github-instructions", "--select", "system-prompt", "--system-prompt-host", "copilot-cli")


# ---------------------------------------------------------------- files and snapshots
def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_text(text: str) -> str:
    return sha(text.replace("\r\n", "\n").encode("utf-8"))


def snap(root: Path) -> dict:
    """Every entry below root: kind, content hash, inode and mtime (strong no-write evidence)."""
    out = {}
    if not root.exists():
        return out
    st = os.lstat(root)
    out["."] = ("d", None, st.st_ino, st.st_mtime_ns)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = os.lstat(path)
            rel = path.relative_to(root).as_posix()
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("l", os.readlink(path), st.st_ino, st.st_mtime_ns)
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("d", None, st.st_ino, st.st_mtime_ns)
            else:
                try:
                    digest = sha(path.read_bytes())
                except PermissionError:
                    digest = "unreadable"
                out[rel] = ("f", digest, st.st_ino, st.st_mtime_ns)
    return out


def changed_files(a: dict, b: dict) -> set[str]:
    """Paths whose content/kind differ (directories compared by existence only)."""
    keys = set(a) | set(b)
    diff = set()
    for k in keys:
        x, y = a.get(k), b.get(k)
        if x is None or y is None:
            diff.add(k)
        elif x[0] != y[0] or (x[0] != "d" and x[1] != y[1]):
            diff.add(k)
    return diff


def read(p: Path, rel: str) -> str:
    return (p / rel).read_bytes().decode("utf-8")


def write(p: Path, rel: str, text: str | bytes) -> None:
    target = p / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))


def begins(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip() == BEGIN)


def split_block(text: str) -> tuple[str, str, str]:
    """(prefix, inner, suffix) around the single marker block."""
    lines = text.splitlines(keepends=True)
    b = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    e = [i for i, line in enumerate(lines) if line.strip() == END]
    assert len(b) == 1 and len(e) == 1 and b[0] < e[0], "expected one marker block"
    return "".join(lines[:b[0]]), "".join(lines[b[0] + 1:e[0]]), "".join(lines[e[0] + 1:])


def inner_of(p: Path, rel: str) -> str:
    return split_block(read(p, rel))[1]


def edit_inner(p: Path, rel: str, *extra_lines: str) -> None:
    """User edit inside the toolkit fragment: insert lines (in order) after the first body lines."""
    text = read(p, rel)
    nl = "\r\n" if "\r\n" in text else "\n"
    pre, inner, suf = split_block(text)
    lines = inner.splitlines(keepends=True)
    lines[2:2] = [line + nl for line in extra_lines]
    write(p, rel, pre + BEGIN + nl + "".join(lines) + END + nl + suf)


def record(p: Path) -> dict:
    return json.loads(read(p, RECORD))


def no_bare_lf(text: str) -> bool:
    return "\n" not in text.replace("\r\n", "")


def chmod_tree_back(path: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames:
            os.chmod(Path(dirpath) / name, 0o755)
        for name in filenames:
            q = Path(dirpath) / name
            if not q.is_symlink():
                os.chmod(q, 0o644)


# ---------------------------------------------------------------- independent rendering (design Part 2)
def toolkit_version(root: Path = TOOLKIT) -> str:
    text = (root / FW / "scripts/src/x_ipe_secure_code/__init__.py").read_text(encoding="utf-8")
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def defn_of(p: Path, env: str = GC) -> dict:
    return json.loads(read(p, f"{PROFILE[env][0]}/{DEF_REL}"))


def def_digest(obj: dict) -> str:
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return sha(canonical.encode("utf-8"))


def identity(obj: dict, version: str) -> str:
    return f"ai-secure-code-toolkit {version}, definition sha256:{def_digest(obj)}"


def render(obj: dict, version: str, env: str, kind: str, host: str | None = None) -> str:
    skills_dir, host_entry = PROFILE[env]
    third = {"host-entry": f"Integration carrier: host entry (`{host_entry}`).",
             "github-instructions": "Integration carrier: GitHub instructions.",
             "system-prompt": f'Integration carrier: system-prompt fragment for host "{host}".'}[kind]
    lines = [f"## {obj['title']}", "", f"{third} Routing identity: {identity(obj, version)}.",
             obj["declaration"], "", f"This project uses the AI secure-code toolkit skills in `{skills_dir}/`:", ""]
    lines += [f"- `{s['name']}`: {s['pointer']}" for s in obj["skills"]]
    by_id = {s["id"]: s for s in obj["sections"]}
    for sid in SECTION_ORDER:
        lines += ["", f"### {by_id[sid]['heading']}", ""] + [f"- {st}" for st in by_id[sid]["statements"]]
    lines += ["", "Check status: `" + obj["status_command"].replace("{skills_dir}", skills_dir) + "`"]
    return "\n".join(lines) + "\n"


def block(body: str, nl: str = "\n") -> str:
    return (BEGIN + "\n" + body + END + "\n").replace("\n", nl)


def routing_region(text: str) -> str:
    lines = text.replace("\r\n", "\n").splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith("This project uses"))
    end = next(i for i, line in enumerate(lines) if line.startswith("Check status:"))
    return "".join(lines[start:end + 1])


def edit_definition(p: Path, tag: str, env: str = GC) -> dict:
    """A valid Maintainer edit of the installed routing definition (changes its identity)."""
    rel = f"{PROFILE[env][0]}/{DEF_REL}"
    obj = json.loads(read(p, rel))
    sec = next(s for s in obj["sections"] if s["id"] == "results")
    sec["statements"][-1] = sec["statements"][-1].rstrip(".") + f" (team wording {tag})."
    write(p, rel, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    return obj


# ---------------------------------------------------------------- projects and toolkit copies
def new_dir(tag: str) -> Path:
    _COUNTER[0] += 1
    d = WORK / f"{tag}-{_COUNTER[0]}" / "outer"
    d.mkdir(parents=True)
    return d


def proj(tag: str, env: str = GC, pre=None, do_init: bool = True, scripts: Path | None = None,
         extra=()) -> Path:
    p = new_dir(tag) / "proj ü"
    p.mkdir()
    if pre:
        pre(p)
    if do_init:
        r = init(p, *extra, env=env, scripts=scripts)
        if r.code != 0:
            raise RuntimeError(f"fixture init failed: {r.codes()}")
    return p


def clone(p: Path, tag: str) -> Path:
    dst = new_dir(tag) / "proj ü"
    shutil.copytree(p, dst, symlinks=True)
    return dst


IGNORE = shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".coverage", "*.pyc")


def toolkit_copy(kind: str) -> Path:
    """era: payload without routing definition; old: era + pre-003B code; bumped: version 0.2.0;
    changed: routing definition with one changed statement."""
    if kind in _CACHE:
        return _CACHE[kind]
    dst = WORK / f"toolkit-{kind}" / "ai-secure-code-toolkit"
    shutil.copytree(TOOLKIT, dst, ignore=IGNORE)
    fw = dst / FW
    if kind in ("era", "old"):
        (fw / "references/routing-definition.json").unlink()
    if kind == "old":
        src = fw / "scripts/src/x_ipe_secure_code"
        shutil.rmtree(src)
        shutil.copytree(OLD_PKG, src, ignore=IGNORE)
    if kind == "bumped":
        init_py = fw / "scripts/src/x_ipe_secure_code/__init__.py"
        init_py.write_text(init_py.read_text(encoding="utf-8").replace('"0.1.0"', '"0.2.0"'), encoding="utf-8")
        pyproject = fw / "scripts/pyproject.toml"
        pyproject.write_text(pyproject.read_text(encoding="utf-8").replace('version = "0.1.0"',
                                                                          'version = "0.2.0"', 1),
                             encoding="utf-8")
    if kind == "changed":
        path = fw / "references/routing-definition.json"
        obj = json.loads(path.read_text(encoding="utf-8"))
        sec = next(s for s in obj["sections"] if s["id"] == "handoff")
        sec["statements"][-1] = sec["statements"][-1].rstrip(".") + " (new toolkit wording)."
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _CACHE[kind] = dst
    return dst


def scripts_of(kind: str) -> Path:
    return toolkit_copy(kind) / FW / "scripts"


def hold_lock(root: Path, seconds: float):
    """A helper process (not toolkit code) holding flock on the project root folder."""
    code = ("import fcntl,os,sys,time\nfd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('ready', flush=True)\ntime.sleep(float(sys.argv[2]))\n")
    proc = subprocess.Popen([sys.executable, "-c", code, str(root), str(seconds)], stdout=subprocess.PIPE,
                            text=True)
    if proc.stdout.readline().strip() != "ready":
        raise RuntimeError("lock holder did not start")
    return proc


def trust_dir() -> Path:
    home = Path(os.path.expanduser("~"))
    if sys.platform == "darwin":
        return home / "Library/Application Support/ai-secure-code-toolkit"
    return home / ".config/ai-secure-code-toolkit"


def norm(obj, *roots: Path):
    """JSON value with project roots replaced and timestamps blanked (for result comparison)."""
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    for i, root in enumerate(roots):
        text = text.replace(str(root), f"<ROOT{i}>")
    text = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "<TIME>", text)
    return json.loads(text)


def no_needles(*texts: str) -> bool:
    blob = "\n".join(texts)
    return not any(n in blob for n in NEEDLES)


# ---------------------------------------------------------------- case runner
def case(tc: str, acs: list[str], fn, *, only: str | None = None) -> None:
    if only and MODE != only:
        return
    started = time.time()
    CASE_ERR.clear()
    notes: dict = {}
    try:
        checks = fn(notes)
        tracebacks = [e for e in CASE_ERR if "Traceback" in e]
        checks.append(("no traceback on stderr of any CLI run", not tracebacks))
        failed = [name for name, ok in checks if not ok]
        status_ = "Pass" if not failed else "Fail"
        detail = {"checks": [name for name, _ in checks], "failed": failed}
    except Exception as exc:  # noqa: BLE001 - an unexpected error is a failed case
        status_, detail = "Fail", {"error": f"{type(exc).__name__}: {exc}"}
    row = {"tc": tc, "acs": acs, "status": status_, "seconds": round(time.time() - started, 1), **detail}
    if notes:
        row["notes"] = notes
    RESULTS.append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)


# ================================================================ TC-B-01  all carriers, one identity
ABS_PATH = re.compile(r"(^|[\s`(])(/[^\s/]|~/|[A-Za-z]:\\)")
SECRETISH = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|"
                       r"\bsk-[A-Za-z0-9]{20,}|(?i:password|passphrase|secret|api[_-]?key)\s*[:=]")
CLAIMS = re.compile(r"(?i)loaded by|is loaded|host loads|routing (?:was |is )?verified|verified routing|"
                    r"host effect: verified|host effect verified")


def _verified_only_negated(text: str) -> bool:
    return all(text[max(0, m.start() - 4):m.start()].lower() == "not " for m in re.finditer(r"verified", text))


def tc_b01_all_carriers(notes):
    p = proj("b01")
    outer = p.parent
    outer_before = {k: v for k, v in snap(outer).items() if not k.startswith("proj ü")}
    trust_before = snap(trust_dir())
    home = Path(os.path.expanduser("~"))
    home_before = None
    if MODE == "container":
        home_before = {k: v for k, v in snap(home).items()
                       if not k.startswith((".cache", "fat-work", "fat-tmp"))}
    d, v = defn_of(p), toolkit_version()
    ident = identity(d, v)
    r = car(p, *ALL3)
    rt = car(p, json_=False)
    st = status(p)
    sh = st.dd().get("host_integration", {})
    agents, instr, spf = read(p, "AGENTS.md"), read(p, INSTR), read(p, SP)
    bodies = {"host-entry": render(d, v, GC, "host-entry"), "github-instructions": render(d, v, GC, "github-instructions"),
              "system-prompt": render(d, v, GC, "system-prompt", "copilot-cli")}
    inners = {"host-entry": split_block(agents)[1], "github-instructions": split_block(instr)[1],
              "system-prompt": split_block(spf)[1]}
    skill_lines = set()
    for s in SKILLS:
        for line in read(p, f".github/skills/{s}/SKILL.md").splitlines():
            if len(line.strip(" -*")) >= 30:
                skill_lines.add(line.strip(" -*"))
    carrier_texts = list(inners.values())
    sp_data = r.dd().get("system_prompt", {})
    declaration = r.dd().get("integration_declaration", "")
    out_after = {k: v2 for k, v2 in snap(outer).items() if not k.startswith("proj ü")}
    checks = [
        ("01a run ok", r.code == 0 and r.data["ok"]),
        ("01a states host current, instructions+system-prompt created",
         r.states() == {"host-entry": "current", "github-instructions": "created", "system-prompt": "created"}),
        ("01a three carriers at the decided locations",
         all((p / rel).is_file() for rel in ("AGENTS.md", INSTR, SP))),
        ("01a every managed body equals the independent rendering of the installed definition",
         all(inners[k] == bodies[k] for k in bodies)),
        ("01a same identity (version + definition digest) in every carrier",
         all(f"Routing identity: {ident}." in t for t in carrier_texts) and r.dd().get("routing_identity") == ident),
        ("01a result paths named", {c["path"] for c in r.dd().get("carriers", [])} == {"AGENTS.md", INSTR, SP}),
        ("03b instructions file = exact front matter + blank line + marker block",
         instr == FM + "\n" + block(bodies["github-instructions"])),
        ("03b result names instructions path and state",
         any(c["path"] == INSTR and c["state"] == "created" and c["front_matter"] == "ok"
             for c in r.dd().get("carriers", []))),
        ("03c system-prompt file under .x-ipe/private/secure-code/carriers", spf == block(bodies["system-prompt"])),
        ("03c fragment shown in the result", sp_data.get("content") == bodies["system-prompt"].splitlines()
         and sp_data.get("path") == SP and sp_data.get("host") == "copilot-cli"),
        ("03c manual step stated", "manual step" in sp_data.get("manual_step", "")
         and "never changes host, global or user-level configuration" in sp_data.get("manual_step", "")),
        ("03c nothing outside the project root changed", out_after == outer_before),
        ("03c trust store unchanged", snap(trust_dir()) == trust_before),
        ("03h no credential/key/authorization material in the fragment", not SECRETISH.search(spf)),
        ("03h carriers folder holds only the fragment",
         sorted(x.name for x in (p / SP).parent.iterdir()) == ["system-prompt.md"]),
        ("03h no key/trust/grant/revocation file next to it",
         not [x for x in (p / ".x-ipe/private/secure-code").rglob("*")
              if re.search(r"(?i)key|trust|grant|revoc|\.pem$", x.name)]),
        ("01c no absolute machine path in any carrier", not any(ABS_PATH.search(t) for t in carrier_texts)
         and not any(str(WORK) in t or str(home) in t for t in carrier_texts)),
        ("01c no credential in any carrier", not any(SECRETISH.search(t) for t in carrier_texts)),
        ("01c no carrier line is a copied SKILL.md line (>=30 chars)",
         not any(line.strip(" -*") in skill_lines for t in carrier_texts for line in t.splitlines())),
        ("01c only statements, three pointers and the status command",
         all(len(re.findall(r"^- `x-ipe-secure-code-toolkit-", t, re.M)) == 3
             and t.count("Check status:") == 1 for t in carrier_texts)),
        ("01f routing statements identical in AGENTS.md and instructions",
         routing_region(inners["host-entry"]) == routing_region(inners["github-instructions"])),
        ("01f declaration sentence in each carrier",
         all("one integration declaration" in t and "at most one Copilot or Guard flow for the same stage and effective context"
             in t for t in carrier_texts)),
        ("01f result names both carriers as one declaration with one identity",
         "one integration declaration" in declaration and "AGENTS.md" in declaration and INSTR in declaration
         and ident in declaration and declaration.count("sha256:") == 1),
        ("01f status: same declaration and identity",
         "one integration declaration" in sh.get("integration_declaration", "") and sh.get("routing_identity") == ident),
        ("06c generation result: written / component-checked; host effect not verified",
         r.dd().get("host_effect") == HOST_EFFECT and HOST_EFFECT in rt.out),
        ("06c status: host effect not verified for the section and every carrier",
         sh.get("host_effect") == "not verified"
         and all(c.get("host_effect") == "not verified" for c in sh.get("carriers", []))),
        ("06c no host-loading or verified-routing claim in results, status or carriers",
         not any(CLAIMS.search(t) for t in [r.out, rt.out, json.dumps(sh), *carrier_texts])
         and _verified_only_negated(r.out + rt.out + json.dumps(sh))),
    ]
    if home_before is not None:
        home_after = {k: v2 for k, v2 in snap(home).items() if not k.startswith((".cache", "fat-work", "fat-tmp"))}
        checks.append(("03c no user-level configuration changed (container HOME)", home_after == home_before))
    return checks


# ================================================================ TC-B-02  routing content
STATEMENTS = {
    "02a": ["Use the Copilot skill proactively for every design, implementation, bug fix and refactor task, "
            "including changes to an existing design.",
            "Do not use the Copilot skill for plain questions or read-only knowledge lookups, and not to verify "
            "already finished artifacts."],
    "02b": ["Use the Guard skill only on an explicit verification request or an authorized upstream verification step.",
            "Never start Guard automatically because an artifact was completed, and never use Guard instead of "
            "Copilot for in-flow suggestions."],
    "02c": ["Loading several toolkit carriers never starts a Copilot or Guard flow more than once; they are one "
            "integration declaration.",
            "Do not start the flow again for the same stage and the same effective context.",
            "Evaluate again after a relevant change of input or stage; never skip it permanently.",
            "A read-only Reviewer never starts the Copilot or Guard flow.",
            "Do not merge different Framework needs within one task."],
    "02d": ["A failed or old report never counts as done for the current work.",
            "Report an unavailable skill or invalid output as not completed; the upstream caller decides under its "
            "existing gates.",
            "Never make up Policies from memory.", "Continuing the work is not passing.",
            "Never bypass mandatory gates silently."],
    "02e": ["Framework: pass the scenario, rule clues and information need; it returns concrete Policies, sources "
            "and unresolved items.",
            "Copilot: pass the task, the current artifact or change and the constraints; it returns concrete "
            "suggestions, the adoption review and items not adopted or not verifiable.",
            "Guard: pass the formed artifact, explicit targets, rule clues and the execution authorization and budget; "
            "it returns the three-state verdict, findings, coverage gaps and execution state.",
            "Only naming a skill is not a completed handoff; the upstream caller acts on the results."],
    "02g": ["Roles come only from actual verification: the Maintainer by the owner-signed authorization, agents by "
            "real requests or signed pre-authorization.",
            "This carrier text grants no role, permission or consent."],
}


def _when_to_use(text: str) -> str:
    m = re.search(r"^## When to Use\n(.*?)(?=^## )", text, re.S | re.M)
    return re.sub(r"\s+", " ", m.group(1)) if m else ""


def tc_b02_routing_content(notes):
    texts = {}
    pg = proj("b02gc")
    car(pg, *ALL3)
    texts.update({f"gc:{k}": inner_of(pg, rel) for k, rel in
                  (("host-entry", "AGENTS.md"), ("github-instructions", INSTR), ("system-prompt", SP))})
    pc = proj("b02cc", env=CC)
    car(pc, "--select", "system-prompt", "--system-prompt-host", "claude-cli", env=CC)
    texts.update({f"cc:{k}": inner_of(pc, rel) for k, rel in (("host-entry", "CLAUDE.md"), ("system-prompt", SP))})
    checks = []
    for ac, stmts in STATEMENTS.items():
        checks.append((f"{ac} every statement in all 5 carriers (gc x3, cc x2)",
                       all(f"- {s}\n" in t for s in stmts for t in texts.values())))
    cop_skill = read(pg, ".github/skills/x-ipe-secure-code-toolkit-copilot/SKILL.md")
    grd_skill = read(pg, ".github/skills/x-ipe-secure-code-toolkit-guard/SKILL.md")
    cw, gw = _when_to_use(cop_skill), _when_to_use(grd_skill)
    t = texts["gc:host-entry"]
    copilot_lines = [line for line in t.splitlines() if "Copilot skill" in line or "`x-ipe-secure-code-toolkit-copilot`" in line]
    guard_lines = [line for line in t.splitlines() if "Guard skill" in line or "`x-ipe-secure-code-toolkit-guard`" in line]
    checks += [
        ("02a Copilot trigger covered by Copilot When to Use (design/implementation/bug fix/refactor, existing design)",
         "Design, implementation, bug fix or refactor tasks" in cw and "changes to an existing design" in cw),
        ("02f Copilot non-use agrees: plain questions, read-only lookups, not verifying finished artifacts",
         "Not for plain questions or read-only lookups" in cw and "not for verifying already finished artifacts" in cw
         and "not to verify already finished artifacts" in t),
        ("02f Guard trigger covered by Guard When to Use (explicit / authorized upstream verification)",
         "An explicit verification request, or an authorized upstream verification step" in gw),
        ("02f Guard non-use agrees: not for in-flow suggestions",
         "Not for in-flow suggestions" in gw and "never use Guard instead of Copilot for in-flow suggestions" in t),
        ("02f every Copilot trigger line points to Copilot, every Guard trigger to Guard",
         all("verif" not in line or "not to verify" in line for line in copilot_lines if "Use the Copilot" in line)
         and all("explicit" in line or "Never start Guard" in line or "verification" in line for line in guard_lines)),
        ("02f skill descriptions agree (Copilot: design/implement/fix/refactor; Guard: explicit or authorized)",
         "Use when an agent designs, implements, fixes or refactors code" in cop_skill
         and "Use only on an explicit or authorized security verification request" in grd_skill),
        ("02b no statement starts Guard on completion or replaces Copilot",
         not re.search(r"(?i)^- (?!Never).*Guard.*(automatic|on completion)", t, re.M)),
        ("02a/02f same statements in every carrier kind and environment (only line 3 and skills folder differ)",
         len({routing_region(x).replace(".claude/skills", ".github/skills") for x in texts.values()}) == 1),
    ]
    return checks


# ================================================================ TC-B-03  definition change A -> B
def tc_b03_definition_change(notes):
    checks = []
    v = toolkit_version()
    # (a) Maintainer edit of the installed definition; one carrier edited by the user beforehand.
    p = proj("b03a")
    car(p, *ALL3)
    a = defn_of(p)
    edit_inner(p, SP, "- Team note inside the system-prompt fragment.")
    sp_before = read(p, SP)
    b = edit_definition(p, "B")
    r = car(p)
    st = status(p)
    idb, ida = identity(b, v), identity(a, v)
    checks += [
        ("01b(a) run ok", r.code == 0),
        ("01b(a) unedited carriers updated in the same run, listed", r.states().get("host-entry") == "updated"
         and r.states().get("github-instructions") == "updated"),
        ("01b(a) updated carriers state identity B and equal rendering B",
         inner_of(p, "AGENTS.md") == render(b, v, GC, "host-entry")
         and inner_of(p, INSTR) == render(b, v, GC, "github-instructions")),
        ("01b(a) edited carrier still on A is reported as a difference (kept)",
         r.states().get("system-prompt") == "kept-differs" and "FRAGMENT_EDITED" in r.codes()
         and SP in r.dd().get("differences", {}) and read(p, SP) == sp_before and ida in sp_before),
        ("01b(a) no unreported carrier states identity A",
         ida not in read(p, "AGENTS.md") and ida not in read(p, INSTR)),
        ("01b(a) record identity B for updated carriers",
         record(p)["carriers"]["entries"]["github-instructions"]["routing"]["definition_sha256"] == def_digest(b)
         and record(p)["fragment_sha256"] == sha_text(render(b, v, GC, "host-entry"))),
        ("01b(a) status identity B", st.dd()["host_integration"]["routing_identity"] == idb),
    ]
    # (b) new toolkit version (real 0.2.0 copy) runs carriers on a 0.1.0 project.
    q = proj("b03b")
    car(q, *ALL3)
    dq = defn_of(q)
    bumped = scripts_of("bumped")
    r1 = car(q, scripts=bumped)
    id2 = identity(dq, "0.2.0")
    checks += [
        ("01b(b) bumped toolkit carriers ok, all three updated in one run",
         r1.code == 0 and set(r1.states().values()) == {"updated"} and len(r1.states()) == 3),
        ("01b(b) every carrier states 0.2.0 identity", all(f"Routing identity: {id2}." in read(q, rel)
                                                           for rel in ("AGENTS.md", INSTR, SP))),
        ("01b(b) no FRAGMENT_EDITED / no refusal on version change", "FRAGMENT_EDITED" not in r1.codes()),
    ]
    r2 = init(q, scripts=bumped)
    r3 = car(q, scripts=bumped)
    checks += [
        ("01b(b) bumped init then carriers: host entry current, all current",
         r2.code == 0 and r2.dd().get("fragment") == "current" and set(r3.states().values()) == {"current"}),
        ("01b(b) no carrier states 0.1.0 identity afterwards",
         not any(identity(dq, v) in read(q, rel) for rel in ("AGENTS.md", INSTR, SP))),
    ]
    # (c) new definition delivered by a toolkit source (init) then carriers.
    w = proj("b03c")
    car(w, *ALL3)
    r4 = init(w, "--toolkit-source", toolkit_copy("changed"))
    c_def = defn_of(w)
    r5 = car(w)
    checks += [
        ("01b(c) init with changed definition updates definition and host entry",
         r4.code == 0 and f".github/skills/{DEF_REL}" in r4.dd()["files"]["updated"]
         and r4.dd().get("fragment") == "update"),
        ("01b(c) carriers then updates the other unedited carriers to the new identity",
         r5.states() == {"host-entry": "current", "github-instructions": "updated", "system-prompt": "updated"}
         and all(f"Routing identity: {identity(c_def, v)}." in read(w, rel) for rel in ("AGENTS.md", INSTR, SP))),
    ]
    return checks


# ================================================================ TC-B-04  pre-003B install, two-step upgrade
def _record_without_times(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k not in ("initialized_at", "updated_at")}


def tc_b04_pre003b_upgrade(notes):
    checks = []
    old = scripts_of("old")
    era = toolkit_copy("era")
    golden = block(GOLDEN_001A.format(s=".github/skills"))
    # Real pre-003B toolkit version (baseline code) installs the project.
    p = proj("b04real", do_init=False)
    r0 = init(p, scripts=old)
    rec0 = record(p)
    s0 = snap(p)
    checks += [
        ("01d pre-003B init ok, FEATURE-001-A minimal fragment (golden bytes)",
         r0.code == 0 and read(p, "AGENTS.md") == golden),
        ("01d pre-003B record: 8 FEATURE-001-A fields, no member, no routing definition",
         set(rec0) == RECORD_KEYS_001A and f".github/skills/{DEF_REL}" not in rec0["files"]
         and not (p / f".github/skills/{DEF_REL}").exists()),
    ]
    r1 = car(p)
    r1t = car(p, json_=False)
    checks += [
        ("01d step 1: carriers refused ROUTING_DEFINITION_INVALID naming the missing definition",
         r1.code == 1 and r1.codes() == ["ROUTING_DEFINITION_INVALID"]
         and "routing-definition.json" in r1.data["problems"][0]["message"]),
        ("01d step 1: next step secure-code init", any("secure-code init" in s for s in r1.data["next_steps"])
         and "secure-code init" in r1t.out),
        ("01d step 1: nothing written (tree incl. inodes/mtimes identical)", snap(p) == s0),
    ]
    r2 = init(p)
    rec2 = record(p)
    v = toolkit_version()
    checks += [
        ("01d step 2: plain init installs the routing definition under safe-reinstall rules",
         r2.code == 0 and f".github/skills/{DEF_REL}" in r2.dd()["files"]["created"]
         and f".github/skills/{DEF_REL}" in rec2["files"]),
        ("01d step 2: unedited fragment updated in place (update, not edited)",
         r2.dd().get("fragment") == "update" and "FRAGMENT_EDITED" not in r2.codes()),
        ("01d step 2: exactly one fragment, same markers, rendering of the definition",
         begins(read(p, "AGENTS.md")) == 1 and read(p, "AGENTS.md") == block(render(defn_of(p), v, GC, "host-entry"))),
        ("01d step 2: initialized_at kept", rec2["initialized_at"] == rec0["initialized_at"]),
        ("08b FEATURE-001-A record read without loss (no member added by plain init)",
         set(rec2) == RECORD_KEYS_001A),
    ]
    r3 = car(p)
    checks.append(("01d step 3: carriers succeeds, host entry current",
                   r3.code == 0 and r3.states() == {"host-entry": "current"}))
    # Same FEATURE-001-A-era payload installed by the pre-003B code and by this version: byte-identical.
    a = proj("b04old", do_init=False)
    b = proj("b04new", do_init=False)
    ra = init(a, "--toolkit-source", era, scripts=old)
    rb = init(b, "--toolkit-source", era)
    ra2 = init(a, "--toolkit-source", era, scripts=old)
    rb2 = init(b, "--toolkit-source", era)
    reca, recb = record(a), record(b)
    checks += [
        ("001-A-era --toolkit-source: this version writes the golden FEATURE-001-A fragment",
         rb.code == 0 and read(b, "AGENTS.md") == golden),
        ("001-A-era --toolkit-source: AGENTS.md byte-identical to the pre-003B code's",
         (a / "AGENTS.md").read_bytes() == (b / "AGENTS.md").read_bytes()),
        ("08b/08c record compatibility: records byte-identical apart from timestamps",
         _record_without_times(reca) == _record_without_times(recb) and set(recb) == RECORD_KEYS_001A),
        ("08c init results identical apart from the project root",
         norm(ra.data, a) == norm(rb.data, b) and norm(ra2.data, a) == norm(rb2.data, b)),
        ("08c re-run: both no-op (already current), record bytes unchanged",
         ra2.dd().get("already_current") is True and rb2.dd().get("already_current") is True),
    ]
    s_b = snap(b)
    rb3 = car(b)
    checks += [
        ("03d payload without definition: carriers refused with init next step, nothing written",
         rb3.code == 1 and rb3.codes() == ["ROUTING_DEFINITION_INVALID"] and snap(b) == s_b
         and any("secure-code init" in s for s in rb3.data["next_steps"])),
    ]
    rb4 = init(b)
    rb5 = car(b)
    checks.append(("01d two-step also from the 001-A-era payload: init update, carriers current",
                   rb4.dd().get("fragment") == "update" and rb5.states() == {"host-entry": "current"}))
    # claude-code golden bytes.
    c = proj("b04cc", env=CC, do_init=False)
    rc = init(c, "--toolkit-source", era, env=CC)
    checks.append(("001-A-era --toolkit-source (claude-code): golden FEATURE-001-A fragment in CLAUDE.md",
                   rc.code == 0 and read(c, "CLAUDE.md") == block(GOLDEN_001A.format(s=".claude/skills"))))
    return checks


# ================================================================ TC-B-05  init and carriers interleaved
INIT_TO_CAR = {"current": "current", "update": "updated", "customized": "customized", "append": "appended",
               "create_file": "created"}


def tc_b05_interleaved(notes):
    checks, seq = [], []
    p = proj("b05")
    files = ("AGENTS.md", INSTR, SP)

    def observe(label, r, kind):
        state = r.dd().get("fragment") if kind == "init" else r.states().get("host-entry")
        seq.append(f"{label}:{kind}={state}")
        one = all(begins(read(p, rel)) <= 1 for rel in files if (p / rel).exists())
        clean = "FRAGMENT_EDITED" not in r.codes() and "FRAGMENT_DUPLICATE" not in r.codes() and r.code == 0
        return one and clean, state

    ok_all, pairs = True, []
    steps = [("s1", "car", ()), ("s2", "init", ()), ("s3", "car", ALL3), ("s4", "init", ()),
             ("s5", "edit", None), ("s6", "car", ()), ("s7", "init", ()), ("s8", "edit", None),
             ("s9", "init", ()), ("s10", "car", ()), ("s11", "init", ()), ("s12", "car", ()),
             ("s13", "car", ("--deselect", "system-prompt")), ("s14", "init", ()), ("s15", "car", ())]
    for n, (label, kind, args) in enumerate(steps):
        if kind == "edit":
            edit_definition(p, f"E{n}")
            pairs.append(("edit", None))
            continue
        r = car(p, *args) if kind == "car" else init(p)
        good, state = observe(label, r, kind)
        ok_all = ok_all and good
        pairs.append((kind, state))
    notes["sequence"] = seq
    # After a writing run, the other command (no change in between) must report "current" for the same bytes.
    agree = True
    for i in range(1, len(pairs)):
        prev_kind, _ = pairs[i - 1]
        kind, state = pairs[i]
        if prev_kind != "edit" and kind != "edit" and kind != prev_kind:
            agree = agree and state == "current"
    checks += [
        ("01e every run ok; at most one fragment per carrier file; no FRAGMENT_EDITED/duplicate", ok_all),
        ("01e host entry state the same for init and carriers on unchanged bytes (both current)", agree),
        ("01e after a definition edit, whichever runs first updates (update/updated), never edited",
         "s9:init=update" in seq and "s6:car=updated" in seq),
        ("01e one fragment in AGENTS.md at the end", begins(read(p, "AGENTS.md")) == 1),
    ]
    # Same state reported by both commands for one disk state (fresh copies of the same project).
    q = clone(p, "b05same")
    edit_definition(q, "Z")
    q2 = clone(q, "b05same2")
    ri, rc = init(q), car(q2)
    checks.append(("01e same pending change: init 'update' <-> carriers 'updated' on identical copies",
                   INIT_TO_CAR.get(ri.dd().get("fragment")) == rc.states().get("host-entry") == "updated"))
    return checks


# ================================================================ TC-B-06  accepted host-entry customization
TEAM_LINE = "- Team rule: security review happens in the pull request template."


def accepted_project(tag: str, extra_lines=(TEAM_LINE,)) -> tuple[Path, list[str]]:
    p = proj(tag)
    car(p, "--select", "github-instructions")
    edit_inner(p, "AGENTS.md", *extra_lines)
    r1 = car(p)
    r2 = car(p, "--accept", "host-entry")
    ok = (r1.states().get("host-entry") == "kept-differs" and "FRAGMENT_EDITED" in r1.codes()
          and r2.code == 0 and r2.states().get("host-entry") == "customized")
    if not ok:
        raise RuntimeError("acceptance fixture failed")
    return p, [r1.out, r1.err, r2.out, r2.err]


def _agents_meta(p: Path):
    st = os.lstat(p / "AGENTS.md")
    return (p / "AGENTS.md").read_bytes(), st.st_ino, st.st_mtime_ns


def tc_b06_accepted_customization(notes):
    checks = []
    v = toolkit_version()
    # 01g order A: accept -> init -> carriers
    p, _ = accepted_project("b06a")
    acc = record(p)["carriers"]["entries"]["host-entry"]["accepted"]
    d = defn_of(p)
    checks += [
        ("05d/01g acceptance recorded: digest of the current fragment, identity, time",
         acc["fragment_sha256"] == sha_text(inner_of(p, "AGENTS.md"))
         and acc["routing"] == {"toolkit_version": v, "definition_sha256": def_digest(d)}
         and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", acc["accepted_at"]) is not None),
    ]
    for order, first, second in (("A", "init", "car"), ("B", "car", "init")):
        q = p if order == "A" else accepted_project("b06b")[0]
        meta, member = _agents_meta(q), record(q)["carriers"]
        rec_bytes = (q / RECORD).read_bytes()
        res = {}
        for kind in (first, second):
            res[kind] = init(q) if kind == "init" else car(q)
        ri, rc = res["init"], res["car"]
        checks += [
            (f"01g order {order}: init reports customized (accepted, not synced), no FRAGMENT_EDITED",
             ri.code == 0 and ri.dd().get("fragment") == "customized"
             and "not synced" in ri.dd().get("fragment_note", "") and "FRAGMENT_EDITED" not in ri.codes()),
            (f"01g order {order}: init never current/updated", ri.dd().get("already_current") is False
             and ri.dd().get("fragment") not in ("current", "update")),
            (f"01g order {order}: carriers reports customized", rc.states().get("host-entry") == "customized"
             and "not synced" in next(c["next_step"] for c in rc.dd()["carriers"] if c["carrier"] == "host-entry")),
            (f"01g order {order}: AGENTS.md not written (bytes, inode, mtime)", _agents_meta(q) == meta),
            (f"01g order {order}: recorded acceptance data unchanged",
             record(q)["carriers"] == member and (q / RECORD).read_bytes() == rec_bytes),
        ]
    # 01h edit after acceptance
    h, _ = accepted_project("b06h")
    edit_inner(h, "AGENTS.md", "- A second edit after the acceptance.")
    before = (h / "AGENTS.md").read_bytes()
    rh = init(h)
    rh2 = car(h)
    checks += [
        ("01h init reports FRAGMENT_EDITED (FEATURE-001-A), not customized",
         rh.code == 0 and "FRAGMENT_EDITED" in rh.codes() and rh.dd().get("fragment") == "edited_kept"
         and "customized" not in rh.out),
        ("01h fragment kept byte-identical by init and carriers", (h / "AGENTS.md").read_bytes() == before),
        ("01h carriers reports a difference for decision (choices)",
         rh2.states().get("host-entry") == "kept-differs"
         and "choices" in rh2.dd()["differences"].get("AGENTS.md", {})),
    ]
    # 01i invalid / unreadable member: never honoured.
    base, _ = accepted_project("b06i")

    def mutate(kind):
        def fn(rec):
            m = rec["carriers"]
            if kind == "accepted-wrong-type":
                m["entries"]["host-entry"]["accepted"] = "accepted"
            elif kind == "digest-missing":
                del m["entries"]["host-entry"]["accepted"]["fragment_sha256"]
            elif kind == "digest-malformed":
                m["entries"]["host-entry"]["accepted"]["fragment_sha256"] = "not-a-digest"
            elif kind == "member-wrong-type":
                rec["carriers"] = ["host-entry"]
            elif kind == "unknown-key":
                m["entries"]["host-entry"]["accepted"]["extra"] = 1
            elif kind == "routing-wrong-type":
                m["entries"]["host-entry"]["accepted"]["routing"] = "0.1.0"
            return rec
        return fn

    variants = ["accepted-wrong-type", "digest-missing", "digest-malformed", "member-wrong-type", "unknown-key",
                "routing-wrong-type", "record-not-json"]
    if not IS_ROOT:
        variants.append("record-unreadable")
    results_ok = True
    for kind in variants:
        for replace in (False, True):
            q = clone(base, f"b06i-{kind}")
            if kind == "record-not-json":
                write(q, RECORD, "{ not json")
            elif kind == "record-unreadable":
                os.chmod(q / RECORD, 0)
            else:
                write(q, RECORD, json.dumps(mutate(kind)(record(q)), indent=2))
            before = (q / "AGENTS.md").read_bytes()
            r = init(q, *(["--replace", "AGENTS.md"] if replace else []))
            rt = init(q, *(["--replace", "AGENTS.md"] if replace else []), json_=False)
            ok = (r.code == 1 and "RECORD_INVALID" in r.codes() and (q / "AGENTS.md").read_bytes() == before
                  and "customized" not in r.out + rt.out and r.dd().get("fragment") not in ("current", "update"))
            if kind == "record-unreadable":
                os.chmod(q / RECORD, 0o644)
            results_ok = results_ok and ok
    notes["01i_variants"] = variants
    checks.append(("01i invalid/unreadable member (all variants, with and without --replace AGENTS.md): "
                   "existing RECORD_INVALID refusal, AGENTS.md not overwritten, never customized/current",
                   results_ok))
    # 01j accepted against A, definition now B (Maintainer edit) / toolkit 0.2.0.
    j, _ = accepted_project("b06j")
    a_disp = identity(defn_of(j), v)
    b_obj = edit_definition(j, "J")
    before = _agents_meta(j)
    rj = init(j)
    msg = " ".join(pr["message"] for pr in rj.data["problems"] if pr["code"] == "CUSTOMIZATION_ROUTING_CHANGED")
    checks += [
        ("01j init: customized + routing changed since acceptance (A -> B)",
         rj.code == 0 and rj.dd().get("fragment") == "customized" and "CUSTOMIZATION_ROUTING_CHANGED" in rj.codes()
         and a_disp in msg and identity(b_obj, v) in msg),
        ("01j init: next step names the carriers operation", "secure-code carriers" in rj.data["next_steps"][0]),
        ("01j init: fragment kept byte-identical, never current", _agents_meta(j) == before
         and rj.dd().get("already_current") is False),
    ]
    rj2 = car(j)
    checks.append(("01j carriers then reports the carrier again as a difference for decision",
                   rj2.states().get("host-entry") == "kept-differs" and "AGENTS.md" in rj2.dd()["differences"]
                   and _agents_meta(j)[0] == before[0]))
    k, _ = accepted_project("b06jv")
    rk = init(k, scripts=scripts_of("bumped"))
    rk2 = car(k, scripts=scripts_of("bumped"))
    checks += [
        ("01j new toolkit version: init customized + CUSTOMIZATION_ROUTING_CHANGED (0.1.0 -> 0.2.0)",
         rk.dd().get("fragment") == "customized" and "CUSTOMIZATION_ROUTING_CHANGED" in rk.codes()),
        ("01j new toolkit version: carriers reports a difference (kept)",
         rk2.states().get("host-entry") == "kept-differs"),
    ]
    return checks


# ================================================================ TC-B-07  --replace after acceptance
CANARY_LINES = [f"- token {CAN_TOKEN}", f"- aws {CAN_AWS}", f'- password: "{CAN_PASS}"',
                *CAN_PEM.splitlines()]


def tc_b07_replace_after_acceptance(notes):
    checks = []
    base, fixture_out = accepted_project("b07", extra_lines=CANARY_LINES)
    v = toolkit_version()
    for mode in ("json", "text"):
        p = clone(base, f"b07{mode}")
        pre, _, suf = split_block(read(p, "AGENTS.md"))
        r = init(p, "--replace", "AGENTS.md", json_=(mode == "json"))
        after = read(p, "AGENTS.md")
        pre2, inner2, suf2 = split_block(after)
        if mode == "json":
            rc = r.dd().get("replaced_customization", {})
            diff = "\n".join(rc.get("diff", []))
            checks += [
                ("01k init --replace AGENTS.md: replaced", r.code == 0 and r.dd().get("fragment") == "replaced"),
                ("01k states that an accepted customization was replaced",
                 "accepted customization" in rc.get("statement", "") and "replaced" in rc.get("statement", "")),
                ("01k previous content shown as masked difference with redaction markers",
                 rc.get("content") == MASK_LABEL and all(m in diff for m in MARKERS)),
                ("01k acceptance cleared from the record",
                 "host-entry" not in (record(p).get("carriers") or {}).get("entries", {})),
            ]
        else:
            checks.append(("01k text output states the replaced customization with markers",
                           "accepted customization" in r.out and all(m in r.out for m in MARKERS)))
        checks += [
            (f"01k ({mode}) fragment = current rendering; bytes outside identical",
             inner2 == render(defn_of(p), v, GC, "host-entry") and pre2 == pre and suf2 == suf),
            (f"01k ({mode}) no canary value in stdout/stderr", no_needles(r.out, r.err)),
        ]
        rc1, ri1 = car(p), init(p)
        checks.append((f"01k ({mode}) following carriers and init both report current, never customized",
                       rc1.states().get("host-entry") == "current" and ri1.dd().get("fragment") == "current"
                       and "customized" not in rc1.out + ri1.out))
    checks.append(("01k/05f acceptance fixture outputs (kept difference) masked too", no_needles(*fixture_out)))
    return checks


# ================================================================ TC-B-08  default selection, write set, refusals
def _skills(p: Path, env: str = GC) -> dict:
    return snap(p / PROFILE[env][0])


def tc_b08_default_and_write_set(notes):
    checks = []
    p = proj("b08a")
    s0 = snap(p)
    r = car(p)
    checks += [
        ("03a no selection stored or given: only the host entry carrier checked",
         r.code == 0 and [c["carrier"] for c in r.dd()["carriers"]] == ["host-entry"]
         and r.states() == {"host-entry": "current"}),
        ("03a no instructions file and no system-prompt fragment created",
         not (p / INSTR).exists() and not (p / SP).exists() and not (p / ".github/instructions").exists()),
        ("03a nothing written at all (record unchanged, member omitted)", snap(p) == s0 and "carriers" not in record(p)),
    ]

    def pre(q):
        write(q, ".gitignore", "node_modules/\n.env\n")
        write(q, "CLAUDE.md", "# Claude notes of the user\n")
        write(q, ".github/copilot-instructions.md", "Repository-wide instructions of the user.\n")
    q = proj("b08b", pre=pre)
    write(q.parent, "sibling.txt", "outside the project root\n")
    s_out = {k: v for k, v in snap(q.parent).items() if not k.startswith("proj ü")}
    s1, sk1 = snap(q), _skills(q)
    r1 = car(q, *ALL3)
    s2 = snap(q)
    allowed = {INSTR, SP, RECORD, ".github/instructions", ".x-ipe/private/secure-code/carriers"}
    checks += [
        ("03d selection run: only selected carrier files and the install record differ",
         r1.code == 0 and changed_files(s1, s2) <= allowed and {INSTR, SP, RECORD} <= changed_files(s1, s2)),
        ("03d skills folder (incl. routing definition) not created/modified/deleted", _skills(q) == sk1),
        ("03d .gitignore, CLAUDE.md, .github/copilot-instructions.md byte-identical (inode/mtime too)",
         all(s1[k] == s2[k] for k in (".gitignore", "CLAUDE.md", ".github/copilot-instructions.md"))),
        ("03d files outside the project root unchanged",
         {k: v for k, v in snap(q.parent).items() if not k.startswith("proj ü")} == s_out),
    ]
    edit_inner(q, INSTR, "- local instructions edit")
    edit_definition(q, "W")
    sk2 = _skills(q)
    s3 = snap(q)
    r2 = car(q, "--regenerate", "github-instructions")
    s4 = snap(q)
    r3 = car(q, "--deselect", "system-prompt")
    s5 = snap(q)
    checks += [
        ("03d regenerate run: write set within the selected carriers + record",
         r2.code == 0 and changed_files(s3, s4) <= {"AGENTS.md", INSTR, SP, RECORD}),
        ("03d deselect run: only the install record may differ", r3.code == 0 and changed_files(s4, s5) <= {RECORD}),
        ("03d skills folder untouched across all carriers runs (definition edit stays)", _skills(q) == sk2),
    ]
    # Refusals with an init next step; nothing written, no implicit reinstall.
    base = proj("b08r")
    car(base, *ALL3)
    edit_definition(base, "R")   # pending update so that a non-refused run would write

    def refuse(label, mutate, code):
        x = clone(base, f"b08r-{label}")
        mutate(x)
        before = snap(x)
        rr = car(x)
        good = (rr.code == 1 and rr.codes() == [code] and snap(x) == before
                and any("secure-code init" in s for s in rr.data["next_steps"]))
        if label == "definition-unreadable":
            os.chmod(x / f".github/skills/{DEF_REL}", 0o644)
        return good

    def drop_skill(x):
        (x / ".github/skills/x-ipe-secure-code-toolkit-guard/SKILL.md").unlink()

    def bad_json(x):
        write(x, f".github/skills/{DEF_REL}", "{ broken")

    def no_def(x):
        (x / f".github/skills/{DEF_REL}").unlink()

    def invalid_def(x):
        obj = defn_of(x)
        obj["sections"] = [s for s in obj["sections"] if s["id"] != "roles"]
        write(x, f".github/skills/{DEF_REL}", json.dumps(obj))

    def abs_path_def(x):
        obj = defn_of(x)
        obj["sections"][0]["statements"][0] = "Read /etc/passwd first."
        write(x, f".github/skills/{DEF_REL}", json.dumps(obj))

    def unreadable_def(x):
        os.chmod(x / f".github/skills/{DEF_REL}", 0)

    cases = [("skill-missing", drop_skill, "SKILLS_INVALID"), ("definition-not-json", bad_json, "ROUTING_DEFINITION_INVALID"),
             ("definition-missing", no_def, "ROUTING_DEFINITION_INVALID"),
             ("definition-invalid", invalid_def, "ROUTING_DEFINITION_INVALID"),
             ("definition-absolute-path", abs_path_def, "ROUTING_DEFINITION_INVALID")]
    if not IS_ROOT:
        cases.append(("definition-unreadable", unreadable_def, "ROUTING_DEFINITION_INVALID"))
    notes["03d_refusals"] = [c[0] for c in cases]
    for label, mutate, code in cases:
        checks.append((f"03d {label}: refused {code} with init next step; nothing written", refuse(label, mutate, code)))
    y = clone(base, "b08valid")
    sk = _skills(y)
    ry = car(y)
    checks.append(("03d valid Maintainer edit of the definition is not invalid (renders; skills untouched)",
                   ry.code == 0 and set(ry.states().values()) == {"updated"} and _skills(y) == sk))
    return checks


# ================================================================ TC-B-09  deselection, no longer managed
def tc_b09_deselect(notes):
    checks = []
    p = proj("b09")
    car(p, *ALL3)
    sp_meta = os.lstat(p / SP)
    sp_bytes = (p / SP).read_bytes()
    r = car(p, "--deselect", "system-prompt")
    entry = next((c for c in r.dd().get("carriers", []) if c["carrier"] == "system-prompt"), {})
    st = status(p)
    sentry = next((c for c in st.dd()["host_integration"]["carriers"] if c["carrier"] == "system-prompt"), {})
    checks += [
        ("03e deselected carrier: file and fragment not deleted or modified",
         (p / SP).read_bytes() == sp_bytes and os.lstat(p / SP).st_ino == sp_meta.st_ino
         and os.lstat(p / SP).st_mtime_ns == sp_meta.st_mtime_ns),
        ("03e result: no longer managed + manual next step",
         entry.get("selection") == "no longer managed" and entry.get("state") == "no longer managed"
         and "manually" in entry.get("next_step", "")),
        ("03e status: no longer managed + manual next step",
         sentry.get("fragment") == "no longer managed" and "manually" in sentry.get("next_step", "")),
        ("03e record: selection stored, entry kept for reporting",
         record(p)["carriers"]["selected"] == ["host-entry", "github-instructions"]
         and "system-prompt" in record(p)["carriers"]["entries"]),
    ]
    edit_inner(p, SP, "- user line in an unmanaged carrier")
    sp2 = (p / SP).read_bytes()
    edit_definition(p, "D")
    r2 = car(p)
    checks += [
        ("03e later run without selection: the stored set is generated/checked again",
         r2.code == 0 and r2.states() == {"host-entry": "updated", "github-instructions": "updated",
                                         "system-prompt": "no longer managed"}),
        ("03e no-longer-managed file never read/written, not reported as a difference",
         (p / SP).read_bytes() == sp2 and SP not in r2.dd().get("differences", {})),
    ]
    r3 = car(p, "--select", "system-prompt")
    checks += [
        ("03e --select replaces the stored selection (instructions now no longer managed)",
         r3.code == 0 and r3.states().get("github-instructions") == "no longer managed"
         and r3.states().get("system-prompt") == "kept-differs" and (p / INSTR).exists()),
    ]
    s = snap(p)
    r4 = car(p, "--deselect", "host-entry")
    checks.append(("03e host entry cannot be deselected (ARGUMENT_INVALID), nothing written",
                   r4.code == 1 and r4.codes() == ["ARGUMENT_INVALID"] and snap(p) == s))
    return checks


# ================================================================ TC-B-10  unknown / unsupported carriers and arguments
def tc_b10_unsupported(notes):
    checks = []
    p = proj("b10")
    c = proj("b10cc", env=CC)
    sp_, sc_ = snap(p), snap(c)
    r1 = car(p, "--select", "bogus")
    r1t = car(p, "--select", "bogus", json_=False)
    r2 = car(c, "--select", "github-instructions", env=CC)
    r3 = car(p, "--regenerate", "nope")
    checks += [
        ("03f unknown carrier refused, supported carriers listed",
         r1.code == 1 and r1.codes() == ["CARRIER_UNSUPPORTED"]
         and r1.dd().get("supported_carriers") == KINDS[GC]
         and all(k in r1t.out for k in KINDS[GC])),
        ("03f GitHub instructions for claude-code refused, claude-code carriers listed",
         r2.code == 1 and r2.codes() == ["CARRIER_UNSUPPORTED"] and r2.dd().get("supported_carriers") == KINDS[CC]),
        ("03f unknown kind in a decision refused", r3.code == 1 and r3.codes() == ["CARRIER_UNSUPPORTED"]),
        ("03f nothing written", snap(p) == sp_ and snap(c) == sc_),
    ]
    bad = [(("--select", "github-instructions", "--deselect", "system-prompt"), "ARGUMENT_INVALID"),
           (("--system-prompt-host", "copilot-cli"), "ARGUMENT_INVALID"),
           (("--select", "system-prompt"), "ARGUMENT_INVALID"),
           (("--select", "system-prompt", "--system-prompt-host", "Bad Host!"), "ARGUMENT_INVALID"),
           (("--regenerate", "host-entry", "--accept", "host-entry"), "ARGUMENT_INVALID"),
           (("--accept", "github-instructions"), "ARGUMENT_INVALID"),
           (("--accept", "host-entry"), "DECISION_NOT_APPLICABLE")]
    ok = True
    for args, code in bad:
        rr = car(p, *args)
        ok = ok and rr.code == 1 and rr.codes() == [code]
    checks.append(("CLI contract: invalid argument combinations refused with their codes", ok))
    checks.append(("CLI contract: refusals wrote nothing", snap(p) == sp_))
    rr = sc("carriers", "--project", p, "--env", GC, "--unknown-option")
    checks.append(("CLI contract: unknown option is an argparse usage error (exit 2)", rr.code == 2))
    return checks


# ================================================================ TC-B-11  instructions boundaries and front matter
def _entry(r: R, kind: str, status_: bool = False) -> dict:
    items = r.dd()["host_integration"]["carriers"] if status_ else r.dd().get("carriers", [])
    return next((c for c in items if c["carrier"] == kind), {})


def tc_b11_instructions_boundaries(notes):
    checks = []
    v = toolkit_version()
    p = proj("b11")
    car(p, "--select", "github-instructions")
    text = read(p, INSTR)
    user_mid = "User note between the front matter and the markers.\n\n"
    user_end = "\nUser trailing note after the markers.\n"
    edited = text[:len(FM)] + user_mid + text[len(FM) + 1:] + user_end
    write(p, INSTR, edited)
    before = snap(p)
    r = car(p)
    st = status(p)
    e, se = _entry(r, "github-instructions"), _entry(st, "github-instructions", True)
    checks += [
        ("03g user bytes outside both boundaries byte-identical (whole tree unchanged)", snap(p) == before),
        ("03g carriers: user content detected outside the managed boundaries (kept), front matter ok, current",
         e.get("user_content") == USER_CONTENT and e.get("front_matter") == "ok" and e.get("state") == "current"),
        ("03g status: same, separately from front-matter drift",
         se.get("user_content") == USER_CONTENT and se.get("front_matter") == "ok"),
        ("03g informational only: no difference and no FRONT_MATTER_DRIFT",
         INSTR not in r.dd().get("differences", {}) and "FRONT_MATTER_DRIFT" not in r.codes()),
    ]
    b = edit_definition(p, "G")
    r2 = car(p)
    pre, inner, suf = split_block(read(p, INSTR))
    checks.append(("03g only the managed body changes on update; user text and front matter preserved",
                   r2.states().get("github-instructions") == "updated" and pre == FM + user_mid and suf == user_end
                   and inner == render(b, v, GC, "github-instructions")))
    base = clone(p, "b11base")
    cur = read(base, INSTR)
    body_part = cur[len(FM):]
    variants = {
        "removed": (body_part, "missing"),
        "applyTo-changed": ('---\napplyTo: "src/**"\n---\n' + body_part, "altered"),
        "key-added": ('---\napplyTo: "**"\ndescription: team tweak\n---\n' + body_part, "altered"),
        "moved": ("Intro written by the user.\n" + FM + body_part, "moved"),
    }
    for name, (content, state) in variants.items():
        x = clone(base, f"b11-{name}")
        write(x, INSTR, content)
        s0 = snap(x)
        rs = status(x)
        rc = car(x)
        es, ec = _entry(rs, "github-instructions", True), _entry(rc, "github-instructions")
        diff = rc.dd().get("differences", {}).get(INSTR, {})
        sdiff = rs.dd()["host_integration"].get("differences", {}).get(INSTR, {})
        checks += [
            (f"06d {name}: status reports front-matter drift ({state}) with masked difference and next step",
             es.get("front_matter") == f"drift: {state}" and sdiff.get("front_matter_diff")
             and sdiff.get("content") == MASK_LABEL and "--regenerate github-instructions" in es.get("next_step", "")),
            (f"06d {name}: carriers reports FRONT_MATTER_DRIFT, kept-differs, masked front_matter_diff",
             ec.get("front_matter") == f"drift: {state}" and "FRONT_MATTER_DRIFT" in rc.codes()
             and ec.get("state") == "kept-differs" and diff.get("front_matter_diff") and diff.get("content") == MASK_LABEL),
            (f"06d {name}: drift distinct from user content outside the boundaries",
             ec.get("user_content") == (USER_CONTENT) and es.get("user_content") == USER_CONTENT),
            (f"06d {name}: file kept, not rewritten (tree identical)", snap(x) == s0),
        ]
        rg = car(x, "--regenerate", "github-instructions")
        after = read(x, INSTR)
        if state == "missing":
            expected = FM + content
        elif state == "altered":
            lead_end = content.index("\n---\n") + len("\n---\n")
            expected = FM + content[lead_end:]
        else:
            start = content.index(FM)
            expected = FM + content[:start] + content[start + len(FM):]
        checks += [
            (f"05c/06d {name}: regenerate restores the exact front matter at file start, one block only",
             rg.code == 0 and rg.states().get("github-instructions") == "replaced" and after.startswith(FM)
             and after.count(FM) == 1),
            (f"05c/06d {name}: every other user byte preserved (exact expected bytes)", after == expected),
            (f"05c {name}: replaced difference shown masked", rg.dd()["differences"].get(INSTR, {}).get("replaced") is True
             and rg.dd()["differences"][INSTR].get("content") == MASK_LABEL),
        ]
    return checks


# ================================================================ TC-B-12  preservation, idempotency, mentions
def tc_b12_preservation(notes):
    checks = []
    v = toolkit_version()
    for nl in ("\n", "\r\n"):
        tag = "lf" if nl == "\n" else "crlf"
        head = f"# Team rules ü 日本語{nl}{nl}Use tabs.{nl}"
        p = proj(f"b12{tag}", pre=lambda q, head=head: write(q, "AGENTS.md", head))
        car(p, *ALL3)
        agents = read(p, "AGENTS.md") + f"{nl}## Later user edit — straße{nl}"
        write(p, "AGENTS.md", agents)
        instr = read(p, INSTR).replace("\n", nl) + f"{nl}User trailing instructions — ñ{nl}"
        write(p, INSTR, instr)
        sp_text = read(p, SP).replace("\n", nl) + f"User note after the system-prompt fragment — ü{nl}"
        write(p, SP, sp_text)
        outside = {rel: (split_block(read(p, rel))[0], split_block(read(p, rel))[2]) for rel in ("AGENTS.md", INSTR, SP)}
        rmid = car(p)
        b = edit_definition(p, f"P{tag}")
        r = car(p)
        ok_out = all((split_block(read(p, rel))[0], split_block(read(p, rel))[2]) == outside[rel]
                     for rel in ("AGENTS.md", INSTR, SP))
        bodies_ok = (inner_of(p, "AGENTS.md").replace("\r\n", "\n") == render(b, v, GC, "host-entry")
                     and inner_of(p, INSTR).replace("\r\n", "\n") == render(b, v, GC, "github-instructions"))
        style_ok = all(no_bare_lf(read(p, rel)) for rel in ("AGENTS.md", INSTR, SP)) if nl == "\r\n" else \
            all("\r" not in read(p, rel) for rel in ("AGENTS.md", INSTR, SP))
        checks += [
            (f"04a ({tag}) user edits after generation are not differences (unedited fragments current)",
             set(rmid.states().values()) == {"current"}),
            (f"04a ({tag}) regenerate: all three carriers updated", set(r.states().values()) == {"updated"}),
            (f"04a ({tag}) all bytes outside each managed boundary identical (non-ASCII included)", ok_out),
            (f"04a ({tag}) managed content = new rendering", bodies_ok),
            (f"04a ({tag}) managed content uses the file's newline style", style_ok),
        ]
    # 04b idempotent re-run
    q = proj("b12idem")
    car(q, *ALL3)
    s0, rec0 = snap(q), (q / RECORD).read_bytes()
    r1 = car(q)
    r2 = car(q, *ALL3)
    r3 = init(q)
    checks += [
        ("04b unchanged inputs: every carrier current, record not written",
         set(r1.states().values()) == {"current"} and r1.dd().get("record_written") is False
         and set(r2.states().values()) == {"current"} and r2.dd().get("record_written") is False),
        ("04b no file written (tree incl. inodes/mtimes identical), record byte-identical",
         snap(q) == s0 and (q / RECORD).read_bytes() == rec0),
        ("04b no duplicate fragment", all(begins(read(q, rel)) == 1 for rel in ("AGENTS.md", INSTR, SP))),
        ("04b plain init on unchanged project: already current, nothing written",
         r3.dd().get("already_current") is True and snap(q) == s0),
    ]
    # 04c toolkit mentions and a pasted copy without markers
    pasted = render(json.loads((TOOLKIT / FW / "references/routing-definition.json").read_text(encoding="utf-8")),
                    v, GC, "host-entry")
    mention = ("Our notes mention ai-secure-code-toolkit, secure-code, x-ipe-secure-code-toolkit-copilot, "
               "x-ipe-secure-code-toolkit-guard and x-ipe-secure-code-toolkit-framework.\n\n")
    w = proj("b12mention", pre=lambda q: write(q, "AGENTS.md", mention + pasted))
    text0 = read(w, "AGENTS.md")
    rc = car(w)
    x = clone(w, "b12absent")
    write(x, "AGENTS.md", mention + pasted)        # the user removed the marked fragment, kept the copy
    rx = car(x)
    entry = _entry(rx, "host-entry")
    b = edit_definition(w, "M")
    rc2 = car(w)
    pre2, inner2, suf2 = split_block(read(w, "AGENTS.md"))
    checks += [
        ("04c init appended a real fragment after the user text (user text kept)",
         text0.startswith(mention + pasted) and begins(text0) == 1),
        ("04c carriers on the unchanged project: current, pasted text not a difference",
         rc.states().get("host-entry") == "current" and rc.dd().get("differences") == {}),
        ("04c markers absent, pasted copy present: new fragment appended, similar text noted, copy kept",
         entry.get("state") == "appended" and "not taken over" in entry.get("note", "")
         and read(x, "AGENTS.md").startswith(mention + pasted) and begins(read(x, "AGENTS.md")) == 1),
        ("04c regeneration replaces only the marked fragment; mentions and pasted copy unchanged",
         rc2.states().get("host-entry") == "updated" and pre2.startswith(mention + pasted)
         and inner2 == render(b, v, GC, "host-entry")),
        ("04c no difference reported for user text", rc2.dd().get("differences") == {}),
    ]
    return checks


# ================================================================ TC-B-13  malformed carriers and symbolic links
def _break(x: Path, rel: str, how: str) -> None:
    text = read(x, rel)
    if how == "unmatched":
        write(x, rel, text.replace(END + "\n", ""))
    elif how == "reversed":
        pre, inner, suf = split_block(text)
        write(x, rel, pre + END + "\n" + inner + BEGIN + "\n" + suf)
    elif how == "duplicate":
        pre, inner, suf = split_block(text)
        write(x, rel, text + "\n" + BEGIN + "\n" + inner + END + "\n")
    elif how == "non-utf8":
        write(x, rel, text.encode("utf-8") + b"\n\xff\xfe broken bytes\n")


EXPECT_CODE = {"unmatched": "FRAGMENT_MALFORMED", "reversed": "FRAGMENT_MALFORMED", "duplicate": "FRAGMENT_DUPLICATE"}


def tc_b13_malformed_and_links(notes):
    checks = []
    base = proj("b13")
    car(base, *ALL3)
    edit_definition(base, "X")     # pending updates: a non-refused run would write every carrier
    ok_all = True
    for rel, kind in (("AGENTS.md", "host-entry"), (INSTR, "github-instructions"), (SP, "system-prompt")):
        for how in ("unmatched", "reversed", "duplicate", "non-utf8"):
            x = clone(base, f"b13-{kind}-{how}")
            _break(x, rel, how)
            s0 = snap(x)
            r = car(x)
            code = EXPECT_CODE.get(how) or ("HOST_ENTRY_UNREADABLE" if kind == "host-entry" else "CARRIER_UNREADABLE")
            msg = " ".join(pr["message"] for pr in (r.data or {}).get("problems", []))
            ok = r.code == 1 and r.codes() == [code] and rel in msg and snap(x) == s0
            ok_all = ok_all and ok
            if not ok:
                notes.setdefault("04d_failed", []).append(f"{kind}/{how}")
    checks.append(("04d 3 carriers x {unmatched, reversed, duplicate, non-UTF-8}: whole run refused naming carrier "
                   "and problem; no carrier, skill or record written", ok_all))
    y = clone(base, "b13-two")
    _break(y, "AGENTS.md", "duplicate")
    _break(y, SP, "reversed")
    s0 = snap(y)
    r = car(y)
    msgs = [pr["message"] for pr in r.data["problems"]]
    checks.append(("04d two broken carriers named in one refusal",
                   r.code == 1 and sorted(r.codes()) == ["FRAGMENT_DUPLICATE", "FRAGMENT_MALFORMED"]
                   and any("AGENTS.md" in m for m in msgs) and any(SP in m for m in msgs) and snap(y) == s0))

    def link_agents(x):
        os.rename(x / "AGENTS.md", x / "TEAM.md")
        os.symlink("TEAM.md", x / "AGENTS.md")

    def link_instr_dir(x):
        os.rename(x / ".github/instructions", x / "docs-instructions")
        os.symlink("../docs-instructions", x / ".github/instructions")

    def link_carriers_dir(x):
        os.rename(x / ".x-ipe/private/secure-code/carriers", x / "sp-folder")
        os.symlink("../../../sp-folder", x / ".x-ipe/private/secure-code/carriers")

    def link_instr_file(x):
        os.rename(x / INSTR, x / "instr-real.md")
        os.symlink("../../instr-real.md", x / INSTR)

    for label, fn, named in (("AGENTS.md -> TEAM.md", link_agents, "AGENTS.md"),
                             (".github/instructions folder link", link_instr_dir, ".github/instructions"),
                             ("carriers folder link", link_carriers_dir, ".x-ipe/private/secure-code/carriers"),
                             ("instructions file link", link_instr_file, INSTR)):
        x = clone(base, "b13-link")
        fn(x)
        s0 = snap(x)
        r = car(x)
        msg = " ".join(pr["message"] for pr in (r.data or {}).get("problems", []))
        checks.append((f"04e {label} (inside the project): PATH_UNSAFE naming the path, nothing written",
                       r.code == 1 and r.codes() == ["PATH_UNSAFE"] and named in msg and snap(x) == s0))
    return checks


# ================================================================ TC-B-14  write failure and convergence
def tc_b14_write_failure(notes):
    checks = []
    tiny = os.environ.get("FAT_TINY")
    if MODE == "container" and IS_ROOT:
        if not tiny:
            return [("04f tiny tmpfs available for a real ENOSPC failure", False)]
        root = Path(tiny) / f"w-{_COUNTER[0]}"
        root.mkdir(parents=True)
        p = root / "proj ü"
        p.mkdir()
        if init(p).code != 0:
            return [("04f fixture init on tmpfs", False)]
        filler = root / "filler.bin"
        vfs = os.statvfs(p)
        free = vfs.f_bavail * vfs.f_frsize
        page = vfs.f_frsize
        with open(filler, "wb") as handle:
            handle.write(b"\0" * (free - page))   # leave exactly one page: the first carrier fits
            handle.flush()
            os.fsync(handle.fileno())
        notes["failure_method"] = f"ENOSPC on tmpfs ({page}-byte page left free)"

        def fix():
            filler.unlink()
    else:
        p = proj("b14")
        (p / ".x-ipe/private/secure-code/carriers").mkdir(parents=True)
        os.chmod(p / ".x-ipe/private/secure-code/carriers", 0o555)
        notes["failure_method"] = "EACCES: carriers folder read-only (chmod 555)"

        def fix():
            os.chmod(p / ".x-ipe/private/secure-code/carriers", 0o755)
    rec0 = (p / RECORD).read_bytes()
    r = car(p, *ALL3)
    written = r.dd().get("written_before_failure")
    checks += [
        ("04f run reports failure (IO_ERROR)", r.code == 1 and r.codes() == ["IO_ERROR"]),
        ("04f lists the carriers written before the failure", written == [INSTR] and (p / INSTR).is_file()),
        ("04f install record not updated", (p / RECORD).read_bytes() == rec0),
    ]
    fix()
    r2 = car(p, *ALL3)
    checks += [
        ("04f re-run after the fix: written carrier recognized as current, rest created",
         r2.code == 0 and r2.states() == {"host-entry": "current", "github-instructions": "current",
                                          "system-prompt": "created"}),
        ("04f no fragment duplicated", all(begins(read(p, rel)) == 1 for rel in ("AGENTS.md", INSTR, SP))),
        ("04f record now matches the carriers on disk",
         record(p)["carriers"]["entries"]["github-instructions"]["fragment_sha256"] == sha_text(inner_of(p, INSTR))
         and record(p)["carriers"]["entries"]["system-prompt"]["fragment_sha256"] == sha_text(inner_of(p, SP))),
    ]
    return checks


# ================================================================ TC-B-15  concurrency and the bounded lock wait
LOCK_TIMEOUT = 10.0


def _consistent(p: Path) -> bool:
    rec = record(p)
    ok = begins(read(p, "AGENTS.md")) == 1 and rec["fragment_sha256"] == sha_text(inner_of(p, "AGENTS.md"))
    for kind, rel in (("github-instructions", INSTR), ("system-prompt", SP)):
        entry = (rec.get("carriers") or {}).get("entries", {}).get(kind)
        if entry and kind in rec["carriers"]["selected"]:
            ok = ok and begins(read(p, rel)) == 1 and entry["fragment_sha256"] == sha_text(inner_of(p, rel))
    return ok


def tc_b15_concurrency(notes):
    checks = []
    p = proj("b15")
    car(p, *ALL3)
    t_base = min(car(p).secs for _ in range(3))
    notes["unlocked_run_seconds"] = round(t_base, 2)
    # 04h: a foreign process holds the project lock longer than the bounded wait.
    edit_definition(p, "H")
    s0 = snap(p)
    holder = hold_lock(p, 40)
    try:
        ri = init(p)
        rc = car(p)
    finally:
        holder.kill()
        holder.wait()
    notes["04h_seconds"] = {"init": round(ri.secs, 2), "carriers": round(rc.secs, 2)}
    margin = t_base + 3.0
    checks += [
        ("04h plain init refuses LOCKED with a retry next step",
         ri.code == 1 and ri.codes() == ["LOCKED"] and "Retry" in ri.data["next_steps"][0]),
        ("04h carriers refuses LOCKED with a retry next step",
         rc.code == 1 and rc.codes() == ["LOCKED"] and "Retry" in rc.data["next_steps"][0]),
        ("04h each waited the bounded wait (10.0 s) and not longer (plus process start-up)",
         all(LOCK_TIMEOUT - 0.2 <= x.secs <= LOCK_TIMEOUT + margin for x in (ri, rc))),
        ("04h nothing written, no lock file (tree incl. inodes/mtimes identical)", snap(p) == s0),
    ]
    # 04g (a): runs started while the lock is held wait and then complete under the lock.
    holder = hold_lock(p, 3)
    t0 = time.time()
    a, b = spawn("init", "--project", p, "--env", GC, "--json"), spawn("carriers", "--project", p, "--env", GC, "--json")
    ra, rb = join(a), join(b)
    holder.wait()
    notes["04g_wait_seconds"] = {"init": round(ra.secs, 2), "carriers": round(rb.secs, 2)}
    checks += [
        ("04g runs started under a held lock waited, then completed after release (not unlocked)",
         ra.code == 0 and rb.code == 0 and min(ra.secs, rb.secs) >= 2.5 and max(ra.secs, rb.secs) < LOCK_TIMEOUT + margin
         and time.time() - t0 >= 2.5),
        ("04g after the waited runs: one fragment per carrier, record matches disk", _consistent(p)),
    ]
    # 04g (b): truly concurrent pairs with pending writes.
    pairs = [("init", "carriers"), ("carriers", "carriers"), ("init", "init"), ("carriers", "init")] * 3
    outcomes, ok_all = [], True
    for n, (x, y) in enumerate(pairs):
        edit_definition(p, f"C{n}")
        procs = [spawn(k, "--project", p, "--env", GC, "--json") for k in (x, y)]
        rs = [join(pr) for pr in procs]
        for k, rr in zip((x, y), rs):
            good = rr.code == 0 or (rr.code == 1 and rr.codes() == ["LOCKED"])
            ok_all = ok_all and good
            outcomes.append(f"{k}:{'ok' if rr.code == 0 else ','.join(rr.codes())}")
        ok_all = ok_all and _consistent(p)
    notes["04g_outcomes"] = outcomes
    final = car(p)
    checks += [
        ("04g 12 concurrent pairs: each run completed or refused LOCKED; no other outcome", ok_all),
        ("04g no carrier with more than one fragment; record matches carriers on disk after every pair", ok_all),
        ("04g final state converged (every carrier current)", set(final.states().values()) == {"current"}),
    ]
    return checks


# ================================================================ TC-B-16  lock unavailable on POSIX (root not openable)
def tc_b16_lock_unavailable_posix(notes):
    checks = []
    p = proj("b16")
    car(p, "--select", "github-instructions")
    edit_definition(p, "U")
    s0 = snap(p)
    os.chmod(p, 0o333)      # write+search only: the project root cannot be opened read-only
    try:
        r = car(p)
    finally:
        os.chmod(p, 0o755)
    checks += [
        ("04i carriers refuses LOCK_UNAVAILABLE (interim, B11) where the file-free lock is unavailable",
         r.code == 1 and r.codes() == ["LOCK_UNAVAILABLE"] and "B11" in r.data["problems"][0]["message"]),
        ("04i no lock file created and nothing written", snap(p) == s0),
    ]
    # Plain init with the lock unavailable behaves exactly as delivered FEATURE-001-A: compare the pre-003B
    # code and this version on the same FEATURE-001-A-era payload, both on unopenable roots.
    era, old = toolkit_copy("era"), scripts_of("old")
    pa, pb = proj("b16old", do_init=False), proj("b16new", do_init=False)
    outs = {}
    for label, q, scripts in (("old", pa, old), ("new", pb, None)):
        write(q, "AGENTS.md", "# user file\n")
        os.chmod(q, 0o333)
        try:
            outs[label] = [init(q, "--toolkit-source", era, scripts=scripts),
                           init(q, "--toolkit-source", era, scripts=scripts)]
        finally:
            os.chmod(q, 0o755)
    ra, rb = outs["old"], outs["new"]
    checks += [
        ("04i plain init on a lock-unavailable root: no LOCKED/LOCK_UNAVAILABLE, completes",
         all(x.code == 0 and "LOCKED" not in x.codes() and "LOCK_UNAVAILABLE" not in x.codes() for x in rb)),
        ("04i plain init results identical to the pre-003B code (fresh and re-run)",
         [norm(x.data, pa) for x in ra] == [norm(x.data, pb) for x in rb]),
        ("04i AGENTS.md and record identical to the pre-003B code's (apart from timestamps)",
         read(pa, "AGENTS.md") == read(pb, "AGENTS.md")
         and _record_without_times(record(pa)) == _record_without_times(record(pb))),
    ]
    return checks


# ================================================================ TC-B-17  Maintainer difference handling
FILES3 = (("host-entry", "AGENTS.md"), ("github-instructions", INSTR), ("system-prompt", SP))


def tc_b17_differences(notes):
    checks = []
    v = toolkit_version()
    base = proj("b17")
    car(base, *ALL3)
    p = clone(base, "b17edit")
    for kind, rel in FILES3:
        edit_inner(p, rel, f"- Local addition by the team to {kind}.")
    s0 = snap(p)
    r = car(p)
    diffs = r.dd().get("differences", {})
    ok5a = True
    for kind, rel in FILES3:
        d = diffs.get(rel, {})
        e = _entry(r, kind)
        ok5a = ok5a and (e.get("state") == "kept-differs" and d.get("content") == MASK_LABEL
                         and d.get("diff", [""])[0] == "--- current fragment (masked)"
                         and any(line.startswith("-") and f"Local addition by the team to {kind}" in line
                                 for line in d.get("diff", []))
                         and d.get("choices") == [c.format(k=kind) for c in CHOICES]
                         and "Decide" in e.get("next_step", ""))
    checks += [
        ("05a each edited carrier kept byte-identical (tree identical)", snap(p) == s0),
        ("05a path, differs, masked difference and the five choices per carrier", ok5a and r.code == 0
         and r.codes().count("FRAGMENT_EDITED") == 3),
    ]
    again = [car(p) for _ in range(2)]
    st = status(p)
    sh = st.dd()["host_integration"]
    checks += [
        ("05b kept differences reported again on every run, never overwritten",
         all(set(x.states().values()) == {"kept-differs"} and len(x.dd()["differences"]) == 3 for x in again)
         and snap(p) == s0),
        ("05b status reports each difference (modified + masked diff)",
         all(_entry(st, k, True).get("fragment") == "modified" for k, _ in FILES3)
         and set(sh.get("differences", {})) == {rel for _, rel in FILES3}),
    ]
    pre, _, suf = split_block(read(p, "AGENTS.md"))
    rg = car(p, "--regenerate", "host-entry")
    pre2, inner2, suf2 = split_block(read(p, "AGENTS.md"))
    checks += [
        ("05c regenerate: only that carrier's managed boundary replaced with the current rendering",
         rg.states() == {"host-entry": "replaced", "github-instructions": "kept-differs", "system-prompt": "kept-differs"}
         and inner2 == render(defn_of(p), v, GC, "host-entry") and pre2 == pre and suf2 == suf),
        ("05c other differing carriers kept and reported (bytes unchanged)",
         all(snap(p)[rel][1] == s0[rel][1] for rel in (INSTR, SP)) and set(rg.dd()["differences"]) == {"AGENTS.md", INSTR, SP}),
        ("05c replaced content shown as masked difference",
         rg.dd()["differences"]["AGENTS.md"].get("replaced") is True
         and rg.dd()["differences"]["AGENTS.md"].get("content") == MASK_LABEL),
    ]
    # 05d accept per carrier kind
    for kind, rel in FILES3:
        x = clone(base, f"b17acc-{kind}")
        edit_inner(x, rel, "- Accepted team wording.")
        car(x)
        ra = car(x, "--accept", kind)
        acc_entry = record(x)["carriers"]["entries"][kind]["accepted"]
        sa = status(x)
        decl = ra.dd().get("integration_declaration", "")
        checks += [
            (f"05d accept {kind}: record holds accepted digest, routing identity and time",
             acc_entry["fragment_sha256"] == sha_text(inner_of(x, rel))
             and acc_entry["routing"]["definition_sha256"] == def_digest(defn_of(x)) and "accepted_at" in acc_entry),
            (f"05d accept {kind}: result and status customized (accepted) - not synced, never current",
             ra.states()[kind] == "customized" and "not synced" in _entry(ra, kind)["next_step"]
             and _entry(sa, kind, True).get("fragment") == "customized" and "not synced" in decl),
        ]
        rb = car(x)
        checks.append((f"05d accept {kind}: stays customized on the next run (no write)",
                       rb.states()[kind] == "customized" and rb.dd().get("record_written") is False))
        y = clone(x, f"b17acc2-{kind}")
        edit_inner(x, rel, "- Changed again after acceptance.")
        r1 = car(x)
        edit_definition(y, f"A{kind}")
        r2 = car(y)
        checks.append((f"05d accept {kind}: fragment change or routing change -> reported again as a difference",
                       r1.states()[kind] == "kept-differs" and r2.states()[kind] == "kept-differs"
                       and rel in r1.dd()["differences"] and rel in r2.dd()["differences"]))
    # 05e missing / unknown / mismatching digest never removes the decision
    golden_body = GOLDEN_001A.format(s=".github/skills")
    variants = {}
    for label in ("digest-null", "digest-foreign", "entry-digest-foreign"):
        x = clone(base, f"b17dig-{label}")
        rec = record(x)
        if label == "digest-null":
            rec["fragment_sha256"] = None
            t = read(x, "AGENTS.md")
            write(x, "AGENTS.md", t.replace(inner_of(x, "AGENTS.md"), golden_body))
            rel = "AGENTS.md"
        elif label == "digest-foreign":
            rec["fragment_sha256"] = sha(b"another environment's fragment")
            edit_inner(x, "AGENTS.md", "- edited")
            rel = "AGENTS.md"
        else:
            rec["carriers"]["entries"]["github-instructions"]["fragment_sha256"] = sha(b"lost")
            edit_inner(x, INSTR, "- edited")
            rel = INSTR
        write(x, RECORD, json.dumps(rec, indent=2))
        before = (x / rel).read_bytes()
        rr = car(x)
        variants[label] = (rr.code == 0 and rel in rr.dd()["differences"] and (x / rel).read_bytes() == before
                           and "FRAGMENT_EDITED" in rr.codes())
    notes["05e"] = variants
    checks.append(("05e digest missing/foreign/mismatching: differing fragment kept and reported, never overwritten",
                   all(variants.values())))
    z = clone(base, "b17lost")
    edit_inner(z, "AGENTS.md", "- edited before the record was lost")
    (z / RECORD).unlink()
    zs = snap(z)
    rz = car(z)
    rz_unchanged = snap(z) == zs
    before = (z / "AGENTS.md").read_bytes()
    rz2 = init(z)
    checks += [
        ("05e lost record: carriers refused PROJECT_NOT_INITIALIZED, nothing written",
         rz.code == 1 and rz.codes() == ["PROJECT_NOT_INITIALIZED"] and rz_unchanged),
        ("05e lost record: plain init keeps the differing fragment (FRAGMENT_EDITED), not overwritten",
         rz2.code == 0 and "FRAGMENT_EDITED" in rz2.codes() and (z / "AGENTS.md").read_bytes() == before),
    ]
    return checks


# ================================================================ TC-B-18  secret masking with canaries
def tc_b18_masking(notes):
    checks = []
    base = proj("b18")
    car(base, *ALL3)
    p = clone(base, "b18c")
    for rel in ("AGENTS.md", INSTR, SP):
        edit_inner(p, rel, *CANARY_LINES)
    text = read(p, INSTR)
    fm_canary = ('---\napplyTo: "**"\n' + f"token: {CAN_TOKEN}\naws: {CAN_AWS}\n" + f'password: "{CAN_PASS}"\n'
                 + "---\n")
    write(p, INSTR, fm_canary + text[len(FM):])
    on_disk = all(any(n in read(p, rel) for n in NEEDLES) for rel in ("AGENTS.md", INSTR, SP))
    rj, rt = car(p), car(p, json_=False)
    sj, stt = status(p), status(p, json_=False)
    outs = [rj.out, rj.err, rt.out, rt.err, sj.out, sj.err, stt.out, stt.err]
    diffs = rj.dd().get("differences", {})
    kinds_ok = all(set(diffs.get(rel, {}).get("masked_kinds", [])) >= {"credential.token", "credential.cloud_key",
                                                                       "credential.assignment", "credential.private_key"}
                   for rel in ("AGENTS.md", INSTR, SP))
    checks += [
        ("05f fixture: canaries are on disk in the kept fragments and front matter", on_disk),
        ("05f no canary value in carriers/status output (text and JSON, stdout and stderr)", no_needles(*outs)),
        ("05f each kind replaced by its redaction marker (text and JSON)",
         all(m in rj.out and m in rt.out and m in sj.out and m in stt.out for m in MARKERS)),
        ("05f front-matter canaries masked in the front-matter difference",
         all(m in json.dumps(diffs.get(INSTR, {}).get("front_matter_diff", [])) for m in
             ("[masked:credential.token]", "[masked:credential.cloud_key]", "[masked:credential.assignment]"))),
        ("05f shown content labelled as masked; masked kinds listed",
         all(diffs.get(rel, {}).get("content") == MASK_LABEL for rel in ("AGENTS.md", INSTR, SP)) and kinds_ok),
        ("05f/05b fragments kept on disk (canaries remain the user's content)", on_disk),
    ]
    for mode in ("json", "text"):
        x = clone(p, f"b18g{mode}")
        rg = car(x, "--regenerate", "host-entry", "--regenerate", "github-instructions", "--regenerate", "system-prompt",
                 json_=(mode == "json"))
        out = rg.out
        checks += [
            (f"05g ({mode}) regenerate: replaced content/difference masked with the same markers",
             rg.code == 0 and all(m in out for m in MARKERS)),
            (f"05g ({mode}) no unmasked replaced content in output or stderr", no_needles(rg.out, rg.err)
             and rg.err == ""),
            (f"05g ({mode}) managed regions now hold the toolkit rendering (canaries gone from managed parts)",
             not any(n in read(x, rel) for n in NEEDLES for rel in ("AGENTS.md", INSTR, SP))
             and read(x, INSTR).startswith(FM)),
        ]
    return checks


# ================================================================ TC-B-19  status per carrier, read-only
def tc_b19_status(notes):
    checks = []
    expect = {}
    p1 = proj("b19a", pre=lambda q: write(q, "CLAUDE.md", "# another environment's host file\n"))
    car(p1, *ALL3)
    t = read(p1, INSTR)
    pre, _, suf = split_block(t)
    write(p1, INSTR, pre + "Instructions without the toolkit block.\n" + suf)     # absent
    (p1 / SP).unlink()                                                               # missing file
    expect[p1] = {"host-entry": "present", "github-instructions": "absent", "system-prompt": "missing file"}
    p2 = proj("b19b")
    car(p2, *ALL3)
    edit_inner(p2, "AGENTS.md", "- edited")                                          # modified
    edit_inner(p2, INSTR, "- accepted")
    car(p2, "--accept", "github-instructions")                                       # customized
    car(p2, "--deselect", "system-prompt")                                           # no longer managed
    expect[p2] = {"host-entry": "modified", "github-instructions": "customized", "system-prompt": "no longer managed"}
    p3 = proj("b19c")
    car(p3, *ALL3)
    write(p3, "AGENTS.md", read(p3, "AGENTS.md").replace(END + "\n", ""))               # malformed
    write(p3, INSTR, (p3 / INSTR).read_bytes() + b"\xff\xfe")                       # unreadable (not UTF-8)
    expect[p3] = {"host-entry": "malformed", "github-instructions": "unreadable", "system-prompt": "present"}
    projects = [p1, p2, p3]
    label = {p1: "P1(present/absent/missing file)", p2: "P2(modified/customized/no longer managed)",
             p3: "P3(malformed/unreadable non-UTF-8/present)"}
    if not IS_ROOT:
        p4 = proj("b19d")
        car(p4, *ALL3)
        os.chmod(p4 / "AGENTS.md", 0)
        os.chmod(p4 / SP, 0)
        expect[p4] = {"host-entry": "unreadable", "github-instructions": "present", "system-prompt": "unreadable"}
        projects.append(p4)
        label[p4] = "P4(unreadable chmod 000)"
    seen = set()
    for q in projects:
        s0 = snap(q)
        st = status(q)
        stt = status(q, json_=False)
        sh = st.dd().get("host_integration", {})
        items = {c["carrier"]: c for c in sh.get("carriers", [])}
        got = {k: c.get("fragment") for k, c in items.items()}
        seen |= set(got.values())
        checks += [
            (f"06a {label[q]}: per-carrier fragment states {sorted(expect[q].values())}", got == expect[q]),
            (f"06a {label[q]}: path, selection, metadata state, one next step, host effect not verified",
             all(c.get("path") and c.get("selection") and "front_matter" in c and c.get("next_step")
                 and c.get("host_effect") == "not verified" for c in items.values())),
            (f"06a {label[q]}: only the record's environment carriers (no CLAUDE.md entry)",
             all(c["path"] != "CLAUDE.md" for c in items.values())),
            (f"06a {label[q]}: FEATURE-001-A host fields kept", HOST_KEYS_001A <= set(sh)),
            (f"06b {label[q]}: status wrote nothing (text and JSON runs)",
             snap(q) == s0 and st.code == 0 and stt.code == 0),
        ]
        if q in expect and expect[q].get("github-instructions") in ("present", "absent", "customized"):
            checks.append((f"06a {label[q]}: instructions metadata state reported (front matter ok)",
                           items["github-instructions"].get("front_matter") == "ok"))
    if not IS_ROOT:
        os.chmod(projects[3] / "AGENTS.md", 0o644)
        os.chmod(projects[3] / SP, 0o644)
        notes["unreadable_variant"] = "chmod 000 (host)"
    else:
        notes["unreadable_variant"] = "non-UTF-8 only (container runs as root: chmod 000 not effective)"
    checks.append(("06a all eight states observed",
                   {"present", "absent", "missing file", "modified", "customized", "no longer managed", "malformed",
                    "unreadable"} <= seen))
    fresh = new_dir("b19e") / "proj ü"
    fresh.mkdir()
    s0 = snap(fresh)
    r = status(fresh)
    checks.append(("06b status on an uninitialized project writes nothing", r.code == 0 and snap(fresh) == s0))
    return checks


# ================================================================ TC-B-20  nested sandbox, seeded ancestors
def _seed_ancestors(top: Path, donor: Path) -> list[Path]:
    seeds = {
        "AGENTS.md": f"# ancestor rules\n{BEGIN}\nancestor fragment\n{END}\n",
        "CLAUDE.md": "# ancestor Claude rules without markers\n",
        ".github/copilot-instructions.md": "ancestor repository instructions\n",
        INSTR: FM + "\n" + f"{BEGIN}\nancestor instructions\n{END}\n",
        RECORD: read(donor, RECORD),
        ".github/skills/x-ipe-secure-code-toolkit-framework/SKILL.md": "ancestor skill\n",
        f".github/skills/{DEF_REL}": read(donor, f".claude/skills/{DEF_REL}"),
        "a/AGENTS.md": "# intermediate ancestor rules mentioning secure-code\n",
    }
    paths = []
    for rel, text in seeds.items():
        write(top, rel, text)
        paths.append(top / rel)
    return paths


def _run_sequence(p: Path) -> list:
    rs = [status(p), car(p), init(p), car(p, *ALL3), status(p), car(p), init(p)]
    return [norm(r.data, p) for r in rs]


def tc_b20_nested_sandbox(notes):
    checks = []
    donor = proj("b20donor", env=CC)
    seeded_top = new_dir("b20seeded")
    plain_top = new_dir("b20plain")
    seeds = _seed_ancestors(seeded_top, donor)
    ps = seeded_top / "a" / "b" / "proj ü"
    pp = plain_top / "a" / "b" / "proj ü"
    ps.mkdir(parents=True)
    pp.mkdir(parents=True)
    anc_before = {k: v for k, v in snap(seeded_top).items() if not k.startswith("a/b/proj ü")}
    locked = []
    if not IS_ROOT:
        for s in seeds:
            os.chmod(s, 0)            # any read of a seeded ancestor file would now fail visibly
            locked.append(s)
        for d in (seeded_top / ".github/instructions", seeded_top / ".x-ipe", seeded_top / ".github/skills"):
            os.chmod(d, 0)
            locked.append(d)
    try:
        seq_s = _run_sequence(ps)
    finally:
        for s in reversed(locked):
            os.chmod(s, 0o755 if s.is_dir() else 0o644)
    seq_p = _run_sequence(pp)
    anc_after = {k: v for k, v in snap(seeded_top).items() if not k.startswith("a/b/proj ü")}
    notes["ancestor_read_probe"] = "seeded files/folders chmod 000 during the runs" if not IS_ROOT else \
        "not applicable as root (container); results comparison and write check only"
    checks += [
        ("07e results with seeded ancestors equal results without seeds (status, carriers, init, selection)",
         seq_s == seq_p),
        ("07b/07e first carriers run on the uninitialized nested root refused (ancestor record not used)",
         seq_s[1]["problems"][0]["code"] == "PROJECT_NOT_INITIALIZED"),
        ("07b carriers written only under the explicit root",
         all((ps / rel).is_file() for rel in ("AGENTS.md", INSTR, SP)) and (ps / RECORD).is_file()),
        ("07b/07e ancestor files byte-identical, no ancestor write (inode/mtime too)", anc_after == anc_before),
        ("07e no new carrier/record/skills path in any ancestor folder",
         not [k for k in set(anc_after) - set(anc_before)]),
    ]
    return checks


# ================================================================ TC-B-21  record compatibility, environment switch
def tc_b21_record_compat(notes):
    checks = []
    p = proj("b21")
    rec0 = record(p)
    checks.append(("08b fresh record: unchanged schema id, exactly the FEATURE-001-A fields, no member",
                   rec0["schema"] == "ai-secure-code-toolkit/install-record/v1" and set(rec0) == RECORD_KEYS_001A))
    car(p)
    checks.append(("08b default carriers run: member still omitted (record equals FEATURE-001-A shape)",
                   set(record(p)) == RECORD_KEYS_001A))
    car(p, *ALL3)
    rec1 = record(p)
    checks += [
        ("08b with optional carriers: the only addition is the 'carriers' member",
         set(rec1) == RECORD_KEYS_001A | {"carriers"} and rec1["schema"] == rec0["schema"]
         and rec1["initialized_at"] == rec0["initialized_at"] and rec1["files"] == rec0["files"]),
        ("08b top-level host_entry/fragment_sha256 authoritative for the host entry carrier",
         rec1["host_entry"] == "AGENTS.md" and rec1["fragment_sha256"] == sha_text(inner_of(p, "AGENTS.md"))
         and "fragment_sha256" not in rec1["carriers"]["entries"].get("host-entry", {})),
    ]
    # 08c plain init ignores stored optional selections and carries the member forward.
    edit_inner(p, INSTR, "- user edit in the optional carrier")
    edit_definition(p, "I")
    meta = {rel: os.lstat(p / rel)[stat.ST_INO] for rel in (INSTR, SP)}
    bytes_ = {rel: (p / rel).read_bytes() for rel in (INSTR, SP)}
    member = record(p)["carriers"]
    ri = init(p)
    rit = init(p, json_=False)
    checks += [
        ("08c plain init: FEATURE-001-A data keys only (no carrier keys)", set(ri.dd()) == INIT_DATA_KEYS_001A),
        ("08c plain init neither generates, checks, reports nor modifies optional carriers",
         all((p / rel).read_bytes() == bytes_[rel] and os.lstat(p / rel)[stat.ST_INO] == meta[rel] for rel in (INSTR, SP))
         and not any(word in out for out in (ri.out, rit.out)
                     for word in (INSTR, SP, "github-instructions", "system-prompt", "integration_declaration"))),
        ("08c plain init carries the member forward unchanged", record(p)["carriers"] == member),
        ("08c host entry updated by FEATURE-001-A logic (single fragment, same markers)",
         ri.dd()["fragment"] == "update" and begins(read(p, "AGENTS.md")) == 1),
    ]
    st = status(p)
    checks.append(("08c status host section keeps FEATURE-001-A fields; per-carrier entries only additional",
                   HOST_KEYS_001A <= set(st.dd()["host_integration"])
                   and st.dd()["host_integration"]["host_entry"] == "AGENTS.md"))
    # 08d one environment per record.
    s0 = snap(p)
    rm = car(p, env=CC)
    checks.append(("08d carriers with another environment refused ENV_MISMATCH, next step init for it, nothing written",
                   rm.code == 1 and rm.codes() == ["ENV_MISMATCH"] and "--env claude-code" in rm.data["next_steps"][0]
                   and snap(p) == s0))
    gc_files = {rel: ((p / rel).read_bytes(), os.lstat(p / rel)[stat.ST_INO]) for rel in ("AGENTS.md", INSTR, SP)}
    rs = init(p, env=CC)
    rec2 = record(p)
    st2 = status(p)
    rc2 = car(p, env=CC)
    listed = [c["path"] for c in st2.dd()["host_integration"]["carriers"]] + [c["path"] for c in rc2.dd()["carriers"]]
    checks += [
        ("08d plain init switching to claude-code: new record without per-carrier entries of github-copilot",
         rs.code == 0 and rec2["environment"] == CC and "carriers" not in rec2),
        ("08d github-copilot carrier files left untouched",
         all(((p / rel).read_bytes(), os.lstat(p / rel)[stat.ST_INO]) == gc_files[rel] for rel in gc_files)),
        ("08d no result or status reports github-copilot carriers",
         "AGENTS.md" not in listed and INSTR not in listed and set(listed) == {"CLAUDE.md"}),
    ]
    # 08e (behaviour behind the documented limit): a pre-003B toolkit refuses an extended record.
    old = scripts_of("old")
    q = proj("b21old")
    car(q, *ALL3)
    s1 = snap(q)
    ro = init(q, scripts=old)
    rso = status(q, scripts=old)
    w = proj("b21oldplain")
    car(w)
    rw = init(w, scripts=old)
    checks += [
        ("08e pre-003B toolkit refuses an extended record with its record error (RECORD_INVALID), writes nothing",
         ro.code == 1 and ro.codes() == ["RECORD_INVALID"] and snap(q) == s1),
        ("08e pre-003B status shows the record as invalid", rso.dd()["install"]["state"] == "invalid record"),
        ("08b member omitted: pre-003B toolkit still reads a record written by this version",
         rw.code == 0 and "RECORD_INVALID" not in rw.codes()),
    ]
    return checks


# ================================================================ TC-B-22  claude-code environment
def tc_b22_claude_code(notes):
    v = toolkit_version()
    p = proj("b22", env=CC, pre=lambda q: write(q, "AGENTS.md", "# user's AGENTS.md for another host\n"))
    agents = (p / "AGENTS.md").read_bytes()
    d = defn_of(p, CC)
    r0 = car(p, env=CC)
    r1 = car(p, "--select", "system-prompt", "--system-prompt-host", "claude-cli", env=CC)
    st = status(p)
    items = [c["path"] for c in st.dd()["host_integration"]["carriers"]]
    return [
        ("claude-code: CLAUDE.md fragment = rendering for CLAUDE.md (skills in .claude/skills)",
         inner_of(p, "CLAUDE.md") == render(d, v, CC, "host-entry") and (p / f".claude/skills/{DEF_REL}").is_file()),
        ("claude-code default: only CLAUDE.md checked", r0.states() == {"host-entry": "current"}),
        ("claude-code system-prompt fragment generated for the named host",
         r1.states() == {"host-entry": "current", "system-prompt": "created"}
         and read(p, SP) == block(render(d, v, CC, "system-prompt", "claude-cli"))),
        ("claude-code status lists only claude-code carriers", items == ["CLAUDE.md", SP]),
        ("claude-code: the user's AGENTS.md untouched", (p / "AGENTS.md").read_bytes() == agents),
    ]


# ================================================================ TC-S-01  documentation (structured package inspection)
def tc_s01_docs(notes):
    checks = []
    p = proj("s01")
    for where, base in (("toolkit source", TOOLKIT / FW), ("installed", p / ".github/skills" / FW)):
        env_md = (base / "references/environments.md").read_text(encoding="utf-8")
        cli_md = (base / "references/cli-contract.md").read_text(encoding="utf-8")
        skill = (base / "SKILL.md").read_text(encoding="utf-8")
        flat_env, flat_cli = " ".join(env_md.split()), " ".join(cli_md.split())
        checks += [
            (f"08e ({where}) environments.md: older versions cannot read the extended record, refuse it, "
             "no forward compatibility",
             "Toolkit versions before the carriers operation cannot read an install record that holds the "
             "`carriers` member and refuse it with `RECORD_INVALID`; there is no forward compatibility." in flat_env),
            (f"08e ({where}) environments.md: member omitted while no optional carrier or customization is recorded",
             "omitted while no optional carrier or customization is recorded" in flat_env),
            (f"08e ({where}) cli-contract.md: member omission and no forward compatibility",
             "omitted while no optional carrier or customization is recorded" in flat_cli
             and "cannot read" in flat_cli and "RECORD_INVALID" in flat_cli),
            (f"FR-003B-8 ({where}) cli-contract.md lists the carriers command and its problem codes",
             "`secure-code carriers`" in cli_md and all(code in cli_md for code in (
                 "CARRIER_UNSUPPORTED", "ENV_MISMATCH", "LOCK_UNAVAILABLE", "SKILLS_INVALID",
                 "ROUTING_DEFINITION_INVALID", "CARRIER_UNREADABLE", "DECISION_NOT_APPLICABLE",
                 "FRONT_MATTER_DRIFT", "CUSTOMIZATION_ROUTING_CHANGED", "LOCKED"))),
            (f"FR-003B-8 ({where}) Framework SKILL.md describes the carriers operation and the honest limit",
             "secure-code carriers" in skill and "host effect: not verified" in skill),
            (f"06c ({where}) no Framework skill/reference text claims host loading or verified routing",
             not any(CLAIMS.search(x) for x in (env_md, cli_md, skill))),
            (f"B11 ({where}) environments.md states the Windows interim neutrally (open gap, not 'unsupported')",
             "LOCK_UNAVAILABLE" in env_md and "B11" in flat_env and "Windows unsupported" not in flat_env
             and "Windows is unsupported" not in flat_env),
        ]
    return checks


# ================================================================ TC-B-23  run hygiene (sandbox-only, masking, toolkit)
def _carrier_paths_in_ancestors(start: Path) -> dict:
    names = ("AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md", ".github/instructions",
             ".x-ipe/private/secure-code")
    found = {}
    for d in [start, *start.parents]:
        for n in names:
            q = d / n
            if q.is_symlink() or q.is_file():
                found[str(q)] = sha(q.read_bytes()) if q.is_file() else "link"
            elif q.is_dir():
                found[str(q)] = sorted(str(x) for x in q.rglob("*"))
    return found


START = {}


def tc_b23_hygiene(notes):
    blob = "\n".join(OUTPUTS)
    tree_now = {k: v[1] for k, v in snap(TOOLKIT).items() if v[0] == "f" and "/.venv/" not in f"/{k}"
                and "__pycache__" not in k and ".pytest_cache" not in k and ".ruff_cache" not in k}
    notes["cli_invocations"] = len(OUTPUTS) // 2
    checks = [
        ("no canary value in any output of the whole run", not any(n in blob for n in NEEDLES)),
        ("no traceback in any stderr of the whole run", "Traceback" not in blob),
        ("07b/07d no carrier, instructions or secure-code path added/changed in any ancestor of the work folder",
         _carrier_paths_in_ancestors(WORK) == START["ancestors"]),
        ("07a/07d toolkit source tree byte-identical start -> end", tree_now == START["toolkit"]),
    ]
    if "repo" in START:
        checks.append(("07a development repository carriers unchanged (AGENTS.md, CLAUDE.md, "
                       ".github/copilot-instructions.md, .github/instructions)",
                       _carrier_paths_in_ancestors(TOOLKIT.parent) == START["repo"]))
    return checks


# ---------------------------------------------------------------- main
def main() -> int:
    if MODE == "container" and os.environ.get("FAT_ISOLATED") != "1":
        print("refusing: container mode expects a disposable HOME and FAT_ISOLATED=1")
        return 2
    if OLD_PKG is None or not (OLD_PKG / "cli.py").is_file():
        print("refusing: FAT_OLD_PKG must point to the pre-003B x_ipe_secure_code folder")
        return 2
    if WORK.exists():
        chmod_tree_back(WORK)
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    START["ancestors"] = _carrier_paths_in_ancestors(WORK)
    START["toolkit"] = {k: v[1] for k, v in snap(TOOLKIT).items() if v[0] == "f" and "/.venv/" not in f"/{k}"
                        and "__pycache__" not in k and ".pytest_cache" not in k and ".ruff_cache" not in k}
    if MODE == "host":
        START["repo"] = _carrier_paths_in_ancestors(TOOLKIT.parent)
    case("TC-B-01", ["AC-003B-01a", "AC-003B-01c", "AC-003B-01f", "AC-003B-03b", "AC-003B-03c", "AC-003B-03h",
                     "AC-003B-06c"], tc_b01_all_carriers)
    case("TC-B-02", ["AC-003B-02a", "AC-003B-02b", "AC-003B-02c", "AC-003B-02d", "AC-003B-02e", "AC-003B-02f",
                     "AC-003B-02g"], tc_b02_routing_content)
    case("TC-B-03", ["AC-003B-01b"], tc_b03_definition_change)
    case("TC-B-04", ["AC-003B-01d", "AC-003B-03d", "AC-003B-08b", "AC-003B-08c"], tc_b04_pre003b_upgrade)
    case("TC-B-05", ["AC-003B-01e"], tc_b05_interleaved)
    case("TC-B-06", ["AC-003B-01g", "AC-003B-01h", "AC-003B-01i", "AC-003B-01j", "AC-003B-05d"],
         tc_b06_accepted_customization)
    case("TC-B-07", ["AC-003B-01k", "AC-003B-05f"], tc_b07_replace_after_acceptance)
    case("TC-B-08", ["AC-003B-03a", "AC-003B-03d"], tc_b08_default_and_write_set)
    case("TC-B-09", ["AC-003B-03e"], tc_b09_deselect)
    case("TC-B-10", ["AC-003B-03f"], tc_b10_unsupported)
    case("TC-B-11", ["AC-003B-03g", "AC-003B-06d", "AC-003B-05c"], tc_b11_instructions_boundaries)
    case("TC-B-12", ["AC-003B-04a", "AC-003B-04b", "AC-003B-04c"], tc_b12_preservation)
    case("TC-B-13", ["AC-003B-04d", "AC-003B-04e"], tc_b13_malformed_and_links)
    case("TC-B-14", ["AC-003B-04f"], tc_b14_write_failure)
    case("TC-B-15", ["AC-003B-04g", "AC-003B-04h"], tc_b15_concurrency)
    case("TC-B-16", ["AC-003B-04i"], tc_b16_lock_unavailable_posix, only="host")
    case("TC-B-17", ["AC-003B-05a", "AC-003B-05b", "AC-003B-05c", "AC-003B-05d", "AC-003B-05e"], tc_b17_differences)
    case("TC-B-18", ["AC-003B-05f", "AC-003B-05g"], tc_b18_masking)
    case("TC-B-19", ["AC-003B-06a", "AC-003B-06b"], tc_b19_status)
    case("TC-B-20", ["AC-003B-07b", "AC-003B-07e"], tc_b20_nested_sandbox)
    case("TC-B-21", ["AC-003B-08b", "AC-003B-08c", "AC-003B-08d", "AC-003B-08e"], tc_b21_record_compat)
    case("TC-B-22", ["AC-003B-03f", "AC-003B-06a"], tc_b22_claude_code)
    case("TC-S-01", ["AC-003B-08e", "AC-003B-06c"], tc_s01_docs)
    case("TC-B-23", ["AC-003B-07a", "AC-003B-07b", "AC-003B-07d", "AC-003B-05f"], tc_b23_hygiene)
    chmod_tree_back(WORK)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": MODE, "platform": sys.platform, "python": sys.version.split()[0],
                                  "root": IS_ROOT, "passed": passed, "total": len(RESULTS),
                                  "checks": sum(len(r.get("checks", [])) for r in RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
