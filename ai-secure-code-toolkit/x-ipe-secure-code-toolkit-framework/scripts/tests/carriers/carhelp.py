"""Shared helpers for the FEATURE-003-B carrier tests.

Every project used here is a sandbox target project created beneath the test's own
``tmp_path`` (never the toolkit development repository). Product code under test is reached
through the CLI (``conftest.run_cli`` or a toolkit copy's own launcher) or, for unit-level
cases, in-process under ``allow(project)`` of the write-audit harness.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from conftest import SCRIPTS, TOOLKIT_ROOT, run_cli, tree_hashes

SUPPORT = SCRIPTS / "tests" / "support"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

ENV = "github-copilot"
AGENTS = "AGENTS.md"
CLAUDE = "CLAUDE.md"
INSTR = ".github/instructions/x-ipe-secure-code-toolkit.instructions.md"
SYSP = ".x-ipe/private/secure-code/carriers/system-prompt.md"
RECORD = ".x-ipe/private/secure-code/install-record.json"
FRAMEWORK = "x-ipe-secure-code-toolkit-framework"
DEF_REL = f"{FRAMEWORK}/references/routing-definition.json"
FRONT_MATTER = '---\napplyTo: "**"\n---\n'
BEGIN = "<!-- BEGIN ai-secure-code-toolkit: managed fragment, edits are reported not overwritten -->"
END = "<!-- END ai-secure-code-toolkit -->"
KINDS = ("host-entry", "github-instructions", "system-prompt")
PATHS = {"host-entry": AGENTS, "github-instructions": INSTR, "system-prompt": SYSP}
HOST = "copilot-cli"
CHOICES = [
    "keep (default)",
    "modify, then keep or accept",
    "change the routing definition",
    "regenerate (--regenerate {kind})",
    "accept customization (--accept {kind})",
]
HOST_EFFECT_RESULT = "written / component-checked; host effect not verified"
RECORD_001A_KEYS = {"schema", "toolkit_version", "environment", "skills_dir", "host_entry",
                    "fragment_sha256", "initialized_at", "updated_at", "files"}
# Modules/data this feature adds to the payload; removing them yields a FEATURE-001-A-era toolkit.
ERA_001A_REMOVED = (
    f"{FRAMEWORK}/references/routing-definition.json",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/routing.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/carrier_view.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/carriers.py",
    # Every payload file added after the recorded baseline is removed too (DAO-002 code implementation):
    # FEATURE-001-F.
    f"{FRAMEWORK}/references/presets-and-tags.md",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/catalog.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/presets.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/tags.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/policy/preset_scope.py",
    # FEATURE-002-G.
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare_bounds.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare_cover.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare_io.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare_match.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare_render.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/guard/compare_validate.py",
    # FEATURE-001-G.
    f"{FRAMEWORK}/references/knowledge-drafting.md",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_auth.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_blocks.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_checks.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_lint.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_mask.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_model.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_pipeline.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_service.py",
    f"{FRAMEWORK}/scripts/src/x_ipe_secure_code/knowledge/drafting_supplements.py",
)

# FEATURE-001-A minimal fragment, byte for byte as written by host_fragment.py a14b9b85… (golden).
_GOLDEN_BODY = (
    "## AI Secure Code Toolkit\n"
    "\n"
    "This project uses the AI secure-code toolkit skills in `{skills}/`:\n"
    "\n"
    "- `x-ipe-secure-code-toolkit-copilot`: use during design, implementation, bug fix and refactor "
    "tasks for in-flow security suggestions and adoption review.\n"
    "- `x-ipe-secure-code-toolkit-guard`: use only for an explicit or authorized security verification "
    "request; it reports findings and does not fix.\n"
    "- `x-ipe-secure-code-toolkit-framework`: security knowledge, Policies, status and Maintainer "
    "authorization.\n"
    "\n"
    "Check status: `uvx --from {skills}/x-ipe-secure-code-toolkit-framework/scripts secure-code status "
    "--project . --json`\n"
)
GOLDEN_001A_BODY = {
    "github-copilot": _GOLDEN_BODY.format(skills=".github/skills"),
    "claude-code": _GOLDEN_BODY.format(skills=".claude/skills"),
}
GOLDEN_001A_FRAGMENT = {env: BEGIN + "\n" + body + END + "\n" for env, body in GOLDEN_001A_BODY.items()}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_text(text: str) -> str:
    """Same digest as host_fragment.sha256_text (CRLF-normalized)."""
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def canaries() -> dict[str, str]:
    """Secret-looking canary values, assembled from parts (no single real-looking literal)."""
    return {
        "credential.token": "ghp_" + "Zq9" * 12,
        "credential.cloud_key": "AKIA" + "QX7Z" * 4,
        "credential.private_key": "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE" + "qW3r" * 10
        + "\n-----END RSA " + "PRIVATE KEY-----",
        "credential.assignment": 'password = "' + "Hunter" + "2wq9Zt" + '"',
    }


def canary_needles() -> list[str]:
    """Substrings that must never appear in any output once masked."""
    c = canaries()
    return [c["credential.token"], c["credential.cloud_key"], "qW3r" * 10, "Hunter2wq9Zt"]


# ---------------------------------------------------------------- write-audit harness access

def write_audit():
    """The suite-wide write-audit harness (tests/support/write_audit.py)."""
    if str(SUPPORT) not in sys.path:
        sys.path.insert(0, str(SUPPORT))
    import write_audit as module

    return module


@contextmanager
def allow(*roots: Path) -> Iterator[None]:
    """Register in-process product writes beneath exactly these roots."""
    with write_audit().allow(*roots):
        yield


@contextmanager
def watch_writes() -> Iterator[list[dict[str, Any]]]:
    """Collect the product write records made (in this process or its children) inside the block."""
    wa = write_audit()
    mark = wa.mark()
    box: list[dict[str, Any]] = []
    yield box
    box.extend(wa.writes_since(mark))


def written_paths(records: list[dict[str, Any]]) -> set[Path]:
    paths: set[Path] = set()
    for record in records:
        paths.update(Path(p) for p in record["resolved"])
    return paths


# ---------------------------------------------------------------- sandbox target projects

@dataclass
class Sandbox:
    tmp: Path
    root: Path
    trust: Path
    env: str

    def run(self, *args: str, extra: tuple[str, ...] = (), json_out: bool = True,
            env_extra: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess, dict]:
        argv = [*args, "--json"] if json_out else list(args)
        proc = run_cli(argv, self.trust, extra=list(extra), env_extra=env_extra)
        if not json_out:
            return proc, {}
        try:
            out = json.loads(proc.stdout)
        except ValueError:
            out = {"ok": False, "data": {}, "problems": [], "next_steps": [],
                   "unparsed": proc.stdout + proc.stderr}
        return proc, out

    def init(self, *args: str, env: str | None = None, toolkit: Path | None = None,
             json_out: bool = True):
        argv = ["init", "--project", str(self.root), "--env", env or self.env, *args]
        if toolkit is not None:
            argv += ["--toolkit-source", str(toolkit)]
        return self.run(*argv, json_out=json_out)

    def carriers(self, *args: str, env: str | None = None, json_out: bool = True):
        return self.run("carriers", "--project", str(self.root), "--env", env or self.env, *args,
                        json_out=json_out)

    def status(self, json_out: bool = True, extra: tuple[str, ...] = ()):
        return self.run("status", "--project", str(self.root), json_out=json_out, extra=extra)

    def select_all(self, *extra: str):
        return self.carriers("--select", "github-instructions", "--select", "system-prompt",
                             "--system-prompt-host", HOST, *extra)

    def path(self, rel: str) -> Path:
        return self.root / rel

    def read(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()

    def text(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def write(self, rel: str, data: bytes | str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)

    def record(self) -> dict[str, Any]:
        return json.loads(self.text(RECORD))

    def save_record(self, data: dict[str, Any] | str) -> None:
        text = data if isinstance(data, str) else json.dumps(data, indent=2, sort_keys=True) + "\n"
        self.write(RECORD, text)

    def hashes(self) -> dict[str, str]:
        return tree_hashes(self.root)

    def skills_dir(self) -> str:
        return ".github/skills" if self.env == "github-copilot" else ".claude/skills"

    def definition_path(self) -> Path:
        return self.root / self.skills_dir() / DEF_REL

    def definition(self) -> dict[str, Any]:
        return json.loads(self.definition_path().read_text(encoding="utf-8"))

    def edit_definition(self, change=None) -> dict[str, Any]:
        """Maintainer edit of the installed routing definition (still valid)."""
        obj = self.definition()
        (change or edit_statement)(obj)
        self.definition_path().write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n",
                                          encoding="utf-8")
        return obj


def sandbox(tmp_path: Path, env: str = ENV, *, init: bool = True, name: str = "sbx ü",
            parent: Path | None = None) -> Sandbox:
    root = (parent or (tmp_path / name)) / "project"
    root.mkdir(parents=True)
    box = Sandbox(tmp=tmp_path, root=root, trust=tmp_path / "trust-app", env=env)
    if init:
        proc, out = box.init()
        assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return box


def edit_statement(obj: dict[str, Any], suffix: str = " Keep the change small.") -> None:
    """A valid Maintainer edit: extend the first Copilot statement."""
    for section in obj["sections"]:
        if section["id"] == "copilot":
            section["statements"][0] = section["statements"][0] + suffix
            return
    raise AssertionError("definition has no copilot section")


def packaged_definition() -> dict[str, Any]:
    return json.loads((TOOLKIT_ROOT / DEF_REL).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- results

def entry(out: dict[str, Any], kind: str, *, section: str | None = None) -> dict[str, Any]:
    data = out["data"] if section is None else out["data"][section]
    matches = [item for item in data.get("carriers", []) if item["carrier"] == kind]
    assert len(matches) == 1, (kind, data.get("carriers"), out.get("problems"), out.get("unparsed"))
    return matches[0]


def status_entry(out: dict[str, Any], kind: str) -> dict[str, Any]:
    return entry(out, kind, section="host_integration")


def codes(out: dict[str, Any]) -> list[str]:
    return [p["code"] for p in out.get("problems", [])]


def problem(out: dict[str, Any], code: str) -> dict[str, str]:
    found = [p for p in out.get("problems", []) if p["code"] == code]
    assert found, (code, out.get("problems"), out.get("unparsed"))
    return found[0]


def choices(kind: str) -> list[str]:
    return [c.format(kind=kind) for c in CHOICES]


def inner(text: str) -> str:
    """Text strictly between the BEGIN and END marker lines, LF-normalized."""
    lines = text.replace("\r\n", "\n").splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    assert len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0], text
    return "".join(lines[begins[0] + 1:ends[0]])


def split_outside(data: bytes) -> tuple[bytes, bytes, bytes]:
    """(bytes before the BEGIN line, the BEGIN…END block, bytes after the END line)."""
    begin = data.index(BEGIN.encode())
    end_marker = data.index(END.encode())
    stop = data.index(b"\n", end_marker) + 1
    return data[:begin], data[begin:stop], data[stop:]


def identity_text(version: str, digest: str) -> str:
    return f"ai-secure-code-toolkit {version}, definition sha256:{digest}"


def routing_region(text: str) -> str:
    """Lines from 'This project uses' up to and including 'Check status:' (AC-003B-01f)."""
    body = inner(text)
    start = body.index("This project uses")
    stop = body.index("\n", body.index("Check status:")) + 1
    return body[start:stop]


def begin_count(data: bytes) -> int:
    return data.count(BEGIN.encode())


# ---------------------------------------------------------------- toolkit copies

def toolkit_copy(tmp_path: Path, *, era: str | None = None, version: str | None = None,
                 definition: dict[str, Any] | bytes | None = None, name: str | None = None) -> Path:
    """Copy of the toolkit (a real second toolkit version when its own launcher is used)."""
    dest = tmp_path / (name or f"toolkit-{era or version or 'copy'}")
    shutil.copytree(TOOLKIT_ROOT, dest, ignore=shutil.ignore_patterns(
        ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "*.pyc", ".coverage", ".coverage.*",
        "*.egg-info"))
    if era == "001A":
        for rel in ERA_001A_REMOVED:
            (dest / rel).unlink(missing_ok=True)
    if version is not None:
        init = dest / FRAMEWORK / "scripts/src/x_ipe_secure_code/__init__.py"
        init.write_text(re.sub(r'__version__ = "[^"]*"', f'__version__ = "{version}"',
                               init.read_text(encoding="utf-8")), encoding="utf-8")
        pyproject = dest / FRAMEWORK / "scripts/pyproject.toml"
        pyproject.write_text(re.sub(r'(?m)^version = "[^"]*"', f'version = "{version}"',
                                    pyproject.read_text(encoding="utf-8")), encoding="utf-8")
    if definition is not None:
        data = definition if isinstance(definition, bytes) else (
            json.dumps(definition, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        (dest / DEF_REL).write_bytes(data)
    return dest


def run_copy(copy: Path, box: Sandbox, *args: str) -> tuple[subprocess.CompletedProcess, dict]:
    """Run a toolkit copy's own code (its launcher puts the copy's src first on sys.path)."""
    launcher = copy / FRAMEWORK / "scripts/tests/support/launcher.py"
    env = dict(os.environ)
    env.update(write_audit().child_env([box.root, box.trust, box.tmp / ".tmp"]))
    proc = subprocess.run([sys.executable, str(launcher), "--test-trust-dir", str(box.trust), *args,
                           "--json"], capture_output=True, text=True, env=env, timeout=120)
    try:
        out = json.loads(proc.stdout)
    except ValueError:
        out = {"ok": False, "data": {}, "problems": [], "next_steps": [],
               "unparsed": proc.stdout + proc.stderr}
    return proc, out


# ---------------------------------------------------------------- FEATURE-001-A baseline outputs

def normalize_init(stdout: str, root: Path) -> str:
    """Normalize an init result for comparison with the recorded FEATURE-001-A baseline.

    The root path becomes <ROOT>; each per-category list of skill files becomes a count
    (the names are checked separately against the payload).
    """
    text = stdout.replace(str(root), "<ROOT>")
    if text.lstrip().startswith("{"):
        obj = json.loads(text)
        files = obj.get("data", {}).get("files")
        if isinstance(files, dict):
            obj["data"]["files"] = {k: f"<{len(v)} files>" for k, v in files.items()}
        return json.dumps(obj, indent=2, ensure_ascii=False)
    out: list[str] = []
    count = 0
    for line in text.splitlines():
        if re.match(r"^    - \.(github|claude)/skills/", line):
            count += 1
            continue
        if count:
            out.append(f"    - <{count} files>")
            count = 0
        out.append(line)
    if count:
        out.append(f"    - <{count} files>")
    return "\n".join(out)


def normalize_record(data: dict[str, Any]) -> dict[str, Any]:
    data = dict(data)
    data["initialized_at"] = data["updated_at"] = "<TS>"
    data["files"] = f"<{len(data['files'])} files>"
    return data


def baseline_001a() -> dict[str, Any]:
    """FEATURE-001-A plain-init outputs recorded from the unmodified baseline code (TASK-062 Stage A)."""
    return json.loads((FIXTURES / "init_001a_baseline.json").read_text(encoding="utf-8"))


def init_001a_sequence(run_init, root: Path, host: str) -> list[dict[str, Any]]:
    """The recorded FEATURE-001-A plain-init sequence: fresh, rerun, rerun (text), edited, --replace.

    ``run_init(*args, json_out=bool)`` returns (exit code, stdout).
    """
    steps: list[dict[str, Any]] = []

    def step(name: str, *args: str, json_out: bool = True) -> None:
        code, stdout = run_init(*args, json_out=json_out)
        record = json.loads((root / RECORD).read_text(encoding="utf-8"))
        steps.append({"step": name, "exit": code, "stdout": normalize_init(stdout, root),
                      "host": (root / host).read_text(encoding="utf-8"),
                      "record": normalize_record(record)})

    step("fresh")
    step("rerun")
    step("rerun_text", json_out=False)
    path = root / host
    path.write_bytes(path.read_bytes().replace(b"in-flow", b"IN-FLOW"))
    step("edited")
    step("replace", "--replace", host)
    return steps


# ---------------------------------------------------------------- platform simulation (B11 / DAO-005)

class _NtOs:
    """The `os` module as seen by the lock code on Windows: name 'nt', everything else delegated."""

    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


def simulate_no_lock_platform(monkeypatch) -> list[tuple]:
    """Windows simulated for the lock code: os.name == 'nt' and fcntl not importable.

    A global ``os.name`` patch would turn every ``pathlib.Path`` into ``WindowsPath`` on this
    Python, so the platform is simulated where the lock decision is made (``atomic``), while
    ``import fcntl`` fails process-wide. Returns the calls made to the real ``flock`` (spy).
    """
    import fcntl

    from x_ipe_secure_code import atomic

    calls: list[tuple] = []
    real = fcntl.flock

    def spy(*args):
        calls.append(args)
        return real(*args)

    monkeypatch.setattr(fcntl, "flock", spy)
    monkeypatch.setattr(atomic, "os", _NtOs())
    monkeypatch.setattr(atomic, "fcntl", None, raising=False)
    monkeypatch.setitem(sys.modules, "fcntl", None)
    return calls


def flock_failing_with(monkeypatch, code: int) -> list[tuple]:
    """Every flock call fails with errno `code` (simulated file system); returns the calls."""
    import fcntl

    calls: list[tuple] = []

    def failing(fd, operation):
        calls.append((fd, operation))
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(fcntl, "flock", failing)
    return calls


UNAVAILABLE_ERRNOS = {name: getattr(errno, name) for name in ("ENOLCK", "EOPNOTSUPP", "ENOTSUP", "EINVAL")}
HELD_ERRNOS = {name: getattr(errno, name) for name in ("EWOULDBLOCK", "EAGAIN")}


@contextmanager
def hold_project_lock(root: Path, seconds: float) -> Iterator[subprocess.Popen]:
    """A helper process (not toolkit code) holding flock on the project root folder."""
    code = (
        "import fcntl, os, sys, time\n"
        "fd = os.open(sys.argv[1], os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))\n"
        "fcntl.flock(fd, fcntl.LOCK_EX)\n"
        "print('held', flush=True)\n"
        "time.sleep(float(sys.argv[2]))\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code, str(root), str(seconds)],
                            stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None and proc.stdout.readline().strip() == "held"
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=30)


def listing(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")}
