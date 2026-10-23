"""Suite-wide write audit and protected-tree snapshots for the automated tests (test-only).

FEATURE-003-B AC-003B-07a…07e, NFR-003B-7. Every product write (a write whose call stack contains a
frame from an ``x_ipe_secure_code`` package) is classified against the roots registered for that
invocation. The test process uses :func:`install_session`; every child Python process started by a
test loads ``auditsite/sitecustomize.py`` (on ``PYTHONPATH``), which calls :func:`install_child`.

Each process appends JSON lines to ``<log dir>/<pid>.jsonl`` through a descriptor opened before its
hook is installed, so logging raises no audit event of its own.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ENV_LOG = "SECURE_CODE_TEST_WRITE_AUDIT"
ENV_ALLOWED = "SECURE_CODE_TEST_ALLOWED_ROOTS"
ENV_TMP_PATH = "SECURE_CODE_TEST_TMP_PATH"
ENV_TMP_REDIRECT = "SECURE_CODE_TEST_TMP_REDIRECT"
ENV_EXCEPTIONS = "SECURE_CODE_TEST_WRITE_EXCEPTIONS"
ENV_CWD_REDIRECT = "SECURE_CODE_TEST_CWD_REDIRECT"
AUDITSITE = Path(__file__).resolve().parent / "auditsite"
PRODUCT_SEGMENT = os.sep + "x_ipe_secure_code" + os.sep
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _product_argv(argv: list[str]) -> bool:
    """A child that runs the toolkit CLI: the test launcher, the `secure-code` entry point or the package."""
    return any(
        os.path.basename(arg) in ("launcher.py", "secure-code") or arg.startswith("x_ipe_secure_code")
        for arg in argv
    )


# event -> ((path index, dir_fd index or None), ...) for the written paths
EVENTS: dict[str, tuple[tuple[int, int | None], ...]] = {
    "os.rename": ((0, 2), (1, 3)),
    "os.link": ((0, 2), (1, 3)),
    "os.symlink": ((1, 2),),
    "os.remove": ((0, 1),),
    "os.rmdir": ((0, 1),),
    "os.mkdir": ((0, 2),),
    "os.truncate": ((0, None),),
    "os.chmod": ((0, 2),),
    "os.chown": ((0, 3),),
    "os.utime": ((0, 3),),
    "shutil.rmtree": ((0, 1),),
    "shutil.copyfile": ((1, None),),
    "shutil.copytree": ((1, None),),
    "shutil.move": ((0, None), (1, None)),
}


@dataclass(frozen=True)
class Verdict:
    write: bool
    paths: list[str]
    allowed: bool


# ---------------------------------------------------------------- classification (pure)


def _fs(value: Any) -> str | None:
    if isinstance(value, int) or value is None:
        return None
    try:
        return os.fsdecode(os.fspath(value))
    except TypeError:
        return None


def fd_path(fd: int) -> str | None:
    """The path of an open descriptor, or None."""
    try:
        if sys.platform == "darwin":
            import fcntl

            raw = fcntl.fcntl(fd, fcntl.F_GETPATH, b"\0" * 1024)
            return os.fsdecode(raw.split(b"\0", 1)[0]) or None
        return os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError, AttributeError):
        return None


def open_dir_fds() -> list[int]:
    """Descriptors of this process that refer to directories."""
    folder = "/dev/fd" if sys.platform == "darwin" else "/proc/self/fd"
    found = []
    try:
        names = os.listdir(folder)
    except OSError:
        return found
    for name in names:
        try:
            fd = int(name)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                found.append(fd)
        except (ValueError, OSError):
            continue
    return found


def _pattern(glob: str) -> re.Pattern:
    out = []
    i = 0
    while i < len(glob):
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def _is_write_open(args: tuple) -> bool:
    if len(args) < 3 or isinstance(args[0], int):
        return False
    mode, flags = args[1], args[2]
    if isinstance(mode, str) and mode:
        return any(c in mode for c in "wax+")
    return bool(isinstance(flags, int) and flags & WRITE_FLAGS)


def _targets(event: str, args: tuple) -> list[tuple[str | None, int | None]] | None:
    """[(raw path, dir_fd)] written by the event, or None when it is not a write."""
    if event == "open":
        if not _is_write_open(args):
            return None
        return [(_fs(args[0]), None)]
    spec = EVENTS.get(event)
    if spec is None:
        return None
    targets = []
    for path_index, fd_index in spec:
        if path_index >= len(args):
            continue
        raw = args[path_index]
        fd = args[fd_index] if fd_index is not None and fd_index < len(args) else None
        if isinstance(raw, int):  # a descriptor-based call: resolve the descriptor itself
            targets.append((fd_path(raw), None))
            continue
        targets.append((_fs(raw), fd if isinstance(fd, int) and fd >= 0 else None))
    return targets


def _under(path: str, roots: list[str]) -> bool:
    return any(path == root or path.startswith(root.rstrip(os.sep) + os.sep) for root in roots)


def classify(
    event: str,
    args: tuple,
    *,
    allowed: list,
    exceptions: list[str],
    cwd: Path | str,
    open_dir_fds: list[int] | None = None,
) -> Verdict:
    """Is this audit event a write, which paths does it touch, and are all of them allowed?"""
    targets = _targets(event, args)
    if targets is None:
        return Verdict(False, [], True)
    roots = [os.path.realpath(os.fspath(r)) for r in allowed]
    patterns = [_pattern(e) for e in exceptions]
    paths: list[str] = []
    ok = True
    for raw, dir_fd in targets:
        if raw is None:
            ok = False
            continue
        if os.path.isabs(raw):
            bases = [""]
        elif dir_fd is not None:
            base = fd_path(dir_fd)
            if base is None:
                ok = False
                continue
            bases = [base]
        else:
            bases = [os.fspath(cwd)]
            if event == "open":  # an os.open(name, dir_fd=…) shows only the relative name
                bases += [b for b in (fd_path(fd) for fd in (open_dir_fds or [])) if b]
        for base in bases:
            resolved = os.path.realpath(os.path.join(base, raw) if base else raw)
            paths.append(resolved)
            if resolved.startswith("/dev/"):  # devices (e.g. /dev/null, a pty) are not file-system writes
                continue
            if not (_under(resolved, roots) or any(p.match(resolved) for p in patterns)):
                ok = False
    return Verdict(True, paths, ok)


# ---------------------------------------------------------------- the hook (test process and children)

_state = threading.local()
_config: dict[str, Any] = {"fd": None, "role": None, "exceptions": [], "stack": [], "stale_fds": set()}
_write_lock = threading.Lock()
_OS_WRITE = os.write


def _product_frame() -> bool:
    frame = sys._getframe(1)
    depth = 0
    while frame is not None and depth < 80:
        if PRODUCT_SEGMENT in frame.f_code.co_filename:
            return True
        frame = frame.f_back
        depth += 1
    return False


def _node() -> str:
    return os.environ.get("PYTEST_CURRENT_TEST", "").rsplit(" (", 1)[0]


def _env_roots() -> list[str]:
    raw = os.environ.get(ENV_ALLOWED)
    if raw:
        return [r for r in raw.split(os.pathsep) if r]
    return [r for r in (os.environ.get(ENV_TMP_PATH), os.environ.get(ENV_TMP_REDIRECT)) if r]


def _roots() -> list[str]:
    if _config["role"] == "test" and _config["stack"]:
        return list(_config["stack"][-1])
    return [os.path.realpath(r) for r in _env_roots()]


def _emit(record: dict[str, Any]) -> None:
    fd = _config["fd"]
    if fd is None:
        return
    # surrogate-escaped arguments or paths (undecodable bytes) are kept visible, never dropped
    data = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8", "backslashreplace")
    with _write_lock:
        while data:  # a signal may interrupt a write part-way; tests may patch os.write itself
            written = _OS_WRITE(fd, data)
            if written <= 0:
                break
            data = data[written:]


def _handle(event: str, args: tuple) -> None:
    if event == "subprocess.Popen":
        if _config["role"] == "test":
            argv = [
                str(a)
                for a in (
                    args[1]
                    if len(args) > 1 and isinstance(args[1], (list, tuple))
                    else [args[1]]
                    if len(args) > 1
                    else []
                )
            ]
            if _product_argv(argv):
                _emit({"event": "popen", "node": _node(), "pid": os.getpid(), "t": time.time(), "argv": argv})
        return
    if event != "open" and event not in EVENTS:
        return
    if event == "open" and not _is_write_open(args):
        return
    if "x_ipe_secure_code" not in sys.modules or not _product_frame():
        return
    raw = args[0] if args else None
    relative_open = event == "open" and _fs(raw) is not None and not os.path.isabs(_fs(raw))
    roots = _roots()
    candidates = roots
    cwd_redirect = os.environ.get(ENV_CWD_REDIRECT)
    if relative_open and cwd_redirect:
        # The cwd candidate of a relative open with a hidden dir_fd is the test's empty working
        # folder; a real write there is caught by the emptiness check at the end of the test.
        candidates = roots + [os.path.realpath(cwd_redirect)]
    fds = None
    if relative_open:  # descriptors already open when the test began are stale state, not this write's
        fds = [fd for fd in open_dir_fds() if (fd, fd_path(fd)) not in _config["stale_fds"]]
    verdict = classify(
        event, args, allowed=candidates, exceptions=_config["exceptions"], cwd=os.getcwd(), open_dir_fds=fds
    )
    _emit(
        {
            "event": event,
            "node": _node(),
            "pid": os.getpid(),
            "t": time.time(),
            "raw": repr(args)[:300],
            "resolved": verdict.paths,
            "allowed_roots": roots,
            "product": True,
            "allowed": verdict.allowed,
        }
    )


def _hook(event: str, args: tuple) -> None:
    if event != "open" and event != "subprocess.Popen" and event not in EVENTS:
        return
    if getattr(_state, "busy", False):
        return
    _state.busy = True
    try:
        _handle(event, args)
    except Exception as exc:  # noqa: BLE001 - never break the audited operation, but never hide the gap
        _internal_error(event, exc)
    finally:
        _state.busy = False


def _internal_error(event: str, exc: Exception) -> None:
    """An event the hook could not classify is an unaudited write candidate: record it as a violation."""
    _config["internal_errors"] = _config.get("internal_errors", 0) + 1
    try:
        _emit({"event": "audit-error", "audited_event": event, "error": repr(exc)[:300], "node": _node(),
               "pid": os.getpid(), "t": time.time(), "resolved": [], "allowed_roots": [],
               "product": True, "allowed": False})
    except Exception:  # noqa: BLE001 - the counter above still fails the session
        pass


def internal_error_problems() -> list[str]:
    """Session-finish flag: hook failures in this process not consumed as expected test records."""
    count = _config.get("internal_errors", 0)
    if not count:
        return []
    return [f"write-audit hook failed internally {count} time(s); those events were not audited"]


def _open_log(log_dir: str) -> int:
    os.makedirs(log_dir, exist_ok=True)
    return os.open(
        os.path.join(log_dir, f"{os.getpid()}.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
    )


def install_child() -> None:
    """Called by sitecustomize in every child Python process of the test suite."""
    log_dir = os.environ.get(ENV_LOG)
    if not log_dir or _config["role"] is not None:
        return
    _config.update(
        fd=_open_log(log_dir), role="child", exceptions=json.loads(os.environ.get(ENV_EXCEPTIONS, "[]"))
    )
    _emit(
        {
            "event": "process-start",
            "node": _node(),
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "t": time.time(),
            "argv": list(sys.argv),
        }
    )
    sys.addaudithook(_hook)


def install_session(log_dir: Path, exceptions: list[str]) -> None:
    """Install the hook in the pytest process and export the settings to every child process."""
    if _config["role"] is not None:
        return
    os.environ[ENV_LOG] = str(log_dir)
    os.environ[ENV_EXCEPTIONS] = json.dumps(exceptions)
    current = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(AUDITSITE) + (os.pathsep + current if current else "")
    _config.update(fd=_open_log(str(log_dir)), role="test", exceptions=list(exceptions), log_dir=str(log_dir))
    sys.addaudithook(_hook)


# ---------------------------------------------------------------- reading the log

_consumed: set[tuple[str, int]] = set()


def _log_dir() -> Path:
    return Path(_config.get("log_dir") or os.environ[ENV_LOG])


def mark() -> dict[str, int]:
    """Current end of every process log."""
    folder = _log_dir()
    return {p.name: p.stat().st_size for p in folder.glob("*.jsonl")} if folder.is_dir() else {}


def _records_since(position: dict[str, int]) -> list[dict[str, Any]]:
    records = []
    for path in sorted(_log_dir().glob("*.jsonl")):
        start = position.get(path.name, 0)
        with open(path, "rb") as handle:
            handle.seek(start)
            offset = start
            for line in handle:
                key = (path.name, offset)
                offset += len(line)
                if not line.endswith(b"\n"):
                    break
                try:
                    record = json.loads(line)
                except ValueError:  # an unreadable log line is treated as a violation (fail closed)
                    record = {
                        "event": "unreadable-log-line",
                        "node": "",
                        "pid": None,
                        "resolved": [],
                        "allowed_roots": [],
                        "product": True,
                        "allowed": False,
                        "raw": line[:200].decode("utf-8", "replace"),
                    }
                record["_key"] = key
                records.append(record)
    return records


def writes_since(position: dict[str, int]) -> list[dict[str, Any]]:
    """Product write records (any process) logged after `position`."""
    return [r for r in _records_since(position) if r.get("product")]


def violations_since(position: dict[str, int]) -> list[dict[str, Any]]:
    return [r for r in writes_since(position) if not r["allowed"] and tuple(r["_key"]) not in _consumed]


@contextlib.contextmanager
def expect_violations() -> Iterator[list[dict[str, Any]]]:
    """A block that must produce at least one violation (a canary); they are consumed."""
    position = mark()
    found: list[dict[str, Any]] = []
    yield found
    found.extend(violations_since(position))
    if not found:
        raise AssertionError("expected write-audit violation was not detected")
    consume(found)


def consume(records: list[dict[str, Any]]) -> None:
    """Mark expected violation records (canaries, injected hook failures) as handled."""
    for record in records:
        key = tuple(record["_key"])
        if key in _consumed:
            continue
        _consumed.add(key)
        if record.get("event") == "audit-error" and record.get("pid") == os.getpid():
            _config["internal_errors"] = max(0, _config.get("internal_errors", 0) - 1)


def child_env(roots: list) -> dict[str, str]:
    """Environment entries that register exactly these roots for a child process."""
    allowed = [os.path.realpath(os.fspath(r)) for r in roots]
    redirect = os.environ.get(ENV_TMP_REDIRECT)
    if redirect:
        allowed.append(os.path.realpath(redirect))
    return {ENV_ALLOWED: os.pathsep.join(dict.fromkeys(allowed))}


# ---------------------------------------------------------------- registration and per-test state

_test: dict[str, Any] = {}


@contextlib.contextmanager
def allow(*roots) -> Iterator[None]:
    """Register in-process product writes beneath exactly these roots (plus the temp redirect)."""
    resolved = [os.path.realpath(os.fspath(r)) for r in roots]
    for root in resolved:
        register(root)
    redirect = os.environ.get(ENV_TMP_REDIRECT)
    _config["stack"].append(resolved + ([os.path.realpath(redirect)] if redirect else []))
    try:
        yield
    finally:
        _config["stack"].pop()


def register(root) -> None:
    """Remember a project root of the current test and snapshot its ancestors once."""
    if not _test:
        return
    root = os.path.realpath(os.fspath(root))
    if root not in _test["roots"]:
        _test["roots"][root] = ancestor_snapshot(Path(root))


def begin_test() -> None:
    _test.clear()
    _test.update(mark=mark(), roots={}, started=time.time())
    _config["stale_fds"] = {(fd, fd_path(fd)) for fd in open_dir_fds()}


def end_test() -> list[str]:
    """Problems of the current test: product writes outside its roots, unaudited product
    subprocesses, ancestor changes of its registered projects."""
    if not _test:
        return []
    problems = []
    records = _records_since(_test["mark"])
    node = _node()
    for record in records:
        if record.get("product") and not record["allowed"] and tuple(record["_key"]) not in _consumed:
            problems.append(
                f"product write outside the registered roots: {record['event']} "
                f"{record['resolved']} (pid {record['pid']}, roots {record['allowed_roots']})"
            )
    popens = [r for r in records if r.get("event") == "popen" and r.get("node") == node]
    starts = [r for r in records if r.get("event") == "process-start" and r.get("node") == node]
    if len(starts) < len(popens):
        problems.append(f"unaudited product subprocess(es): {[r['argv'] for r in popens]}")
    cwd_redirect = os.environ.get(ENV_CWD_REDIRECT)
    if cwd_redirect and os.path.isdir(cwd_redirect) and os.listdir(cwd_redirect):
        problems.append(f"files written into the test working folder: {sorted(os.listdir(cwd_redirect))}")
    roots = list(_test["roots"])
    for root, before in _test["roots"].items():
        problems += ancestor_violations(Path(root), before, exclude=roots)
    _test.clear()
    return problems


def orphan_violations() -> list[str]:
    """Violations logged outside any test (collection, session fixtures)."""
    return [
        f"{r['event']} {r['resolved']} (pid {r['pid']})"
        for r in _records_since({})
        if r.get("product") and not r["allowed"] and not r.get("node")
    ]


# ---------------------------------------------------------------- snapshots

CARRIER_FILES = ("AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md")
CARRIER_TREES = (".github/instructions", ".x-ipe/private/secure-code")
CARRIER_GLOBS = (
    (".github/skills", "x-ipe-secure-code-toolkit-*"),
    (".claude/skills", "x-ipe-secure-code-toolkit-*"),
)
SKIP_NAMES = {".venv", ".ruff_cache", ".pytest_cache", "__pycache__", ".DS_Store"}


def _sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return f"unreadable: {exc.strerror}"


def snapshot_tree(root: Path) -> dict[str, str]:
    """Path → SHA-256 for every file below `root` (caches and tool environments skipped)."""
    result: dict[str, str] = {}
    root = Path(root)
    if not root.exists():
        return result
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_NAMES and not d.endswith(".egg-info")]
        for name in files:
            if name in SKIP_NAMES or name.startswith(".coverage"):
                continue
            path = Path(current) / name
            result[str(path)] = "symlink" if path.is_symlink() else _sha(path)
    return result


def protected_violations(before: dict[str, str], after: dict[str, str]) -> list[str]:
    problems = [f"modified: {p}" for p in before if p in after and after[p] != before[p]]
    problems += [f"deleted: {p}" for p in before if p not in after]
    problems += [f"new: {p}" for p in after if p not in before]
    return problems


def carrier_paths(folder: Path) -> dict[str, str]:
    """Carrier-relevant files directly anchored at `folder`."""
    result: dict[str, str] = {}
    for rel in CARRIER_FILES:
        path = folder / rel
        if path.is_file() or path.is_symlink():
            result[str(path)] = _sha(path)
    for rel in CARRIER_TREES:
        result.update(snapshot_tree(folder / rel))
    for rel, pattern in CARRIER_GLOBS:
        base = folder / rel
        if base.is_dir():
            for skill in base.glob(pattern):
                result.update(snapshot_tree(skill))
    return result


def ancestor_snapshot(project: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for folder in Path(os.path.realpath(project)).parents:
        result.update(carrier_paths(folder))
    return result


def ancestor_violations(project: Path, before: dict[str, str], exclude: list | tuple = ()) -> list[str]:
    roots = [os.path.realpath(os.fspath(r)) for r in exclude] + [os.path.realpath(project)]
    after = ancestor_snapshot(project)

    def keep(snapshot):
        return {k: v for k, v in snapshot.items() if not _under(os.path.realpath(k), roots)}

    return [f"ancestor of {project}: {item}" for item in protected_violations(keep(before), keep(after))]


_session: dict[str, str] = {}


def take_session_snapshot(toolkit_root: Path, dev_repo: Path, base: Path) -> dict[str, str]:
    snapshot = snapshot_tree(toolkit_root)
    snapshot.update(carrier_paths(dev_repo))
    for folder in Path(os.path.realpath(base)).parents:
        snapshot.update(carrier_paths(folder))
    _session.clear()
    _session.update(snapshot)
    _config["session_args"] = (toolkit_root, dev_repo, base)
    return dict(snapshot)


def session_snapshot() -> dict[str, str]:
    if not _session:
        raise RuntimeError("the session snapshot was not taken")
    return dict(_session)


def session_violations() -> list[str]:
    if "session_args" not in _config:
        return []
    toolkit_root, dev_repo, base = _config["session_args"]
    now = snapshot_tree(toolkit_root)
    now.update(carrier_paths(dev_repo))
    for folder in Path(os.path.realpath(base)).parents:
        now.update(carrier_paths(folder))
    return protected_violations(_session, now)
