from __future__ import annotations

import hashlib
import os
import select
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
SRC = SCRIPTS / "src"
LAUNCHER = SCRIPTS / "tests" / "support" / "launcher.py"
TOOLKIT_ROOT = SCRIPTS.parents[1]  # ai-secure-code-toolkit/
sys.path.insert(0, str(SRC))
sys.path.insert(1, str(SCRIPTS / "tests" / "support"))
import write_audit  # noqa: E402 - test-only harness next to the launcher

PASSPHRASE = "correct horse battery"
CANARY = "sk-canary-0123456789abcdef"


@dataclass
class FakeInteraction:
    interactive: bool = True
    answers: list[str | None] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)

    def is_interactive(self) -> bool:
        return self.interactive

    def prompt_secret(self, prompt: str) -> str | None:
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else None

    def prompt_text(self, prompt: str) -> str | None:
        return self.prompt_secret(prompt)


@pytest.fixture
def trust_paths(tmp_path):
    from x_ipe_secure_code.auth.trust_store import resolve

    return resolve(tmp_path / "config" / "ai-secure-code-toolkit")


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "my project ü"
    root.mkdir()
    return root


def tree_hashes(*roots: Path) -> dict[str, str]:
    result = {}
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
            elif path.is_dir():
                result[str(path) + "/"] = "dir"
    return result


def _cli_roots(args, trust_dir: Path) -> list[Path]:
    """Write roots registered for one CLI invocation (FEATURE-003-B write audit, AC-003B-07c)."""
    args = [str(a) for a in args]
    roots = [Path(trust_dir)]
    for flag, parent in (("--project", False), ("--output", True)):
        if flag in args[:-1]:
            value = Path(args[args.index(flag) + 1])
            roots.append(value.parent if parent else value)
    if "--project" in args[:-1]:
        write_audit.register(roots[1])
    return roots


def run_cli(args, trust_dir: Path, *, extra=(), env_extra=None, input_text=None, cwd=None):
    env = dict(os.environ)
    env.update(write_audit.child_env(_cli_roots(args, trust_dir)))
    env.update(env_extra or {})
    cmd = [sys.executable, str(LAUNCHER), "--test-trust-dir", str(trust_dir), *extra, *args]
    return subprocess.run(
        cmd, capture_output=True, text=True, input=input_text, env=env, cwd=cwd, timeout=120
    )


def run_cli_pty(args, trust_dir: Path, answers: list[str], *, env_extra=None, timeout=60):
    """Run the CLI with a pseudo-terminal as controlling terminal (POSIX only)."""
    import pty

    env = dict(os.environ)
    env.update(env_extra or {})
    cmd = [sys.executable, str(LAUNCHER), "--test-trust-dir", str(trust_dir), *args]
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execvpe(cmd[0], cmd, env)
    output = b""
    sent = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        if sent < len(answers) and output.lower().count(b"passphrase") > sent:
            os.write(fd, answers[sent].encode() + b"\n")
            sent += 1
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


posix_only = pytest.mark.skipif(os.name == "nt", reason="pseudo-terminal tests need POSIX pty")


# FEATURE-002-D: the real-binary Trivy acceptance gate (tests/guard/test_trivy_real.py) never runs by default.
def pytest_addoption(parser):
    parser.addini("write_audit_exceptions", type="linelist", default=[],
                  help="FEATURE-003-B write audit: the only paths outside test-registered roots "
                       "that may be written")
    parser.addoption(
        "--require-real-trivy",
        action="store_true",
        default=False,
        help="run the mandatory real-binary Trivy acceptance gate (marker trivy_real); "
        "missing prerequisites fail",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "trivy_real: real Trivy v0.76.1 acceptance gate (opt-in, never default)"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--require-real-trivy"):
        return
    kept = [item for item in items if item.get_closest_marker("trivy_real") is None]
    deselected = [item for item in items if item.get_closest_marker("trivy_real") is not None]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept


# FEATURE-003-B (AC-003B-07a…07e, NFR-003B-7): suite-wide write audit and protected-tree snapshots.
def _uv_cache() -> str:
    if os.environ.get("UV_CACHE_DIR"):
        return os.path.realpath(os.environ["UV_CACHE_DIR"])
    mac = Path.home() / "Library" / "Caches" / "uv"
    return str(mac if sys.platform == "darwin" else Path.home() / ".cache" / "uv")


def pytest_sessionstart(session):
    config = session.config
    base = Path(config._tmp_path_factory.getbasetemp()).resolve()
    rootdir = str(Path(str(config.rootpath)).resolve())
    exceptions = [item.replace("{rootdir}", rootdir).replace("{uv_cache}", _uv_cache())
                  for item in config.getini("write_audit_exceptions")]
    write_audit.install_session(base / "write-audit", exceptions)
    write_audit.take_session_snapshot(TOOLKIT_ROOT, TOOLKIT_ROOT.parent, base)


def pytest_sessionfinish(session, exitstatus):
    problems = (write_audit.orphan_violations() + write_audit.session_violations()
                + write_audit.internal_error_problems())
    if problems:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "write audit: protected trees or out-of-root product writes", red=True)
            for item in problems:
                reporter.write_line(item)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(autouse=True)
def _write_audit_guard(tmp_path, tmp_path_factory):
    """Per test: temp/cwd redirection, then fail on out-of-root product writes or ancestor changes."""
    aux = tmp_path_factory.mktemp("redirect")
    (aux / "tmp").mkdir()
    (aux / "cwd").mkdir()
    patch = pytest.MonkeyPatch()
    patch.setenv("TMPDIR", str(aux / "tmp"))
    patch.setattr(tempfile, "tempdir", str(aux / "tmp"))
    patch.setenv(write_audit.ENV_TMP_PATH, str(tmp_path.resolve()))
    patch.setenv(write_audit.ENV_TMP_REDIRECT, str((aux / "tmp").resolve()))
    patch.setenv(write_audit.ENV_CWD_REDIRECT, str((aux / "cwd").resolve()))
    patch.chdir(aux / "cwd")
    write_audit.begin_test()
    try:
        yield
    finally:
        problems = write_audit.end_test()
        patch.undo()
    if problems:
        pytest.fail("write audit:\n" + "\n".join(problems), pytrace=False)
