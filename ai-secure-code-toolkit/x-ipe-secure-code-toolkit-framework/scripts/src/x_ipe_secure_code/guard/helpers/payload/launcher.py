"""Trusted PID-1 launcher of a FEATURE-002-F helper container (toolkit payload, never imported).

Runs as PID 1 inside the container under the registered interpreter (`-I -B`). It validates its two
arguments, starts the fixed child for the purpose in its own session, reaps every process re-parented
to it, and kills every process of the PID namespace when the child exits, at the deadline (exit 124) or
on SIGTERM/SIGINT/SIGHUP (exit 143). The kernel ignores SIGKILL/SIGSTOP sent to PID 1 from inside its
namespace, so the helper cannot stop it; it also marks itself non-dumpable (no same-uid ptrace).
Python 3.10+ standard library only; no argument comes from helper content.
"""

import ctypes
import json
import os
import signal
import sys
import time

PURPOSES = ("version", "compile", "sample", "target")
MAX_DEADLINE = 120
VERSION_PROBE = (
    "import json, platform, sys\n"
    "print(json.dumps({'version': list(sys.version_info[:3]), "
    "'implementation': platform.python_implementation().lower(), 'executable': sys.executable}))\n"
)
COMPILE_PROBE = (
    "import json, sys\n"
    "out = {'ok': True, 'version': list(sys.version_info[:3]), 'error': ''}\n"
    "try:\n"
    "    with open('/helper/script.py', 'rb') as f:\n"
    "        compile(f.read(), '/helper/script.py', 'exec', dont_inherit=True)\n"
    "except SyntaxError as exc:\n"
    "    out['ok'] = False\n"
    "    out['error'] = f'{exc.msg} (line {exc.lineno})'[:2000]\n"
    "except Exception as exc:\n"
    "    out['ok'] = False\n"
    "    out['error'] = type(exc).__name__\n"
    "print(json.dumps(out))\n"
)
PR_SET_DUMPABLE = 4
_stop = {"signal": False}


def _non_dumpable():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")


def _kill_all():
    try:
        os.kill(-1, signal.SIGKILL)
    except OSError:
        pass


def _reap():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _on_signal(signum, frame):
    _stop["signal"] = True


def _child_argv(purpose):
    exe = sys.executable
    if purpose == "version":
        return [exe, "-I", "-B", "-c", VERSION_PROBE]
    if purpose == "compile":
        return [exe, "-I", "-B", "-c", COMPILE_PROBE]
    return [exe, "-I", "-B", "/helper/script.py"]


def main(argv):
    if len(argv) != 2 or argv[0] not in PURPOSES or not argv[1].isdigit():
        return 125
    deadline_seconds = int(argv[1])
    if not 1 <= deadline_seconds <= MAX_DEADLINE:
        return 125
    try:
        _non_dumpable()
    except (OSError, AttributeError):
        sys.stderr.write(json.dumps({"launcher": "prctl unavailable"}) + "\n")
        return 125
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    deadline = time.monotonic() + deadline_seconds
    devnull = os.open(os.devnull, os.O_RDONLY)
    child = os.posix_spawn(
        sys.executable,
        _child_argv(argv[0]),
        {k: v for k, v in os.environ.items()},
        file_actions=[(os.POSIX_SPAWN_DUP2, devnull, 0)],
        setsid=True,
    )
    os.close(devnull)
    status = None
    while status is None:
        if _stop["signal"]:
            _kill_all()
            _reap()
            return 143
        if time.monotonic() >= deadline:
            _kill_all()
            _reap()
            sys.stderr.write("launcher: time limit (L-10)\n")
            return 124
        try:
            pid, code = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            pid, code = 0, 0
        if pid == child:
            status = code
        elif pid == 0:
            time.sleep(0.05)
    _kill_all()
    _reap()
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return os.WEXITSTATUS(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
