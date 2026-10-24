"""Shared FEATURE-002-F test helpers: verification fixtures with helper methods, request builders, the
fake container runtime wiring and seeded (library-MAC) registration/conformance records.

New 002-F modules are imported at Act (`mod`) so tests fail for the right reason before they exist.
"""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import copy
import importlib
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))

from conftest import FakeInteraction  # noqa: E402
from test_guard import (  # noqa: E402,F401
    GUARD,
    R1,
    R2,
    REPORTS,
    digest_of,
    env,  # noqa: E402,F401 - fixture reuse (test modules import env and henv)
    opened,
    req,
)

from x_ipe_secure_code.guard import control  # noqa: E402
from x_ipe_secure_code.guard import service as guard  # noqa: E402

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_runtime.py"
METHOD = "helper.yaml-debug"
RULE = R1
IMAGE_ID = "sha256:" + "3f" * 32
IMAGE_ENV = [
    "PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C.UTF-8",
    "PYTHON_VERSION=3.12.4",
]
GAP = {
    "considered": ["semantic-review", "opengrep"],
    "why_insufficient": "reading cannot enumerate every deployed YAML key; no Adapter rule covers it",
    "gap": "debug flags in deployed YAML configuration",
}
SCRIPT = (
    "import json\n"
    "import re\n"
    "from pathlib import Path\n"
    "findings = []\n"
    "scanned = []\n"
    "for p in sorted(Path('/input').rglob('*.yaml')):\n"
    "    rel = str(p.relative_to('/input'))\n"
    "    scanned.append(rel)\n"
    "    for n, line in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1):\n"
    "        if re.search(r'debug:\\s*true', line):\n"
    "            findings.append({'path': rel, 'line': n, 'rule': RULE, 'title': 'debug enabled',\n"
    "                             'excerpt': line[:200], 'basis': 'key debug is true'})\n"
    "doc = {'schema': 'x-ipe-helper-result/1', 'helper': HELPER, 'status': 'complete',\n"
    "       'scanned': scanned, 'findings': findings, 'notes': ''}\n"
    "with open('/results/result.json', 'w', encoding='utf-8') as out:\n"
    "    json.dump(doc, out)\n"
)


def mod(name: str) -> Any:
    return importlib.import_module("x_ipe_secure_code.guard.helpers." + name)


def state_of(env: dict, vid: str) -> dict:
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


def write_state(env: dict, vid: str, state: dict) -> None:
    (env["project"] / GUARD / vid / "state.json").write_text(json.dumps(state))


@pytest.fixture
def henv(env):  # noqa: F811
    """The 002-A Guard env plus YAML configuration files under src/config."""
    project = env["project"]
    (project / "src" / "config").mkdir()
    (project / "src" / "config" / "app.yaml").write_text("name: app\ndebug: false\nport: 80\n")
    (project / "src" / "config" / "db.yaml").write_text("host: db\n")
    (project / "tmp-in").mkdir()
    return env


def helper_check(**over: Any) -> dict:
    check = {
        "id": "C1",
        "rule": RULE,
        "object": ["src/config"],
        "methods": [{"name": METHOD, "kind": "runtime", "required": False}],
        "minimum_evidence": ["runtime"],
        "method_choice": {
            "considered": ["semantic-review", "opengrep", METHOD],
            "selected": [METHOD],
            "reason": "only a script can enumerate the keys",
            "gap": copy.deepcopy(GAP),
        },
    }
    check.update(over)
    return check


def plan_doc(*checks: dict, **over: Any) -> dict:
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": list(checks) or [helper_check()],
        "not_applicable": [{"rule": R2, "reason": "no database access in the target"}],
    }
    doc.update(over)
    return doc


def open_src(env: dict, **over: Any) -> str:
    doc = {"targets": [{"path": "src", "change": "modified"}], "context": [{"path": "README.md"}]}
    doc.update(over)
    return opened(env, **doc)


def plan(env: dict, vid: str, *checks: dict, **over: Any):
    return guard.record_plan(str(env["project"]), vid, req(env, plan_doc(*checks, **over)))


def helper_run(env: dict, *checks: dict, **open_over: Any) -> str:
    vid = open_src(env, **open_over)
    out = plan(env, vid, *checks)
    assert out.ok, out.to_text()
    return vid


def attempt(env: dict, vid: str, kind: str, covers: dict):
    doc = {"schema": "ai-secure-code-toolkit/guard-attempt/v1", "kind": kind, "covers": covers}
    out = control.attempt(str(env["project"]), vid, req(env, doc))
    if not out.ok and out.problems[0].code == "ATTEMPTS_EXHAUSTED":
        extend(env, vid, 10)
        out = control.attempt(str(env["project"]), vid, req(env, doc))
    return out


def extend(env: dict, vid: str, attempts: int = 10, minutes: int = 0):
    out = control.extend(
        str(env["project"]), vid, minutes, attempts, "test", interaction=FakeInteraction(answers=[vid])
    )
    assert out.ok, out.to_text()
    return out


def pair(check: str = "C1", method: str = METHOD) -> dict:
    return {"pairs": [{"check": check, "method": method}]}


def raw_record(env: dict, vid: str, **parts: Any):
    doc = {"schema": "ai-secure-code-toolkit/guard-record/v1", **parts}
    return guard.record(str(env["project"]), vid, req(env, doc))


def unix_socket(folder: Path, name: str = "d.sock") -> Path:
    """A real unix socket file (relative bind keeps the path short on macOS)."""
    here = os.getcwd()
    os.chdir(folder)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(name)
        sock.close()
    finally:
        os.chdir(here)
    return folder / name


# --------------------------------------------------------------------------- fake runtime wiring
def default_control(host: str) -> dict:
    image = {
        "Id": IMAGE_ID,
        "RepoDigests": ["python@sha256:" + "4e" * 32],
        "Config": {"Env": list(IMAGE_ENV), "Entrypoint": None, "User": "", "Labels": {}, "Volumes": None},
    }
    return {
        "host": host,
        "images": {IMAGE_ID: image, "python:3.12-slim": image},
        "version": {"Client": {"Version": "27.3.1"}, "Server": {"Version": "27.3.1", "ApiVersion": "1.47"}},
        "info": {
            "ID": "fake-daemon",
            "OSType": "linux",
            "Architecture": "aarch64",
            "CgroupVersion": "2",
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
        },
        "auto": {"helper": "", "rule": RULE, "pattern": "debug: true"},
    }


class Fake:
    """The installed fake runtime of one test (control file, command log, object state)."""

    def __init__(self, folder: Path) -> None:
        self.dir = folder

    @property
    def control(self) -> dict:
        return json.loads((self.dir / "control.json").read_text())

    def set(self, **updates: Any) -> None:
        ctl = self.control
        ctl.update(updates)
        (self.dir / "control.json").write_text(json.dumps(ctl))

    def log(self) -> list[list[str]]:
        path = self.dir / "log.jsonl"
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        return [r[2:] if r[:1] == ["-H"] else r for r in rows]

    def clear_log(self) -> None:
        (self.dir / "log.jsonl").unlink(missing_ok=True)

    def state(self) -> dict:
        path = self.dir / "state.json"
        return json.loads(path.read_text()) if path.exists() else {"containers": {}, "volumes": {}}

    def subcommands(self) -> list[str]:
        return [" ".join(r[:2]) if r[0] in ("volume", "image", "context") else r[0] for r in self.log()]

    def creates(self, purpose: str | None = None) -> list[list[str]]:
        rows = [r for r in self.log() if r[0] == "create"]
        return [r for r in rows if purpose is None or f"x-ipe.secure-code.purpose={purpose}" in r]


def audited_child_header() -> str:
    """The toolkit gives runtime CLIs a sanitized environment, so the fake joins the FEATURE-003-B write
    audit itself (embedded settings) like every other child Python process of the suite."""
    keys = (
        "SECURE_CODE_TEST_WRITE_AUDIT",
        "SECURE_CODE_TEST_WRITE_EXCEPTIONS",
        "SECURE_CODE_TEST_TMP_PATH",
        "SECURE_CODE_TEST_TMP_REDIRECT",
        "PYTEST_CURRENT_TEST",
    )
    settings = {k: os.environ[k] for k in keys if k in os.environ}
    support = str(HERE.parent / "support")
    return (
        f"import os as _o, sys as _s\n_s.dont_write_bytecode = True\n_A = {settings!r}\n"
        "if _A.get('SECURE_CODE_TEST_WRITE_AUDIT'):\n"
        f"    _o.environ.update(_A)\n    _s.path.append({support!r})\n"
        "    import write_audit as _w\n    _w.install_child()\n    _s.path.remove(_s.path[-1])\n"
    )


@pytest.fixture
def fake(tmp_path, monkeypatch):
    folder = tmp_path / "fakert"
    folder.mkdir()
    sock = unix_socket(folder)
    (folder / "control.json").write_text(json.dumps(default_control(f"unix://{sock}")))
    source = (
        FAKE.read_text(encoding="utf-8")
        .replace(
            'CONTROL = Path(os.environ.get("FAKE_RUNTIME_CONTROL_PATH", "control.json"))'
            "  # replaced when installed",
            f"CONTROL = Path({str(folder / 'control.json')!r})",
        )
        .replace("from __future__ import annotations\n", "")
    )
    exe = folder / "docker"
    exe.write_text(f"#!{sys.executable}\n" + audited_child_header() + source, encoding="utf-8")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.defpath}")
    return Fake(folder)


@pytest.fixture
def no_runtime(tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    return empty


RENDERED_FAKE = {
    "SecurityOpt": ["no-new-privileges"],
    "IpcMode": "none",
    "CgroupnsMode": "private",
    "UsernsMode": "",
    "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
    "RestartPolicy": "no",
    "AppArmorProfile": "",
}


def seed_registry(env: dict, *, conformance: bool = True, image_env: list[str] | None = None) -> dict:
    """Registration + passing conformance written through the library MAC (test seam; AC-002F-11f)."""
    from x_ipe_secure_code import __version__

    registry, runtime = mod("registry"), mod("runtime")
    root = env["project"]
    rt = runtime.CliRuntime.discover()
    identity = rt.identity()
    image = registry.write_image(
        root,
        {
            "image": IMAGE_ID,
            "repo_digests": ["python@sha256:" + "4e" * 32],
            "cpython": "3.12.4",
            "interpreter": "/usr/local/bin/python3",
            "env": list(image_env or IMAGE_ENV),
            "config": {"user": "", "entrypoint": None, "volumes": None, "labels": {}},
            "registered_at": "2026-10-24T00:00:00Z",
            "registered_by": {"role": "maintainer"},
            "toolkit_version": __version__,
            "runtime": {"kind": identity["kind"], "server_version": identity["server_version"]},
        },
    )
    record = None
    if conformance:
        record = registry.write_conformance(
            root,
            {
                "id": registry.conformance_id(identity, IMAGE_ID),
                "identity": identity,
                "image": IMAGE_ID,
                "toolkit_version": __version__,
                "ran_at": "2026-10-24T00:00:00Z",
                "seccomp": {"runtime_profile": "builtin", "denied_syscalls_proven": [], "filters": 1},
                "rendered": dict(RENDERED_FAKE),
                "probes": [{"id": "P-00", "name": "seeded by the test seam", "pass": True, "detail": "seed"}],
                "passed": True,
            },
        )
    return {"image": image, "conformance": record, "identity": identity}


# --------------------------------------------------------------------------- flow driver
TMP = ".x-ipe/private/secure-code/tmp"
POSITIVE = "name: app\ndebug: true\n"
NEGATIVE = "name: app\ndebug: false\n"


def script_for(helper_id: str, rule: str = RULE) -> str:
    return f"RULE = {rule!r}\nHELPER = {helper_id!r}\n" + SCRIPT


class Flow:
    """Drive submit → review → grant → helper attempt → run through the service functions."""

    def __init__(self, env: dict, fake: Fake | None = None) -> None:
        self.env, self.fake = env, fake
        self.root = env["project"]
        (self.root / TMP).mkdir(parents=True, exist_ok=True)

    def file(self, name: str, text: str | bytes) -> str:
        path = self.root / TMP / name
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return f"{TMP}/{name}"

    def predicted(self, vid: str) -> str:
        n = len(state_of(self.env, vid).get("helpers") or []) + 1
        return f"h-{n}-{vid[-8:]}"

    def request(self, vid: str, attempt: str | None, **over: Any) -> dict:
        hid = self.predicted(vid)
        doc = {
            "schema": "ai-secure-code-toolkit/guard-helper/v1",
            "attempt": attempt,
            "check": "C1",
            "method": METHOD,
            "goal": "Detect debug: true in deployed YAML config",
            "read_scope": ["src/config"],
            "judgement_basis": {
                "finding": "a key debug with value true",
                "no_finding": "no such key, or false",
            },
            "language": "python",
            "script_file": self.file(f"{hid}.py", script_for(hid)),
            "samples": [
                {
                    "kind": "positive",
                    "origin": {"type": "synthetic"},
                    "path": "src/config/app.yaml",
                    "content_file": self.file(f"{hid}-pos.yaml", POSITIVE),
                },
                {
                    "kind": "negative",
                    "origin": {"type": "synthetic"},
                    "path": "src/config/app.yaml",
                    "content_file": self.file(f"{hid}-neg.yaml", NEGATIVE),
                },
            ],
        }
        if attempt is None:
            del doc["attempt"]
        doc.update(over)
        return doc

    def generation(self, vid: str, method: str = METHOD) -> str:
        out = attempt(self.env, vid, "generation", pair("C1", method))
        assert out.ok, out.to_text()
        return out.data["attempt"]

    def submit(self, vid: str, doc: dict | None = None, **over: Any):
        doc = doc or self.request(vid, self.generation(vid), **over)
        if self.fake is not None:
            self.fake.set(auto={**self.fake.control.get("auto", {}), "helper": self.predicted(vid)})
        return mod("submit").submit(str(self.root), vid, req(self.env, doc))

    def helper(self, vid: str, hid: str) -> dict:
        return next(h for h in state_of(self.env, vid)["helpers"] if h["id"] == hid)

    def review(
        self,
        vid: str,
        hid: str,
        result: str = "accepted",
        phase: str = "pre_execution",
        run: int | None = None,
        paths=("src",),
        **over: Any,
    ):
        a = attempt(self.env, vid, "reviewer", {"helpers": [hid]})
        assert a.ok, a.to_text()
        h = self.helper(vid, hid)
        subject = {
            "type": "helper",
            "id": hid,
            "phase": phase,
            "result": result,
            "helper_digest": h["helper_digest"],
            "basis": "goal, scope and samples fit the check",
        }
        if phase == "post_run":
            subject.update(
                run=run, result_sha256=next(r for r in h["runs"] if r["n"] == run)["target"]["result_sha256"]
            )
        subject.update(over.pop("subject", {}))
        doc = {
            "schema": "ai-secure-code-toolkit/reviewer-record/v1",
            "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
            "requirement": "Review each helper against its bound check",
            "reviewed_targets": [{"path": p, "digest": target_digest(self.env, vid, p)} for p in paths],
            "subjects": [subject],
            "attempt": a.data["attempt"],
            **over,
        }
        return guard.record_review(str(self.root), vid, req(self.env, doc))

    def grant(self, vid: str, typed: str | None = None, interactive: bool = True, helpers=None):
        interaction = FakeInteraction(interactive=interactive, answers=[typed if typed is not None else vid])
        out = mod("grant").grant(str(self.root), vid, helpers, interaction=interaction)
        self.prompts = interaction.prompts
        return out

    def helper_attempt(self, vid: str, method: str = METHOD) -> str:
        out = attempt(self.env, vid, "helper", pair("C1", method))
        assert out.ok, out.to_text()
        return out.data["attempt"]

    def run(self, vid: str, hid: str, attempt_id: str | None = None):
        return mod("execute").run(str(self.root), vid, hid, attempt_id)

    def ready(self, vid: str | None = None, **open_over: Any) -> tuple[str, str]:
        """Open, plan, submit (checked), review (accepted) and grant; returns (vid, helper id)."""
        vid = vid or helper_run(self.env, **open_over)
        out = self.submit(vid)
        assert out.ok, out.to_text()
        hid = out.data["helper"]
        reviewed = self.review(vid, hid)
        assert reviewed.ok, reviewed.to_text()
        granted = self.grant(vid)
        assert granted.ok, granted.to_text()
        return vid, hid

    def executed(self, **open_over: Any) -> tuple[str, str, Any]:
        vid, hid = self.ready(**open_over)
        out = self.run(vid, hid, self.helper_attempt(vid))
        return vid, hid, out


def target_digest(env: dict, vid: str, path: str) -> str:
    targets = state_of(env, vid)["artifact"]["targets"]
    return next(t["digest"] for t in targets if t["path"] == path)


@pytest.fixture
def flow(henv, fake):  # noqa: F811
    seed_registry(henv)
    return Flow(henv, fake)
