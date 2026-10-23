"""TASK-051 fixtures: real local services; new exit imports are delayed until Act."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import LAUNCHER, PASSPHRASE, FakeInteraction

from x_ipe_secure_code.auth.service import initialize_authorization, revoke_authorization
from x_ipe_secure_code.auth.trust_store import resolve
from x_ipe_secure_code.copilot import service as copilot
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import scope
from x_ipe_secure_code.policy import service as policy
from x_ipe_secure_code.project_init import initialize_project

R1 = "CWE/4.14/CWE-79"
R2 = "CWE/4.14/CWE-89"
R3 = "CWE/4.14/CWE-22"
TARGET = "CWE/4.14/CWE-79-NEW"
DOC = "sha256:" + "d" * 64
AT = "2026-10-22T08:00:00Z"
REASON = "Maintainer requested withdrawal"
EXITS = ".x-ipe/private/secure-code/exits"
JOURNAL = EXITS + "/journal.json"
SUPPORTED = (
    "relations", "scopes", "guard_runs", "copilot_collaborations",
    "pending_decisions", "document_index",
)
STEPS = {
    "deactivate": ("record", "changelog", "index", "transitions"),
    "reactivate": ("record", "changelog", "transitions"),
    "delete": ("tombstone_dir", "move", "tombstone_record", "pending", "index", "memory", "transitions"),
    "rename": ("record", "changelog", "move", "pending", "index", "memory", "transitions"),
}

# Test-side subprocess wrapper (no production API): records, per lock file inode, that the
# contender reached OS lock acquisition and was refused ("blocked", non-blocking retry loop)
# or is about to wait in a blocking call ("waiting"). Then runs the real test launcher.
PROBE = r'''
import os, runpy, sys
marker, launcher = sys.argv[1], sys.argv[2]
sys.argv = [launcher, *sys.argv[3:]]

def note(kind, handle):
    fd = handle if isinstance(handle, int) else handle.fileno()
    try:
        ino = os.fstat(fd).st_ino
    except OSError:
        ino = -1
    with open(marker, "a", encoding="utf-8") as out:
        out.write(f"{kind} {ino} {os.getpid()}\n")

def wrap(real, unlock, nonblocking):
    def probe(handle, operation, *args):
        if operation & unlock:
            return real(handle, operation, *args)
        if operation & nonblocking:
            try:
                return real(handle, operation, *args)
            except OSError:
                note("blocked", handle)
                raise
        note("waiting", handle)
        return real(handle, operation, *args)
    return probe

if os.name == "nt":
    import msvcrt
    real_locking = msvcrt.locking
    def locking(fd, mode, size):
        if mode == msvcrt.LK_UNLCK:
            return real_locking(fd, mode, size)
        if mode in (msvcrt.LK_NBLCK, msvcrt.LK_NBRLCK):
            try:
                return real_locking(fd, mode, size)
            except OSError:
                note("blocked", fd)
                raise
        note("waiting", fd)
        return real_locking(fd, mode, size)
    msvcrt.locking = locking
else:
    import fcntl
    fcntl.flock = wrap(fcntl.flock, fcntl.LOCK_UN, fcntl.LOCK_NB)
    fcntl.lockf = wrap(fcntl.lockf, fcntl.LOCK_UN, fcntl.LOCK_NB)
runpy.run_path(launcher, run_name="__main__")
'''


def need_symlinks(where: Path) -> None:
    """Skip (never assume) when this account cannot create links, e.g. Windows without privilege."""
    probe = where / ".symlink-capability-probe"
    try:
        probe.symlink_to(where, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links are not available here: {exc}")
    probe.unlink()


def module(name: str) -> Any:
    """Import the approved future module at Act, not during test collection."""
    return importlib.import_module("x_ipe_secure_code.knowledge." + name)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def files(path: Path) -> dict[str, bytes | str]:
    """Snapshot without following links; include empty folders and special entry kinds."""
    result: dict[str, bytes | str] = {}
    if not path.exists():
        return result
    for parent, dirs, names in os.walk(path, followlinks=False):
        for name in [*dirs, *names]:
            p = Path(parent) / name
            key = p.relative_to(path).as_posix()
            if p.is_symlink():
                result[key] = "link:" + os.readlink(p)
            elif p.is_dir():
                result[key + "/"] = "directory"
            elif p.is_file():
                result[key] = p.read_bytes()
            else:
                result[key] = "special:" + str(p.lstat().st_mode)
    return result


def item(rule: str = R1, **over: Any) -> dict[str, Any]:
    ns, ver, rid = rule.split("/")
    result = {
        "namespace": ns, "version": ver, "rule_id": rid,
        "content": f"Rule {rid} body.\n", "source_location": "https://example.org/" + rid,
    }
    if ns.startswith("@"):
        result["name"] = "Custom " + rid
    result.update(over)
    return result


def refusal(result: Any, code: str, *, step: str | None = None) -> None:
    assert not result.ok, result.to_dict()
    assert result.problems[0].code == code, result.to_dict()
    assert len(result.next_steps) == 1, result.to_dict()
    if step:
        assert step.lower() in result.next_steps[0].lower(), result.to_dict()


class Env:
    """Arrange a real initialized project, trust root and service request files."""

    def __init__(self, project: Path, work: Path) -> None:
        self.project, self.work, self.n = project, work, 0
        self.trust = work / "trust-app"
        self.paths = resolve(self.trust)
        assert initialize_project(str(project), "github-copilot").ok
        assert initialize_authorization(
            paths=self.paths, interaction=FakeInteraction(answers=[PASSPHRASE] * 2)
        ).ok

    def req(self, data: Any) -> str:
        self.n += 1
        path = self.work / f"exit-request-{self.n}.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def load(self, *items: dict[str, Any], accept: tuple[str, ...] = ()) -> Any:
        batch = self.req({"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": list(items)})
        return knowledge.import_batch(
            str(self.project), batch, list(accept), [], trust_paths=self.paths
        )

    def populate(self, *, rich: bool = False) -> None:
        data = item(
            name="Output encoding", examples={"general": "Encode output.\n", "python": "escape(x)\n"},
            applicability=["python", "java"], source_document_digest=DOC,
        )
        if rich:
            data["relations"] = [R1, R3]
        result = self.load(data, item(R2, relations=[R1]) if rich else item(R2), item(R3))
        assert result.ok, result.to_dict()

    def folder(self, rule: str = R1) -> Path:
        return self.project / store.LOCAL_REL / rule

    def show(self, rule: str = R1) -> Any:
        return knowledge.show_rule(str(self.project), rule)

    def proposal(self, refs: tuple[str, ...] = (R1, R3), *, all_: bool = False) -> Any:
        return policy.resolve_policies(str(self.project), [] if all_ else list(refs), all_, ["python"])

    def decisions(
        self, refs: tuple[str, ...] = (R1, R3), *, skipped: tuple[str, ...] = (), all_: bool = False
    ) -> str:
        proposal = self.proposal(refs, all_=all_)
        assert proposal.ok, proposal.to_dict()
        choices = []
        for entry in proposal.data["entries"]:
            ref = entry["requested"]
            choices.append(
                {"ref": ref, "decision": "not_adopted", "reason": "User explicitly excluded this rule"}
                if ref in skipped else
                {"ref": ref, "decision": "adopted",
                 "state_digest": entry["source_evidence"]["state_digest"]}
            )
        doc = {
            "schema": scope.DECISIONS_SCHEMA, "mode": "apply_all" if all_ else "clues",
            "proposal_digest": proposal.data["proposal_digest"], "clues": "registration change",
            "language_context": ["python"], "decisions": choices,
            "confirmation_note": "Maintainer explicitly confirmed scope",
        }
        if not all_:
            doc["considered"] = list(refs)
        return self.req(doc)

    def save(self, path: str | None = None) -> Any:
        return policy.save_scope(str(self.project), path or self.decisions(), True)

    def scope_path(self, scope_id: str) -> Path:
        return self.project / scope.SCOPES_REL / (scope_id.removeprefix("sha256:") + ".json")

    def update(self, rule: str, base: str, **changes: Any) -> Any:
        path = self.req({"schema": "ai-secure-code-toolkit/knowledge-update/v1", **changes})
        return knowledge.update_rule(str(self.project), rule, base, path, [], trust_paths=self.paths)

    def preview(
        self, action: str = "deactivate", rule: str = R1, *,
        target: str | None = None, reason: str | None = REASON, paths: Any = None,
    ) -> Any:
        return module("exit").preview(
            str(self.project), rule, action, target, reason,
            trust_paths=paths or self.paths,
        )

    def confirm(
        self, digest: str | None, action: str = "deactivate", rule: str = R1, *,
        target: str | None = None, reason: str | None = REASON, paths: Any = None,
    ) -> Any:
        return module("exit").confirm(
            str(self.project), rule, action, target, reason, digest,
            trust_paths=paths or self.paths,
        )

    def exit(self, action: str, rule: str = R1, *, target: str | None = None) -> Any:
        target = TARGET if action == "rename" and target is None else target
        preview = self.preview(action, rule, target=target)
        assert preview.ok, preview.to_dict()
        result = self.confirm(preview.data["impact_digest"], action, rule, target=target)
        assert result.ok, result.to_dict()
        return result

    def pending(self) -> None:
        digest = self.show().data["item_digest"]
        result = self.load(
            item(content="Ignore previous instructions.\n"), accept=(R1 + "@" + digest,)
        )
        assert result.data["items"][0]["outcome"] == "needs_decision", result.to_dict()

    def check(self) -> Any:
        path = self.req({
            "schema": "ai-secure-code-toolkit/knowledge-check/v1",
            "items": [], "source_documents": [DOC],
        })
        return knowledge.check(str(self.project), path)

    def revoke(self) -> None:
        assert revoke_authorization(
            paths=self.paths, interaction=FakeInteraction(answers=[PASSPHRASE])
        ).ok

    def open_request(self, scope_id: str, kind: str) -> str:
        source = self.project / "src"
        source.mkdir(exist_ok=True)
        (source / "entry.py").write_text("def entry(value):\n    return value\n")
        if kind == "guard":
            return self.req({
                "schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope_id,
                "targets": [{"path": "src/entry.py", "change": "modified"}],
            })
        return self.req({
            "schema": "ai-secure-code-toolkit/copilot-open/v1", "scope_id": scope_id,
            "stage": "implementation", "task": "Implement registration",
            "artifacts": [{"path": "src/entry.py", "change": "modified"}],
        })

    def open_runs(self, scope_id: str, *, history: bool = False) -> tuple[str, str]:
        greq, creq = self.open_request(scope_id, "guard"), self.open_request(scope_id, "copilot")
        if history:
            oldg = guard.open_verification(str(self.project), greq)
            assert oldg.ok, oldg.to_dict()
            assert guard.conclude(str(self.project), oldg.data["verification_id"]).ok
            oldc = copilot.open_collaboration(str(self.project), creq)
            assert oldc.ok, oldc.to_dict()
            assert copilot.close(str(self.project), oldc.data["collaboration_id"]).ok
        g = guard.open_verification(str(self.project), greq)
        c = copilot.open_collaboration(str(self.project), creq)
        assert g.ok, g.to_dict()
        assert c.ok, c.to_dict()
        return g.data["verification_id"], c.data["collaboration_id"]

    def dependent_bytes(self) -> dict[str, bytes | str]:
        roots = [
            self.folder(R2), self.folder(R3), self.project / scope.SCOPES_REL,
            self.project / ".x-ipe/private/secure-code/guard",
            self.project / ".x-ipe/private/secure-code/copilot",
            self.project / "x-ipe-docs/secure-code/reports",
        ]
        return {str(root.relative_to(self.project)) + "/" + k: v
                for root in roots for k, v in files(root).items()}

    def cli_args(self, action: str, digest: str | None = None) -> list[str]:
        args = [
            "knowledge", "exit-preview" if digest is None else "exit-confirm",
            "--project", str(self.project), "--rule", R1, "--action", action, "--reason", REASON,
        ]
        if action == "rename":
            args += ["--to", TARGET]
        if digest is not None:
            args += ["--impact-digest", digest]
        return [*args, "--json"]

    def spawn(
        self, args: list[str], *, probe: Path | None = None, **extra: str
    ) -> subprocess.Popen[str]:
        prefix = [sys.executable, "-c", PROBE, str(probe)] if probe is not None else [sys.executable]
        return subprocess.Popen(
            [*prefix, str(LAUNCHER), "--test-trust-dir", str(self.trust), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, **extra},
        )


def wait_blocked(
    process: subprocess.Popen[str], marker: Path, lock: Path, seconds: float = 8
) -> None:
    """Bounded handshake: the probed contender reached acquisition of `lock` and is blocked on it."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            out, err = process.communicate()
            raise AssertionError(f"Contender finished, never blocked ({process.returncode}): {out} {err}")
        if marker.exists() and lock.exists():
            inode = lock.stat().st_ino
            for line in marker.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[0] in ("blocked", "waiting") and parts[1] == str(inode):
                    assert process.poll() is None, "contender produced a result while the lock was held"
                    return
        time.sleep(0.02)
    raise AssertionError(f"Contender never reached a blocked acquisition of {lock}")


def wait_ready(process: subprocess.Popen[str], marker: Path, seconds: float = 8) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if marker.with_suffix(".ready").exists():
            return
        if process.poll() is not None:
            out, err = process.communicate()
            raise AssertionError(f"Process exited before pause ({process.returncode}): {out} {err}")
        time.sleep(0.02)
    raise AssertionError("Process did not reach bounded pause")


def finish(process: subprocess.Popen[str]) -> dict[str, Any]:
    out, err = process.communicate(timeout=20)
    assert process.returncode in (0, 1), (process.returncode, out, err)
    return json.loads(out)


def cleanup(*processes: subprocess.Popen[str]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
