"""FEATURE-001-G test helpers: disposable projects, fixture batches, draft/review files, CLI runners.

Fixture-only acceptance (DAO-008 (3)): no live model output, no real fetch and no real internal
content; the internal-gate rule is the synthetic `@SYNTH/T-1.0/R-01`. Seed identities come from
fixture batches authored under `fixtures/` (never from a project folder outside `tests/`).
Drafting modules are imported at Act, so tests fail for the right reason before they exist.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import re
import select
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import LAUNCHER, SRC, tree_hashes
from knowledge.exithelp import REASON, Env

from x_ipe_secure_code import cli
from x_ipe_secure_code.auth import trust_store
from x_ipe_secure_code.knowledge import store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SRC_HINT = str(SRC)
DRAFTS = "x-ipe-docs/secure-code/drafts"
STAGING = ".x-ipe/private/secure-code/drafting-staging"
AUTH_FILE = ".x-ipe/private/secure-code/drafting-authorizations.json"
DRAFT_SCHEMA = "ai-secure-code-toolkit/knowledge-draft/v1"
REVIEW_SCHEMA = "ai-secure-code-toolkit/knowledge-draft-review/v1"
R89 = "CWE/Top25-2025/CWE-89"
R78 = "CWE/Top25-2025/CWE-78"
A03 = "OWASP/Top10-2025/A03"
SYNTH = "@SYNTH/T-1.0/R-01"
HOST = "fixture-host"
CREATED = "2026-10-23T12:00:00Z"
NOTICE = (
    "AI-generated example — not source text, non-normative; does not add or change requirements of the source"
)
QUOTE = "MUST pass every untrusted value as a bound parameter"
PY = {
    "unsafe": 'query = "SELECT id FROM users WHERE name = \'" + name + "\'"\n'
    "rows = connection.execute(query).fetchall()",
    "safe": 'query = "SELECT id FROM users WHERE name = ?"\n'
    "rows = connection.execute(query, (name,)).fetchall()",
    "demonstrates": [QUOTE],
}
JAVA = {
    "unsafe": 'String sql = "SELECT id FROM users WHERE name = \'" + name + "\'";\n'
    "ResultSet rows = statement.executeQuery(sql);",
    "safe": 'PreparedStatement ps = connection.prepareStatement("SELECT id FROM users WHERE name = ?");\n'
    "ps.setString(1, name);",
    "demonstrates": [QUOTE],
}
BASE_ITEMS = ("unsafe_violates_rule", "safe_addresses_rule", "language_correct")
# Every payload file FEATURE-001-G adds (design Planned Components + P4 reference).
NEW_PAYLOAD = (
    "knowledge/drafting_auth.py",
    "knowledge/drafting_blocks.py",
    "knowledge/drafting_checks.py",
    "knowledge/drafting_lint.py",
    "knowledge/drafting_mask.py",
    "knowledge/drafting_model.py",
    "knowledge/drafting_pipeline.py",
    "knowledge/drafting_service.py",
    "knowledge/drafting_supplements.py",
)
NEW_REFERENCE = "references/knowledge-drafting.md"


def mod(name: str) -> Any:
    """Import a 001-G (or delivered) knowledge module at Act."""
    return importlib.import_module("x_ipe_secure_code.knowledge." + name)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fixture_items(name: str) -> list[dict[str, Any]]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))["items"]


def codes(result: Any) -> list[str]:
    return [p.code for p in result.problems]


def dump(result: Any) -> str:
    """Everything a command prints (JSON and text forms)."""
    return result.to_json() + "\n" + result.to_text()


class DEnv(Env):
    """Exit-test Env plus seeded fixture rules and draft/review helpers."""

    def __init__(self, project: Path, work: Path, *, seed: bool = True, synth: bool = False) -> None:
        super().__init__(project, work)
        if seed:
            items = fixture_items("seed_batch.json") + (fixture_items("synth_batch.json") if synth else [])
            result = self.load(*items)
            assert result.ok, result.to_dict()

    # -- rule state ------------------------------------------------------------------------
    def folder(self, rule: str = R89) -> Path:
        return self.project / store.LOCAL_REL / rule

    def state(self, rule: str = R89) -> str:
        shown = self.show(rule)
        assert shown.ok, shown.to_dict()
        return shown.data["state_digest"]

    def rule_files(self, rule: str = R89) -> dict[str, bytes]:
        folder = self.folder(rule)
        return {p.name: p.read_bytes() for p in sorted(folder.iterdir()) if p.is_file()}

    def tree(self) -> dict[str, str]:
        return tree_hashes(self.project / "x-ipe-docs", self.project / ".x-ipe")

    # -- drafts --------------------------------------------------------------------------------
    def draft_doc(self, rule: str = R89, examples: dict[str, Any] | None = None, **over: Any) -> dict:
        doc: dict[str, Any] = {
            "schema": DRAFT_SCHEMA,
            "rule": rule,
            "base_state": self.state(rule),
            "drafted_by": {"host": HOST},
            "created_at": CREATED,
            "sources": [{"kind": "stored_rule_content"}],
            "examples": examples if examples is not None else {"python": dict(PY)},
        }
        doc.update(over)
        return {k: v for k, v in doc.items() if v is not None}

    def write_draft(self, doc: Any, name: str = "cwe-89--python") -> Path:
        folder = self.project / DRAFTS
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{name}.draft.json"
        data = doc if isinstance(doc, bytes) else json.dumps(doc, indent=2, ensure_ascii=False).encode()
        path.write_bytes(data)
        return path

    def review_doc(
        self,
        draft: Path,
        decisions: dict[str, dict[str, bool]] | None = None,
        *,
        attest: dict[str, bool] | None = None,
    ) -> dict:
        if decisions is None:
            langs = json.loads(draft.read_text(encoding="utf-8"))["examples"]
            decisions = {lang: self.decision(lang) for lang in langs}
        return {
            "schema": REVIEW_SCHEMA,
            "draft_digest": sha(draft.read_bytes()),
            "examples": decisions,
            "attestations": attest if attest is not None else {"non_normative": True},
        }

    @staticmethod
    def decision(lang: str, *, ack: bool = False, drop: tuple[str, ...] = ()) -> dict[str, bool]:
        items = dict.fromkeys(BASE_ITEMS, True)
        if lang != "python":
            items["unchecked_syntax_understood"] = True
        if ack:
            items["example_commands_acknowledged"] = True
        for name in drop:
            items.pop(name, None)
        return items

    def write_review(self, draft: Path, doc: Any = None, **kw: Any) -> Path:
        doc = doc if doc is not None else self.review_doc(draft, **kw)
        path = draft.with_name(draft.name.replace(".draft.json", ".review.json"))
        data = doc if isinstance(doc, bytes) else json.dumps(doc, indent=2).encode()
        path.write_bytes(data)
        return path

    def drafted(
        self, rule: str = R89, examples: Any = None, name: str = "cwe-89--python", **over: Any
    ) -> tuple[Path, Path]:
        draft = self.write_draft(self.draft_doc(rule, examples, **over), name)
        return draft, self.write_review(draft)

    # -- act -----------------------------------------------------------------------------------
    @property
    def svc(self) -> Any:
        return mod("drafting_service")

    def check(self, draft: Path, review: Path | None = None) -> Any:
        return self.svc.draft_check(str(self.project), str(draft), str(review) if review else None)

    def approve(
        self,
        draft: Path,
        review: Path | None,
        digest: str | None,
        fps: tuple[str, ...] = (),
        paths: Any = None,
    ) -> Any:
        return self.svc.draft_approve(
            str(self.project),
            str(draft),
            str(review) if review else None,
            digest,
            list(fps),
            trust_paths=paths or self.paths,
        )

    def checked_approve(self, draft: Path, review: Path, fps: tuple[str, ...] = ()) -> Any:
        report = self.check(draft, review)
        assert report.ok, report.to_dict()
        return self.approve(draft, review, report.data["validation_digest"], fps)

    def supplements(self, rule: str | None = R89) -> Any:
        return mod("drafting_supplements").list_supplements(str(self.project), rule)

    def cli(self, *args: str) -> tuple[int, dict[str, Any]]:
        """In-process `secure-code ... --json` with this Env's trust root (never the host's)."""
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(trust_store, "default_app_dir", lambda: self.trust)
            parsed = cli.build_parser().parse_args([*args, "--json"])
            result = cli.run(parsed)
        return (0 if result.ok else 1), json.loads(result.to_json())

    def cli_check(self, draft: Path, review: Path | None = None) -> tuple[int, dict[str, Any]]:
        args = ["knowledge", "draft-check", "--project", str(self.project), "--draft", str(draft)]
        return self.cli(*args, *(["--review", str(review)] if review else []))

    def cli_approve(self, draft: Path, review: Path, digest: str, *fps: str) -> tuple[int, dict[str, Any]]:
        args = [
            "knowledge",
            "draft-approve",
            "--project",
            str(self.project),
            "--draft",
            str(draft),
            "--review",
            str(review),
            "--validation-digest",
            digest,
        ]
        for fp in fps:
            args += ["--false-positive", fp]
        return self.cli(*args)

    def interrupt_exit(self, rule: str = R78) -> None:
        """A real interrupted 001-D exit (delivered crash point after the exit journal)."""
        from conftest import run_cli

        preview = self.preview("deactivate", rule)
        assert preview.ok, preview.to_dict()
        args = [
            "knowledge",
            "exit-confirm",
            "--project",
            str(self.project),
            "--rule",
            rule,
            "--action",
            "deactivate",
            "--reason",
            REASON,
            "--impact-digest",
            preview.data["impact_digest"],
            "--json",
        ]
        process = run_cli(args, self.trust, env_extra={"SECURE_CODE_TEST_CRASH_AT": "exit_after_journal"})
        assert process.returncode == 86, process.stdout + process.stderr


# --------------------------------------------------------------------------- golden outputs
TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z")
RUN_ID = re.compile(r"\b[a-z]{2}-\d{8}T\d{6}Z-[0-9a-f]{6,}\b")


OS_USER = re.compile(r'"os_user": "[^"]*"')


def normalise(text: str, *paths: Path) -> str:
    """Paths, times, run ids, host name and OS user (no machine identity in fixtures)."""
    for path in paths:
        for form in {str(path), str(path.resolve())}:
            text = text.replace(form, "<" + path.name + ">")
    text = OS_USER.sub('"os_user": "<os-user>"', text.replace(platform.node(), "<hostname>"))
    return TIME.sub("<time>", RUN_ID.sub("<run-id>", text))


def pre_001g_outputs(work: Path, removed: list[str] | None = None) -> dict[str, str]:
    """Delivered outputs for a project without drafts or supplements (design Implementation Step 0).

    In-process CLI (`--json`) with the knowledge/exit/policy clocks frozen; paths and remaining
    times normalised. `init` drops the paths of the new FEATURE-001-G payload files (they are the
    only expected difference; asserted separately by the regression test).
    """
    from presets.presethelp import freeze

    project = work / "golden project"
    project.mkdir()
    out: dict[str, str] = {}
    with pytest.MonkeyPatch.context() as patch:
        freeze(patch)
        env = DEnv(project, work, seed=False)
        fresh = work / "golden init"
        fresh.mkdir()
        _, init = env.cli("init", "--project", str(fresh), "--env", "github-copilot")
        created = init["data"]["files"]["created"]
        init["data"]["files"]["created"] = [p for p in created if not _new_payload(p)]
        if removed is not None:
            removed += [p for p in created if _new_payload(p)]
        out["init.json"] = json.dumps(init, indent=2, ensure_ascii=False)
        batch = work / "seed.json"
        batch.write_text((FIXTURES / "seed_batch.json").read_text(encoding="utf-8"), encoding="utf-8")
        p = str(project)
        out["import.json"] = json.dumps(env.cli("knowledge", "import", "--project", p, "--batch", str(batch)))
        state = env.state(R89)
        update = work / "update.json"
        update.write_text(
            json.dumps(
                {
                    "schema": "ai-secure-code-toolkit/knowledge-update/v1",
                    "examples": {"java": "// fixture java\nrun();\n"},
                }
            ),
            encoding="utf-8",
        )
        out["update.json"] = json.dumps(
            env.cli(
                "knowledge",
                "update",
                "--project",
                p,
                "--rule",
                R89,
                "--base-state",
                state,
                "--input",
                str(update),
            )
        )
        check = work / "check.json"
        check.write_text(
            json.dumps(
                {
                    "schema": "ai-secure-code-toolkit/knowledge-check/v1",
                    "items": [{"rule": R89, "item_digest": "sha256:" + "0" * 64}],
                    "source_documents": [],
                }
            ),
            encoding="utf-8",
        )
        for name, args in (
            ("check", ["knowledge", "check", "--project", p, "--input", str(check)]),
            ("show", ["knowledge", "show", "--project", p, "--rule", R89]),
            ("list", ["knowledge", "list", "--project", p]),
            ("links", ["knowledge", "links", "--project", p]),
            ("status", ["status", "--project", p]),
            ("resolve", ["policy", "resolve", "--project", p, "--rule", R89, "--rule", R78]),
            (
                "exit-preview",
                [
                    "knowledge",
                    "exit-preview",
                    "--project",
                    p,
                    "--rule",
                    R78,
                    "--action",
                    "deactivate",
                    "--reason",
                    "fixture reason",
                ],
            ),
        ):
            out[f"{name}.json"] = json.dumps(env.cli(*args), indent=2, ensure_ascii=False)
        saved = env.save(env.decisions((R89, R78)))
        assert saved.ok, saved.to_dict()
        scope_id = saved.data["scope_id"]
        out["scope-show.json"] = json.dumps(
            env.cli("scope", "show", "--project", p, "--scope", scope_id), indent=2, ensure_ascii=False
        )
        opened = env.cli("guard", "open", "--project", p, "--request", env.open_request(scope_id, "guard"))
        opened[1]["data"].pop("verification_id", None)
        out["guard-open.json"] = json.dumps(opened, indent=2, ensure_ascii=False)
    return {k: normalise(v, project, fresh, work) for k, v in sorted(out.items())}


def _new_payload(path: str) -> bool:
    return any(path.endswith("/scripts/src/x_ipe_secure_code/" + p) for p in NEW_PAYLOAD) or path.endswith(
        "/" + NEW_REFERENCE
    )


def run_pty(
    args: list[str],
    trust_dir: Path,
    answer: str | None,
    *,
    trigger: bytes = b"type the host label",
    timeout: float = 60,
) -> tuple[int, str]:
    """CLI under a pseudo-terminal (POSIX); types `answer` once the confirmation prompt appears."""
    import pty

    cmd = [sys.executable, str(LAUNCHER), "--test-trust-dir", str(trust_dir), *args]
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execvpe(cmd[0], cmd, dict(os.environ))
    output, sent = b"", answer is None
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
        if not sent and trigger in output.lower():
            os.write(fd, answer.encode() + b"\n")
            sent = True
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")
