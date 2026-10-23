"""Shared setup for the FEATURE-003-A Copilot tests (initialized project, Maintainer, adopted scope)."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from conftest import PASSPHRASE, FakeInteraction

from x_ipe_secure_code.auth.service import initialize_authorization
from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust
from x_ipe_secure_code.copilot import service as copilot
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.knowledge.identity import RuleRef
from x_ipe_secure_code.policy import service as policy
from x_ipe_secure_code.project_init import initialize_project

R1 = "CWE/4.14/CWE-79"
R2 = "CWE/4.14/CWE-89"
R3 = "CWE/4.14/CWE-22"
TOKEN = "ghp_" + "d" * 36
PRIVATE = ".x-ipe/private/secure-code/copilot"
REPORTS = "x-ipe-docs/secure-code/reports/copilot"
LOCKS = ".x-ipe/private/secure-code/locks"
S_OPEN = "ai-secure-code-toolkit/copilot-open/v1"
S_ART = "ai-secure-code-toolkit/copilot-artifacts/v1"
S_SUG = "ai-secure-code-toolkit/copilot-suggest/v1"
S_REV = "ai-secure-code-toolkit/reviewer-record/v1"


def _item(rule: str, body: str = "Rule body.\n") -> dict[str, str]:
    ns, ver, rid = rule.split("/")
    return {
        "namespace": ns,
        "version": ver,
        "rule_id": rid,
        "content": body,
        "source_location": "https://example.org/" + rid,
    }


class Env:
    """One initialized project with knowledge R1..R3 and an adopted scope of R1, R2."""

    def __init__(self, project: Path, tmp: Path) -> None:
        self.project = project
        self.tmp = tmp
        self.n = 0
        assert initialize_project(str(project), "github-copilot").ok
        self.paths = resolve_trust(tmp / "trust-app")
        assert initialize_authorization(
            paths=self.paths, interaction=FakeInteraction(answers=[PASSPHRASE] * 2)
        ).ok
        batch = tmp / "batch.json"
        batch.write_text(
            json.dumps(
                {
                    "schema": "ai-secure-code-toolkit/knowledge-batch/v1",
                    "items": [_item(R1), _item(R2), _item(R3)],
                }
            )
        )
        assert knowledge.import_batch(str(project), str(batch), [], [], trust_paths=self.paths).ok
        (project / "src").mkdir()
        (project / "src" / "register.py").write_text("def register(u):\n    return db.run(u)\n")
        (project / "src" / "util.py").write_text("def helper():\n    return 1\n")
        (project / "docs").mkdir()
        (project / "docs" / "design.md").write_text("# Design\n")
        (project / "docs" / "api.md").write_text("# API\n")
        (project / "README.md").write_text("# readme\n")
        self.scope = self.save_scope([R1, R2])

    # ------------------------------------------------------------------ knowledge / scope
    def save_scope(self, adopt: list[str], name: str | None = None) -> str:
        proposal = policy.resolve_policies(str(self.project), list(adopt), False, [])
        decisions = [
            {
                "ref": e["requested"],
                "decision": "adopted",
                "state_digest": e["source_evidence"]["state_digest"],
            }
            for e in proposal.data["entries"]
        ]
        doc = {
            "schema": "ai-secure-code-toolkit/scope-decisions/v1",
            "mode": "clues",
            "proposal_digest": proposal.data["proposal_digest"],
            "clues": "registration change",
            "language_context": ["python"],
            "decisions": decisions,
            "confirmation_note": "user confirmed",
            "considered": list(adopt),
        }
        path = self.req(doc)
        saved = policy.save_scope(str(self.project), path, True)
        assert saved.ok, saved.to_text()
        return saved.data["scope_id"]

    def change_rule(self, rule: str, body: str) -> None:
        upd = self.tmp / f"upd-{self.n}.json"
        self.n += 1
        upd.write_text(json.dumps({"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": body}))
        current = policy.resolve_policies(str(self.project), [rule], False, []).data["entries"][0]
        result = knowledge.update_rule(
            str(self.project),
            rule,
            current["source_evidence"]["state_digest"],
            str(upd),
            [],
            trust_paths=self.paths,
        )
        assert result.ok, result.to_text()

    def remove_rule(self, rule: str) -> None:
        shutil.rmtree(store.rule_dir(self.project, RuleRef.parse(rule)))

    # ------------------------------------------------------------------ requests
    def req(self, doc: Any) -> str:
        self.n += 1
        path = self.tmp / f"req-{self.n}.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return str(path)

    def open(self, **over: Any):
        doc = {
            "schema": S_OPEN,
            "scope_id": self.scope,
            "stage": "implementation",
            "task": "Add user registration",
            "artifacts": [{"path": "src/register.py", "change": "modified"}, {"path": "src/util.py"}],
        }
        doc.update(over)
        return copilot.open_collaboration(str(self.project), self.req(doc))

    def opened(self, **over: Any) -> str:
        result = self.open(**over)
        assert result.ok, result.to_text()
        return result.data["collaboration_id"]

    def artifacts(self, cid: str, entries: list[dict[str, Any]]):
        return copilot.update_artifacts(
            str(self.project), cid, self.req({"schema": S_ART, "artifacts": entries})
        )

    def suggest(self, cid: str, suggestions: list[dict[str, Any]]):
        return copilot.suggest(
            str(self.project), cid, self.req({"schema": S_SUG, "suggestions": suggestions})
        )

    def review(self, cid: str, subjects: list[dict[str, Any]], files: list[str] | None = None, **over: Any):
        files = (
            files
            if files is not None
            else sorted({f for s in subjects for f in self.suggestion_files(cid, s["id"])})
        )
        doc = {
            "schema": S_REV,
            "invocation": {
                "host": "github-copilot",
                "agent": "copilot-reviewer",
                "read_only": True,
                "invoked_at": "2026-10-21T10:00:00Z",
            },
            "requirement": "Check adoption of the suggestions in the formed artifact",
            "reviewed_targets": [{"path": f, "digest": self.digest(f)} for f in files],
            "subjects": subjects,
            "reviewed_at": "2026-10-21T10:05:00Z",
        }
        doc.update(over)
        return copilot.review(str(self.project), cid, self.req(doc))

    def report(self, cid: str):
        return copilot.report(str(self.project), cid)

    def show(self, cid: str):
        return copilot.show(str(self.project), cid)

    def close(self, cid: str):
        return copilot.close(str(self.project), cid)

    # ------------------------------------------------------------------ reading
    def digest(self, rel: str) -> str:
        path = self.project / rel
        if not path.exists():
            return "absent"
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def state(self, cid: str) -> dict[str, Any]:
        return json.loads((self.project / PRIVATE / cid / "state.json").read_text(encoding="utf-8"))

    def suggestion_files(self, cid: str, sid: str) -> list[str]:
        return next(s["files"] for s in self.state(cid)["suggestions"] if s["id"] == sid)

    def result_json(self, cid: str, n: int) -> dict[str, Any]:
        return json.loads((self.project / REPORTS / f"{cid}-r{n}.json").read_text(encoding="utf-8"))

    def report_md(self, cid: str, n: int) -> str:
        return (self.project / REPORTS / f"{cid}-r{n}.md").read_text(encoding="utf-8")

    def rounds(self, cid: str) -> list[str]:
        folder = self.project / REPORTS
        return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []

    def private_entries(self) -> list[str]:
        folder = self.project / PRIVATE
        return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def sug(
    sid: str, rule: str = R1, files: tuple[str, ...] = ("src/register.py",), **over: Any
) -> dict[str, Any]:
    doc = {
        "id": sid,
        "rule": rule,
        "files": list(files),
        "location": "register(), line 2",
        "action": "Use a parameterized query for the insert",
        "reason": "User input reaches SQL",
        "severity": "high",
    }
    doc.update(over)
    return doc


def adoption(sid: str, result: str = "adopted", basis: str = "found in register() line 2") -> dict[str, Any]:
    return {"type": "adoption", "id": sid, "result": result, "basis": basis}


def by_id(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["id"]: s for s in result["suggestions"]}
