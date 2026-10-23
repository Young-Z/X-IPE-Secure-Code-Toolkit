"""FEATURE-001-F test helpers: real initialized projects, request files, fixed clocks.

New 001-F modules are imported at Act (never during collection), so the tests fail for the
right reason before the implementation exists. `pre_001f_outputs` generates the pre-001-F
fixtures (design Implementation Step 1) and re-generates them after the change (AC-001F-09a).
"""

from __future__ import annotations

import importlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from conftest import run_cli
from knowledge.exithelp import R1, R2, R3, TARGET, Env, item

from x_ipe_secure_code.knowledge import exit as exits
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.policy import scope
from x_ipe_secure_code.policy import service as policy

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pre_001f"
PRESETS = "x-ipe-docs/secure-code/presets"
TAGS = "x-ipe-docs/secure-code/tags"
LOCKS = ".x-ipe/private/secure-code/locks"
PRESET_REQ = "ai-secure-code-toolkit/preset-request/v1"
RECOMPUTE_REQ = "ai-secure-code-toolkit/preset-recompute/v1"
TAG_REQ = "ai-secure-code-toolkit/tag-request/v1"
CUSTOM = "@ACME/v1/A-1"
FIXED = datetime(2026, 10, 22, 8, 0, 0, tzinfo=UTC)
AT = "2026-10-22T08:00:00Z"
FIXTURE_NAMES = (
    "clues-proposal.json", "apply-all-proposal.json", "clues-record.json", "apply-all-record.json",
    "links.json", "links.txt",
)


def mod(name: str) -> Any:
    """Import an approved 001-F (or delivered) module at Act."""
    return importlib.import_module("x_ipe_secure_code." + name)


class FixedDateTime:
    @staticmethod
    def now(tz: Any = None) -> datetime:
        return FIXED if tz is not None else FIXED.replace(tzinfo=None)


def freeze(monkeypatch: Any) -> None:
    """Fixed clock for imports, exits and scope saves (deterministic record bytes)."""
    monkeypatch.setattr(knowledge, "_now", lambda: AT)
    monkeypatch.setattr(exits, "_now", lambda: AT)
    monkeypatch.setattr(policy, "datetime", FixedDateTime)


class PEnv(Env):
    """Env plus Preset/tag request files and service calls (imported at Act)."""

    # -- arrange -------------------------------------------------------------------------
    def rules(self, *, custom: bool = False) -> None:
        extra = [item(CUSTOM)] if custom else []
        result = self.load(item(), item(R2), item(R3), *extra)
        assert result.ok, result.to_dict()

    def preset_file(self, name: str = "web-input") -> Path:
        return self.project / PRESETS / f"{name}.json"

    def tag_file(self, name: str = "injection") -> Path:
        return self.project / TAGS / f"{name}.json"

    def preq(self, name: str | None = "web-input", rules: Any = (R1, R2), **over: Any) -> str:
        data: dict[str, Any] = {"schema": PRESET_REQ}
        if name is not None:
            data["name"] = name
        if rules is not None:
            data["rules"] = list(rules)
        data.update(over)
        return self.req(data)

    def treq(self, name: str | None = "injection", members: Any = (R1, R2), **over: Any) -> str:
        data: dict[str, Any] = {"schema": TAG_REQ}
        if name is not None:
            data["name"] = name
        if members is not None:
            data["members"] = list(members)
        data.update(over)
        return self.req(data)

    def creq(self, candidates: Any, **over: Any) -> str:
        return self.req({"schema": RECOMPUTE_REQ, "candidates": list(candidates), **over})

    # -- act -----------------------------------------------------------------------------
    @property
    def presets(self) -> Any:
        return mod("knowledge.presets")

    @property
    def tags(self) -> Any:
        return mod("knowledge.tags")

    @property
    def pscope(self) -> Any:
        return mod("policy.preset_scope")

    def psave(self, name: str = "web-input", rules: Any = (R1, R2), *, confirmed: bool = True,
              **over: Any) -> Any:
        return self.presets.save_preset(str(self.project), self.preq(name, rules, **over), confirmed)

    def pshow(self, name: str = "web-input") -> Any:
        return self.presets.show_preset(str(self.project), name)

    def pdigest(self, name: str = "web-input") -> str:
        shown = self.pshow(name)
        assert shown.ok, shown.to_dict()
        return shown.data["file_digest"]

    def pupdate(self, name: str = "web-input", *, digest: str | None = "current", confirmed: bool = True,
                **fields: Any) -> Any:
        if digest == "current":
            digest = self.pdigest(name)
        path = self.req({"schema": PRESET_REQ, **fields})
        return self.presets.update_preset(str(self.project), name, path, digest, confirmed)

    def pdelete(self, name: str = "web-input", *, digest: str | None = "current",
                confirmed: bool = True) -> Any:
        if digest == "current":
            digest = self.pdigest(name)
        return self.presets.delete_preset(str(self.project), name, digest, confirmed)

    def recompute(self, candidates: Any, name: str = "web-input") -> Any:
        return self.presets.recompute(str(self.project), name, self.creq(candidates))

    def recompute_confirm(self, candidates: Any, digest: str, name: str = "web-input", *,
                          confirmed: bool = True, **over: Any) -> Any:
        path = self.creq(candidates, recompute_digest=digest, **over)
        return self.presets.recompute_confirm(str(self.project), name, path, confirmed)

    def tsave(self, name: str = "injection", members: Any = (R1, R2), *, paths: Any = None,
              confirmed: bool = True) -> Any:
        return self.tags.save_tag(
            str(self.project), self.treq(name, members), confirmed, trust_paths=paths or self.paths
        )

    def tshow(self, name: str = "injection") -> Any:
        return self.tags.show_tag(str(self.project), name)

    def tdigest(self, name: str = "injection") -> str:
        shown = self.tshow(name)
        assert shown.ok, shown.to_dict()
        return shown.data["file_digest"]

    def tupdate(self, name: str = "injection", members: Any = (R1,), *, digest: str | None = "current",
                paths: Any = None, confirmed: bool = True) -> Any:
        if digest == "current":
            digest = self.tdigest(name)
        path = self.treq(None, members)
        return self.tags.update_tag(
            str(self.project), name, path, digest, confirmed, trust_paths=paths or self.paths
        )

    def tdelete(self, name: str = "injection", *, digest: str | None = "current", paths: Any = None,
                confirmed: bool = True) -> Any:
        if digest == "current":
            digest = self.tdigest(name)
        return self.tags.delete_tag(
            str(self.project), name, digest, confirmed, trust_paths=paths or self.paths
        )

    def presolve(self, name: str | None = "web-input", languages: Any = ("python",)) -> Any:
        if name is None:
            return self.pscope.resolve_default(str(self.project), list(languages))
        return self.pscope.resolve_preset(str(self.project), name, list(languages))

    def pdecisions(self, proposal: Any, *, skipped: tuple[str, ...] = (), clue: str | None = None,
                   considered: Any = None) -> str:
        choices = []
        for entry in proposal.data["entries"]:
            ref = entry["requested"]
            if ref in skipped or entry["availability"] != "available":
                choices.append({"ref": ref, "decision": "not_adopted", "reason": "User excluded it"})
            else:
                choices.append({"ref": ref, "decision": "adopted",
                                "state_digest": entry["source_evidence"]["state_digest"]})
        return self.req({
            "schema": scope.DECISIONS_SCHEMA, "mode": "clues",
            "considered": list(considered) if considered is not None
            else [e["requested"] for e in proposal.data["entries"]],
            "proposal_digest": proposal.data["proposal_digest"],
            "clues": clue if clue is not None else proposal.data["preset"]["clue"],
            "language_context": ["python"], "decisions": choices,
            "confirmation_note": "User explicitly confirmed the Preset scope",
        })

    def pscope_save(self, name: str, decisions: str, *, confirmed: bool = True) -> Any:
        return self.pscope.save(str(self.project), name, decisions, confirmed)

    def lock_listing(self) -> list[str]:
        folder = self.project / LOCKS
        return sorted(os.listdir(folder)) if folder.is_dir() else []


def unchanged_but_lock(before: dict[str, Any], after: dict[str, Any]) -> None:
    """A refused request leaves the tree byte-identical except the knowledge lock file."""
    allowed = {f"{LOCKS}/", f"{LOCKS}/knowledge.lock", ".x-ipe/private/secure-code/locks/"}
    changed = {k for k in before if k in after and before[k] != after[k]}
    removed = {k for k in before if k not in after}
    added = {k for k in after if k not in before} - allowed
    assert not changed and not removed and not added, (changed, removed, added)


def pre_001f_outputs(env: Env, monkeypatch: Any, before_links: Any = None) -> dict[str, bytes]:
    """Pre-001-F fixtures: clues/apply_all proposals, their saved records, and links JSON/text
    for a project with a broken relation and a scope adopting an exited rule (fixed clock).
    `before_links(env)` may rearrange the Preset/tag stores right before the link check."""
    freeze(monkeypatch)
    env.populate(rich=True)
    project = str(env.project)
    out: dict[str, bytes] = {}
    clues = run_cli(["policy", "resolve", "--project", project, "--rule", R1, "--rule", R3,
                     "--language", "python", "--json"], env.trust)
    every = run_cli(["policy", "resolve", "--project", project, "--all", "--language", "python",
                     "--json"], env.trust)
    assert clues.returncode == 0 and every.returncode == 0, (clues.stderr, every.stderr)
    out["clues-proposal.json"] = clues.stdout.encode("utf-8")
    out["apply-all-proposal.json"] = every.stdout.encode("utf-8")
    for name, all_ in (("clues-record.json", False), ("apply-all-record.json", True)):
        saved = env.save(env.decisions(all_=all_))
        assert saved.ok, saved.to_dict()
        out[name] = env.scope_path(saved.data["scope_id"]).read_bytes()
    env.exit("rename")
    if before_links is not None:
        before_links(env)
    links = run_cli(["knowledge", "links", "--project", project, "--json"], env.trust)
    text = run_cli(["knowledge", "links", "--project", project], env.trust)
    assert links.returncode == 0 and text.returncode == 0, (links.stderr, text.stderr)
    out["links.json"] = links.stdout.encode("utf-8")
    out["links.txt"] = text.stdout.encode("utf-8")
    assert json.loads(links.stdout)["data"]["broken_relations"], links.stdout
    assert TARGET in links.stdout
    return out
