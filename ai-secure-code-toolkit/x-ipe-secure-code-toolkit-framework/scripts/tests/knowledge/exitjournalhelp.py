"""Independent, hand-built exit-journal/v1 fixtures from the approved disk contract.

These fixtures do not call a production planner or journal writer. They allow a
reader/recovery test to expose invalid-journal behavior on the existing services.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from knowledge.exithelp import AT, DOC, EXITS, JOURNAL, R1, REASON, TARGET, Env, canonical, sha

from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.knowledge import changelog, store
from x_ipe_secure_code.knowledge.identity import RuleRef

EXIT_ID = "ex-20261022T080000Z-1234abcd"


def fingerprint(data: dict[str, bytes]) -> str:
    return sha(canonical([[name, "file", sha(body)] for name, body in sorted(data.items())]))


class JournalFixture:
    """One independently planned transaction, applicable at every done-prefix."""

    def __init__(self, env: Env, action: str, *, optional: bool = True) -> None:
        self.env, self.action = env, action
        self.root = env.project
        self.old = env.folder()
        self.tomb = self.root / EXITS / "tombstones" / EXIT_ID
        self.new = self.tomb / "rule" if action == "delete" else env.folder(TARGET)
        if optional:
            env.pending()
        if action == "reactivate":
            record_path = self.old / "record.json"
            marker = json.loads(record_path.read_text())
            marker["lifecycle"] = {"state": "deactivated", "revision": 1}
            record_path.write_bytes(dumps_json(marker))
            index = json.loads((self.root / store.INDEX_REL).read_text())
            index[DOC]["items"] = []
            index[DOC]["failed"] = [R1]
            index[DOC]["complete"] = False
            (self.root / store.INDEX_REL).write_bytes(dumps_json(index))
        elif not optional:
            (self.root / store.INDEX_REL).unlink()
        self.original = {p.name: p.read_bytes() for p in self.old.iterdir()}
        stored = store.read_rule(self.root, RuleRef.parse(R1))
        assert stored and stored.consistent
        self.before_revision = 1 if action == "reactivate" else 0
        revision = self.before_revision + 1
        old_digest = stored.digest
        old_state = sha(canonical({"item_digest": old_digest, "lifecycle_revision": 1})) if (
            self.before_revision
        ) else old_digest
        record = copy.deepcopy(stored.record)
        if action == "rename":
            record["rule_id"] = TARGET.split("/")[-1]
            record["item_digest"] = replace(stored.item, ref=RuleRef.parse(TARGET)).digest()
            record["updated_at"] = AT
        record["lifecycle"] = {
            "state": "deactivated" if action == "deactivate" else "active", "revision": revision,
        }
        state = None if action == "delete" else sha(canonical({
            "item_digest": record["item_digest"], "lifecycle_revision": revision,
        }))
        self.after_state = state

        def view(present, active, availability, reason, digest):
            return {
                "present": present, "active": active, "availability": availability,
                "reason": reason, "state_digest": digest,
            }

        before = view(
            True, action != "reactivate",
            "missing" if action == "reactivate" else "available",
            "deactivated" if action == "reactivate" else None,
            None if action == "reactivate" else old_state,
        )
        after = view(
            action not in ("delete", "rename"), action == "reactivate",
            "available" if action == "reactivate" else "missing",
            {"deactivate": "deactivated", "delete": "deleted", "rename": "renamed"}.get(action),
            state if action == "reactivate" else None,
        )
        identities = {R1: {"before": before, "after": after}}
        if action == "rename":
            identities[TARGET] = {
                "before": view(False, False, "missing", "not_found", None),
                "after": view(True, True, "available", None, state),
            }
        transition = {
            "exit_id": EXIT_ID, "action": action, "rule": R1,
            "target": TARGET if action == "rename" else None, "at": AT, "identities": identities,
        }
        transition["digest"] = sha(canonical(transition))
        self.transition = transition
        impact_digest = "sha256:" + "a" * 64
        steps = []

        def write(name, old, body):
            text = dumps_json(body).decode()
            steps.append({
                "name": name, "op": "write", "before": sha(old) if old is not None else None,
                "after": sha(text.encode()), "text": text,
            })

        planned = dict(self.original)
        if action in ("deactivate", "reactivate", "rename"):
            write("record", self.original["record.json"], record)
            suffix = (
                f"## {AT} — "
                f"{dict(deactivate='deactivated', reactivate='reactivated', rename='renamed')[action]}"
                " (role: maintainer)\n\n"
                f"- exit id: {EXIT_ID}\n- reason: {REASON}\n"
                f"- rule id: {R1}" + (f" → {TARGET}" if action == "rename" else "") + "\n"
                f"- lifecycle revision: {self.before_revision} → {revision}; "
                f"state digest: {old_state} → {state}\n"
                f"- impact digest: {impact_digest}\n- transition: {transition['digest']}\n\n"
                + changelog._diff(
                    "record.json", self.original["record.json"].decode(), dumps_json(record).decode()
                ) + "\n"
            )
            log = self.original["changelog.md"] + suffix.encode()
            steps.append({
                "name": "changelog", "op": "append", "before": sha(self.original["changelog.md"]),
                "after": sha(log), "suffix": suffix, "suffix_digest": sha(suffix.encode()),
            })
            planned.update({"record.json": dumps_json(record), "changelog.md": log})
        pending = self.root / store.PENDING_REL / (R1 + ".json")
        pending_before = sha(pending.read_bytes()) if pending.exists() else None
        index_path = self.root / store.INDEX_REL
        index = json.loads(index_path.read_text()) if index_path.exists() else {}
        edges = [DOC] if action != "reactivate" and DOC in index else []
        if action == "delete":
            steps += [
                {"name": "tombstone_dir", "op": "mkdir"},
                {"name": "move", "op": "move", "fingerprint": fingerprint(self.original)},
            ]
            write("tombstone_record", None, {
                "schema": "ai-secure-code-toolkit/exit-record/v1", "exit_id": EXIT_ID,
                "action": "delete", "rule": R1, "reason": REASON, "at": AT, "role": "maintainer",
                "consistent": True, "pending_commit": False, "state_digest": old_state,
                "lifecycle_revision": {"from": 0, "to": 1},
                "folder_fingerprint": fingerprint(self.original), "impact_digest": impact_digest,
                "transition": transition["digest"], "impact_counts": {
                    "relations": 2, "scopes": 0, "guard_runs": 0, "copilot_collaborations": 0,
                    "pending_decisions": int(pending_before is not None), "document_index": len(edges),
                },
                "removed_pending": [R1] if pending_before else [], "invalidated_index": edges,
                "special_entries": [],
            })
        elif action == "rename":
            steps.append({"name": "move", "op": "move", "fingerprint": fingerprint(planned)})
        if action in ("delete", "rename") and pending_before:
            steps.append({"name": "pending", "op": "remove", "before": pending_before})
        if edges:
            updated = copy.deepcopy(index)
            updated[DOC]["items"] = [e for e in updated[DOC]["items"] if e["rule"] != R1]
            updated[DOC]["failed"] = sorted(set(updated[DOC]["failed"]) | {R1})
            updated[DOC]["complete"] = False
            updated[DOC]["updated_at"] = AT
            write("index", index_path.read_bytes(), updated)
        if action in ("delete", "rename"):
            write("memory", None, {
                "schema": "ai-secure-code-toolkit/exit-memory/v1",
                "exited": [{
                    "rule": R1, "action": "deleted" if action == "delete" else "renamed",
                    "renamed_to": TARGET if action == "rename" else None,
                    "exit_id": EXIT_ID, "at": AT, "reason": REASON,
                    "tombstone": self.tomb.relative_to(self.root).as_posix() if action == "delete" else None,
                    "transition": transition["digest"],
                }],
            })
        write("transitions", None, {
            "schema": "ai-secure-code-toolkit/exit-transitions/v1", "entries": [transition],
        })
        self.journal = {
            "schema": "ai-secure-code-toolkit/exit-journal/v1", "exit_id": EXIT_ID,
            "action": action, "rule": R1, "target": TARGET if action == "rename" else None,
            "reason": REASON, "at": AT, "impact_digest": impact_digest,
            "transition_digest": transition["digest"],
            "pre_state": {"pending": pending_before, "index_edges": edges}, "steps": steps,
        }
        self.planned = planned

    def path(self, name: str) -> Path:
        if name in ("record", "changelog"):
            folder = self.old if self.old.exists() else self.new
            return folder / ("record.json" if name == "record" else "changelog.md")
        return {
            "tombstone_dir": self.tomb, "move": self.new,
            "tombstone_record": self.tomb / "exit-record.json",
            "pending": self.root / store.PENDING_REL / (R1 + ".json"),
            "index": self.root / store.INDEX_REL, "memory": self.root / EXITS / "memory.json",
            "transitions": self.root / EXITS / "transitions.json",
        }[name]

    def apply(self, step: dict[str, Any]) -> None:
        path = self.path(step["name"])
        if step["op"] == "move":
            path.parent.mkdir(parents=True, exist_ok=True)
            os.rename(self.old, path)
        elif step["op"] == "mkdir":
            path.mkdir(parents=True, exist_ok=True)
        elif step["op"] == "remove":
            path.unlink()
        elif step["op"] == "append":
            path.write_bytes(path.read_bytes() + step["suffix"].encode())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(step["text"].encode())

    def publish(self, prefix: int = 0) -> None:
        for step in self.journal["steps"][:prefix]:
            self.apply(step)
        path = self.root / JOURNAL
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(dumps_json(self.journal))

    def assert_completed(self) -> None:
        assert not (self.root / JOURNAL).exists()
        transitions = json.loads((self.root / EXITS / "transitions.json").read_text())
        assert transitions["entries"][-1] == self.transition
        if self.action in ("delete", "rename"):
            assert not self.old.exists()
            memory = json.loads((self.root / EXITS / "memory.json").read_text())
            assert memory["exited"][0]["transition"] == self.transition["digest"]
        if self.action == "delete":
            assert {p.name: p.read_bytes() for p in self.new.iterdir()} == self.original
            record = json.loads((self.tomb / "exit-record.json").read_text())
            assert record["transition"] == self.transition["digest"]
        else:
            folder = self.new if self.action == "rename" else self.old
            assert {p.name: p.read_bytes() for p in folder.iterdir()} == self.planned
        for step in self.journal["steps"]:
            if step["op"] in ("write", "append"):
                assert sha(self.path(step["name"]).read_bytes()) == step["after"]
            elif step["op"] == "remove":
                assert not self.path(step["name"]).exists()
