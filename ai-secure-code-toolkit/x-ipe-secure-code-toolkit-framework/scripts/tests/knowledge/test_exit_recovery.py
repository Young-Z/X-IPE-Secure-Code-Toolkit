"""AC-001D-06a Integration: crash every action boundary and recover on every command.

Arrange real confirmed exits in subprocesses / independent pending journals; Act
crash and next service command; Assert no success before durable commit, complete
record/history/revision/private/cache state, bounded recovery before current auth.
"""

from __future__ import annotations

import json

import pytest
from conftest import run_cli
from knowledge.exithelp import (
    DOC,
    EXITS,
    JOURNAL,
    R1,
    R2,
    R3,
    STEPS,
    TARGET,
    Env,
    files,
    item,
    module,
    refusal,
)
from knowledge.exitjournalhelp import JournalFixture

from x_ipe_secure_code.atomic import LockHeld
from x_ipe_secure_code.knowledge import service, store
from x_ipe_secure_code.policy import service as policy

CRASHES = [
    (action, point) for action, steps in STEPS.items()
    for point in ("exit_after_journal", *["exit_after_" + s for s in steps], "exit_before_journal_delete")
]


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate(rich=True)
    return result


def assert_real_exit_complete(env, action):
    assert not (env.project / JOURNAL).exists()
    transitions = json.loads((env.project / EXITS / "transitions.json").read_text())["entries"]
    transition = transitions[-1]
    assert transition["action"] == action
    if action in ("delete", "rename"):
        assert not env.folder().exists()
        memory = json.loads((env.project / EXITS / "memory.json").read_text())["exited"]
        entry = next(e for e in memory if e["rule"] == R1)
        assert entry["transition"] == transition["digest"]
        assert not (env.project / store.PENDING_REL / (R1 + ".json")).exists()
        if action == "delete":
            tomb = env.project / entry["tombstone"]
            assert (tomb / "rule/content.md").read_bytes() == b"Rule CWE-79 body.\n"
            exit_record = json.loads((tomb / "exit-record.json").read_text())
            assert exit_record["transition"] == transition["digest"]
            assert exit_record["lifecycle_revision"]["to"] > exit_record["lifecycle_revision"]["from"]
        else:
            shown = env.show(TARGET).data
            assert shown["record"]["lifecycle"] == {"state": "active", "revision": 1}
            assert transition["digest"] in shown["changelog"]
    else:
        shown = env.show().data
        assert shown["consistent"] is True
        assert shown["record"]["lifecycle"] == {
            "state": "active" if action == "reactivate" else "deactivated",
            "revision": 2 if action == "reactivate" else 1,
        }
        assert ("reactivated" if action == "reactivate" else "deactivated") in shown["changelog"]
        assert transition["digest"] in shown["changelog"]
        assert (env.project / store.PENDING_REL / (R1 + ".json")).exists()
    index = json.loads((env.project / store.INDEX_REL).read_text())[DOC]
    assert index["complete"] is False
    assert R1 in index["failed"]
    assert R1 not in {e["rule"] for e in index["items"]}
    assert env.check().data["source_documents"][DOC] == "not_fully_stored"


@pytest.mark.parametrize("action,point", CRASHES)
def test_real_crash_every_documented_durable_boundary(env, action, point):
    env.pending()
    if action == "reactivate":
        env.exit("deactivate")
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    assert preview.ok
    process = run_cli(
        env.cli_args(action, preview.data["impact_digest"]), env.trust,
        env_extra={"SECURE_CODE_TEST_CRASH_AT": point},
    )
    assert process.returncode == 86, process.stdout + process.stderr
    assert '"ok": true' not in process.stdout.lower()
    assert (env.project / JOURNAL).exists()
    recovered = service.list_rules(str(env.project))
    assert recovered.ok, recovered.to_dict()
    assert recovered.data["recovered_exit"]["action"] == action
    assert_real_exit_complete(env, action)
    before = files(env.project)
    assert service.list_rules(str(env.project)).ok
    assert files(env.project) == before


@pytest.mark.parametrize("action", list(STEPS))
@pytest.mark.parametrize("command", [
    "import", "update", "exit-preview", "exit-confirm", "check", "list", "show",
    "links", "resolve", "scope-save", "scope-show",
])
def test_every_knowledge_policy_entry_recovers_first(env, action, command):
    saved = env.save(env.decisions((R2, R3)))
    decisions = env.decisions((R2, R3))
    base = env.show(R2).data["item_digest"]
    fixture = JournalFixture(env, action)
    fixture.publish(1)
    if command == "import":
        result = env.load(item("CWE/4.14/UNRELATED"))
    elif command == "update":
        result = env.update(R2, base, content="Unrelated current update.\n")
    elif command == "exit-preview":
        result = env.preview(rule=R2)
    elif command == "exit-confirm":
        result = env.confirm("sha256:" + "0" * 64, rule=R2)
    elif command == "check":
        result = env.check()
    elif command == "list":
        result = service.list_rules(str(env.project))
    elif command == "show":
        result = env.show(R2)
    elif command == "links":
        result = module("exit").links(str(env.project))
    elif command == "resolve":
        result = env.proposal()
    elif command == "scope-save":
        result = env.save(decisions)
    else:
        result = policy.show_scope(str(env.project), saved.data["scope_id"])
    fixture.assert_completed()
    assert result.data["recovered_exit"]["action"] == action
    assert result.data["recovered_exit"]["rule"] == R1


@pytest.mark.parametrize("command", ["preview", "confirm", "import", "update"])
def test_recovery_before_current_authorization_is_only_bounded_write(env, command):
    base = env.show(R2).data["item_digest"]
    fixture = JournalFixture(env, "delete")
    fixture.publish(1)
    env.revoke()
    if command == "preview":
        result = env.preview(rule=R2)
    elif command == "confirm":
        result = env.confirm("sha256:" + "0" * 64, rule=R2)
    elif command == "import":
        result = env.load(item("CWE/4.14/DENIED"))
    else:
        result = env.update(R2, base, content="Denied write.\n")
    refusal(result, "NOT_AUTHORIZED")
    fixture.assert_completed()
    assert not env.folder("CWE/4.14/DENIED").exists()
    assert (env.folder(R2) / "content.md").read_bytes() == b"Rule CWE-89 body.\n"
    before = files(env.project)
    refusal(env.preview(rule=R2), "NOT_AUTHORIZED")
    assert files(env.project) == before


def test_recovery_cannot_lock_never_exposes_half_state(env, monkeypatch):
    fixture = JournalFixture(env, "rename")
    fixture.publish(1)
    before = files(env.project)

    def held(self):
        raise LockHeld(env.project / store.LOCK_REL, "injected held recovery lock")

    monkeypatch.setattr(module("durable").DirLock, "__enter__", held)
    result = service.list_rules(str(env.project))
    refusal(result, "LOCKED")
    assert "rules" not in result.data
    assert files(env.project) == before
