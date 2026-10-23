"""AC-001D-06a Integration: independently authored journals, every progress prefix.

Arrange hand-built disk transactions (not the production planner); Act a real
knowledge read; Assert complete state or EXIT_JOURNAL_INVALID with no mutation.
"""

from __future__ import annotations

import copy
import json

import pytest
from knowledge.exithelp import EXITS, JOURNAL, R1, Env, files, refusal, sha
from knowledge.exitjournalhelp import JournalFixture

from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.knowledge import service, store

COUNTS = {"deactivate": 4, "reactivate": 3, "delete": 7, "rename": 7}
PREFIXES = [(action, k) for action, n in COUNTS.items() for k in range(n + 1)]


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate(rich=True)
    return result


@pytest.mark.parametrize("action,prefix", PREFIXES)
def test_handbuilt_every_done_prefix_rolls_forward(env, action, prefix):
    fixture = JournalFixture(env, action)
    fixture.publish(prefix)
    result = service.list_rules(str(env.project))
    assert result.ok, result.to_dict()
    fixture.assert_completed()
    assert result.data["recovered_exit"]["action"] == action
    assert result.data["recovered_exit"]["rule"] == R1
    assert result.data["recovered_exit"]["outcome"] == "completed"
    before = files(env.project)
    assert service.list_rules(str(env.project)).ok
    assert files(env.project) == before, "recovery must be idempotent"


@pytest.mark.parametrize("action", list(COUNTS))
def test_handbuilt_optional_steps_absent_when_no_edges(env, action):
    fixture = JournalFixture(env, action, optional=False)
    fixture.publish()
    result = service.list_rules(str(env.project))
    assert result.ok, result.to_dict()
    fixture.assert_completed()


D2_PREFIXES = [(a, k) for a in ("deactivate", "reactivate") for k in range(COUNTS[a] + 1)]


@pytest.mark.parametrize("action,prefix", D2_PREFIXES)
@pytest.mark.parametrize("pre_state_pending", ["recorded", "null"])
def test_deactivate_reactivate_keep_pending_without_pending_step(env, action, prefix, pre_state_pending):
    """Design v1.1 D2 / AC-03f: a retained pending decision with no `pending` step is VALID for
    deactivate/reactivate (presence not checked); recovery completes and the pending file is unchanged."""
    fixture = JournalFixture(env, action)
    pending = env.project / store.PENDING_REL / (R1 + ".json")
    prior = pending.read_bytes()
    assert "pending" not in {s["name"] for s in fixture.journal["steps"]}
    if pre_state_pending == "null":
        fixture.journal["pre_state"]["pending"] = None
    fixture.publish(prefix)
    result = service.list_rules(str(env.project))
    assert result.ok, result.to_dict()
    assert result.data["recovered_exit"]["outcome"] == "completed"
    fixture.assert_completed()
    assert pending.read_bytes() == prior


TAMPERS = [
    "schema", "action", "exit_id", "reason", "target", "duplicate", "out_of_order",
    "payload", "append_suffix", "append_after", "transition_payload", "transition_digest",
    "record_payload_identity", "memory_payload", "index_payload", "tombstone_payload",
    "omitted_required", "omitted_optional", "hidden_pending", "hidden_index",
    "changed_before", "non_prefix", "truncated_parseable", "malformed",
]


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
@pytest.mark.parametrize("tamper", TAMPERS)
def test_invalid_journal_never_mutates_knowledge(env, action, tamper):
    fixture = JournalFixture(env, action)
    journal = fixture.journal
    steps = journal["steps"]
    by_name = {s["name"]: s for s in steps}
    if tamper == "non_prefix":
        fixture.apply(by_name["changelog"] if action != "delete" else by_name["memory"])
    fixture.publish()
    if tamper in ("schema", "action", "exit_id", "reason"):
        journal[tamper] = {
            "schema": "unknown", "action": "restore", "exit_id": "../escape", "reason": "",
        }[tamper]
    elif tamper == "target":
        journal["target"] = "OTHER/v2/NEW"
    elif tamper == "duplicate":
        steps.insert(1, copy.deepcopy(steps[0]))
    elif tamper == "out_of_order":
        steps[0], steps[-1] = steps[-1], steps[0]
    elif tamper == "payload":
        next(s for s in steps if s["op"] == "write")["text"] += "tamper"
    elif tamper.startswith("append"):
        if "changelog" in by_name:
            by_name["changelog"]["suffix" if tamper == "append_suffix" else "after"] = "tampered"
        else:
            by_name["move"]["fingerprint"] = "sha256:" + "0" * 64
    elif tamper.startswith("transition"):
        if tamper == "transition_digest":
            journal["transition_digest"] = "sha256:" + "0" * 64
        else:
            transition = by_name["transitions"]
            data = json.loads(transition["text"])
            data["entries"][0]["identities"][R1]["before"]["present"] = False
            transition["text"] = dumps_json(data).decode()
            transition["after"] = sha(transition["text"].encode())
    elif tamper.endswith("_payload") or tamper == "record_payload_identity":
        name = {
            "record_payload_identity": "record", "memory_payload": "memory",
            "index_payload": "index", "tombstone_payload": "tombstone_record",
        }[tamper]
        name = name if name in by_name else "transitions"
        step = by_name[name]
        data = json.loads(step["text"])
        if name == "record":
            data["rule_id"] = "WRONG"
        elif name == "memory":
            data["exited"] = []
        elif name == "index":
            data = json.loads((env.project / store.INDEX_REL).read_text())
        elif name == "tombstone_record":
            data["rule"] = "CWE/4.14/WRONG"
        else:
            data["entries"] = []
        step["text"] = dumps_json(data).decode()
        step["after"] = sha(step["text"].encode())
    elif tamper == "omitted_required":
        steps.pop()
    elif tamper == "omitted_optional":
        steps.remove(by_name["index"])
    elif tamper == "hidden_pending":
        if "pending" in by_name:
            steps.remove(by_name["pending"])
        journal["pre_state"]["pending"] = None
        if action == "deactivate":
            journal["pre_state"]["index_edges"] = []
            steps.remove(by_name["index"])
    elif tamper == "hidden_index":
        steps.remove(by_name["index"])
        journal["pre_state"]["index_edges"] = []
    elif tamper == "changed_before":
        (env.folder() / "content.md").write_text("Changed after planning.\n")
    elif tamper == "truncated_parseable":
        steps[:] = steps[:1]
    path = env.project / JOURNAL
    path.write_bytes(b"{malformed" if tamper == "malformed" else dumps_json(journal))
    before = files(env.project)
    result = service.list_rules(str(env.project))
    refusal(result, "EXIT_JOURNAL_INVALID", step="Maintainer")
    assert "inspect" in result.next_steps[0].lower()
    assert files(env.project) == before


@pytest.mark.parametrize("action", ["reactivate"])
@pytest.mark.parametrize("tamper", [
    "payload", "suffix", "omitted_record", "omitted_changelog", "omitted_transition", "transition_binding",
])
def test_reactivate_journal_required_steps_and_integrity(env, action, tamper):
    fixture = JournalFixture(env, action)
    fixture.publish()
    steps = fixture.journal["steps"]
    if tamper.startswith("omitted"):
        name = tamper.removeprefix("omitted_")
        name = "transitions" if name == "transition" else name
        steps[:] = [s for s in steps if s["name"] != name]
    elif tamper == "payload":
        steps[0]["text"] += "bad"
    elif tamper == "suffix":
        steps[1]["suffix"] += "bad"
    else:
        steps[1]["suffix"] = steps[1]["suffix"].replace(
            fixture.transition["digest"], "sha256:" + "0" * 64
        )
        steps[1]["suffix_digest"] = sha(steps[1]["suffix"].encode())
        steps[1]["after"] = sha(fixture.original["changelog.md"] + steps[1]["suffix"].encode())
    (env.project / JOURNAL).write_bytes(dumps_json(fixture.journal))
    before = files(env.project)
    refusal(service.list_rules(str(env.project)), "EXIT_JOURNAL_INVALID")
    assert files(env.project) == before


def test_prejournal_exit_temporary_rolls_back_only_itself(env):
    exits = env.project / EXITS
    exits.mkdir(parents=True)
    stray = exits / ".exit-ex-20261022T080000Z-1234abcd.journal.tmp"
    stray.write_bytes(b"incomplete")
    keep = exits / "maintainer-notes"
    keep.write_bytes(b"not exit owned")
    rule = files(env.folder())
    result = service.list_rules(str(env.project))
    assert result.ok
    assert result.data["recovered_exit"]["outcome"] == "rolled_back"
    assert not stray.exists()
    assert keep.read_bytes() == b"not exit owned"
    assert files(env.folder()) == rule
