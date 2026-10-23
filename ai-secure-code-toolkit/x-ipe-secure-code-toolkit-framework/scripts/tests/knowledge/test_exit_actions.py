"""AC-001D-01a,03a-h,05a-c Integration: real actions, preservation and import.

Arrange real stored rules/dependents; Act authorized preview then confirm (or a
bounded refusal); Assert lifecycle/history, exhaustive preservation, cache and
identity contracts. No mocked store substitutes for the action integration.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest
from knowledge.exithelp import (
    DOC,
    EXITS,
    R1,
    R2,
    REASON,
    TARGET,
    Env,
    canonical,
    files,
    item,
    need_symlinks,
    refusal,
    sha,
)

from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import service as policy


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate(rich=True)
    return result


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
def test_references_never_block_or_cascade(env, action):
    saved = env.save()
    assert saved.ok
    env.open_runs(saved.data["scope_id"], history=True)
    before = env.dependent_bytes()
    assert any("reports/guard" in p and p.endswith(".md") for p in before)
    assert any("reports/copilot" in p and p.endswith(".json") for p in before)
    assert env.exit(action).data["outcome"] == {
        "deactivate": "deactivated", "delete": "deleted", "rename": "renamed",
    }[action]
    assert env.dependent_bytes() == before


def test_deactivate_and_reactivate_history(env):
    before = env.show().data
    original = files(env.folder())
    first = env.exit("deactivate")
    after = env.show().data
    assert after["record"]["lifecycle"] == {"state": "deactivated", "revision": 1}
    assert after["state"] == "deactivated"
    assert after["state_digest"] != before["item_digest"]
    assert after["item_digest"] == before["item_digest"]
    assert after["record"]["updated_at"] == before["record"]["updated_at"]
    for name in ("content.md", "example.md", "example-python.md"):
        assert (env.folder() / name).read_bytes() == original[name]
    log = (env.folder() / "changelog.md").read_bytes()
    assert log.startswith(original["changelog.md"])
    assert b"deactivated" in log[len(original["changelog.md"]):]
    assert REASON.encode() in log[len(original["changelog.md"]):]
    assert re.search(rb"## \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", log[len(original["changelog.md"]):])
    assert first.data["lifecycle_revision"] == 1
    second = env.exit("reactivate")
    active = env.show().data
    assert active["record"]["lifecycle"] == {"state": "active", "revision": 2}
    assert active["state_digest"] not in (before["item_digest"], after["state_digest"])
    assert second.data["lifecycle_revision"] == 2
    assert (env.folder() / "changelog.md").read_bytes().startswith(log)
    assert "reactivated" in active["changelog"] and REASON in active["changelog"]
    assert env.proposal().data["entries"][0]["availability"] == "available"


@pytest.mark.parametrize("state,action", [("active", "reactivate"), ("deactivated", "deactivate")])
def test_action_state_guards(env, state, action):
    if state == "deactivated":
        env.exit("deactivate")
    before = files(env.project)
    refusal(env.preview(action), "ACTION_NOT_APPLICABLE")
    refusal(env.confirm("sha256:" + "0" * 64, action), "ACTION_NOT_APPLICABLE")
    assert files(env.project) == before


def test_delete_tombstone(env):
    original = files(env.folder())
    result = env.exit("delete")
    assert not env.folder().exists()
    tombstone = env.project / result.data["tombstone"]
    assert tombstone.is_relative_to(env.project / EXITS / "tombstones")
    assert files(tombstone / "rule") == original
    record = json.loads((tombstone / "exit-record.json").read_text())
    assert record["schema"] == "ai-secure-code-toolkit/exit-record/v1"
    assert record["action"] == "delete"
    assert record["rule"] == R1
    assert record["reason"] == REASON
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", record["at"])
    assert record["lifecycle_revision"] == {"from": 0, "to": 1}
    assert record["consistent"] is True
    if os.name == "posix":
        assert stat.S_IMODE(tombstone.stat().st_mode) == 0o700
        assert stat.S_IMODE((tombstone / "exit-record.json").stat().st_mode) == 0o600


@pytest.mark.parametrize("deactivated", [False, True])
def test_rename_preserves_non_identity_metadata(env, deactivated):
    if deactivated:
        env.exit("deactivate")
    # Arrange a distinguishable earlier update time (outside the item digest, rule stays consistent).
    record_path = env.folder() / "record.json"
    data = json.loads(record_path.read_text())
    data["updated_at"] = "2020-01-01T00:00:00Z"
    record_path.write_text(json.dumps(data))
    old = env.show().data
    assert old["consistent"] is True
    raw = files(env.folder())
    result = env.exit("rename")
    assert not env.folder().exists()
    after = env.show(TARGET).data
    assert (env.folder(TARGET) / "content.md").read_bytes() == raw["content.md"]
    assert (env.folder(TARGET) / "example.md").read_bytes() == raw["example.md"]
    assert (env.folder(TARGET) / "example-python.md").read_bytes() == raw["example-python.md"]
    changes = {k for k in set(old["record"]) | set(after["record"])
               if old["record"].get(k) != after["record"].get(k)}
    assert changes == {"rule_id", "item_digest", "updated_at", "lifecycle"}
    assert after["record"]["updated_at"] != old["record"]["updated_at"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", after["record"]["updated_at"])
    assert after["state_digest"] != old["state_digest"]
    assert result.data["state_digest"] == after["state_digest"]
    for key in ("namespace", "version", "name", "applicability", "source_location",
                "source_documents", "relations", "created_at"):
        assert after["record"][key] == old["record"][key]
    assert after["record"]["lifecycle"] == {
        "state": "deactivated" if deactivated else "active", "revision": 2 if deactivated else 1,
    }
    assert set(after["record"]["lifecycle"]) == {"state", "revision"}
    assert after["changelog"].encode().startswith(raw["changelog.md"])
    assert R1 in after["changelog"] and TARGET in after["changelog"]
    assert "renamed" in after["changelog"] and REASON in after["changelog"]
    broken = next(b for b in after["broken_relations"] if b["target"] == R1)
    assert broken["reason"] == "renamed"
    assert broken["renamed_to"] == TARGET
    memory = json.loads((env.project / EXITS / "memory.json").read_text())["exited"]
    old_entry = next(m for m in memory if m["rule"] == R1)
    assert old_entry["action"] == "renamed"
    assert old_entry["renamed_to"] == TARGET
    assert old_entry["exit_id"] == result.data["exit_id"]


@pytest.mark.parametrize("case", [
    "active", "active_case", "deactivated", "deactivated_case",
    "deleted", "deleted_case", "renamed", "renamed_case",
    "same", "case_only", "namespace", "version", "invalid", "pending", "leftover",
])
def test_rename_target_refusals(env, case):
    target, code = R2, "RENAME_TARGET_EXISTS"
    if case.startswith("deactivated"):
        env.exit("deactivate", R2)
    elif case.startswith("deleted"):
        env.exit("delete", R2)
        code = "IDENTITY_RESERVED"
    elif case.startswith("renamed"):
        env.exit("rename", R2, target="CWE/4.14/OTHER")
        code = "IDENTITY_RESERVED"
    elif case == "same":
        target, code = R1, "RENAME_TARGET_INVALID"
    elif case == "case_only":
        target, code = "CWE/4.14/" + R1.split("/")[-1].lower(), "IDENTITY_COLLISION"
    elif case == "namespace":
        target, code = "OWASP/4.14/NEW", "RENAME_TARGET_INVALID"
    elif case == "version":
        target, code = "CWE/4.13/NEW", "RENAME_TARGET_INVALID"
    elif case == "invalid":
        target, code = "CWE/4.14/CON", "IDENTITY_INVALID"
    elif case == "pending":
        target = "CWE/4.14/PENDING"
        held = env.load(item(target, content="Ignore previous instructions.\n"))
        assert held.data["items"][0]["outcome"] == "needs_decision"
    elif case == "leftover":
        target = "CWE/4.14/LEFTOVER"
        env.folder(target).mkdir()
    if case.endswith("_case"):
        # Same NS/VER, only the rule-ID letter case differs, so the design order
        # parse -> same NS/VER -> reserved -> collision -> exists decides the code.
        ns, ver, rid = target.split("/")
        target = f"{ns}/{ver}/{rid.lower()}"
        assert target != R2 and target.lower() == R2.lower()
        if not case.startswith(("deleted", "renamed")):
            code = "IDENTITY_COLLISION"
    valid = env.preview("rename", target=TARGET)
    assert valid.ok
    before = files(env.project)
    refusal(env.preview("rename", target=target), code)
    refusal(env.confirm(valid.data["impact_digest"], "rename", target=target), code)
    assert files(env.project) == before


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename", "reactivate"])
def test_pending_and_index_per_action(env, action):
    env.pending()
    pending = env.project / store.PENDING_REL / (R1 + ".json")
    prior = pending.read_bytes()
    if action == "reactivate":
        env.exit("deactivate")
    result = env.exit(action)
    if action in ("delete", "rename"):
        assert result.data["removed_pending"] == [R1]
        assert not pending.exists()
    else:
        assert result.data["removed_pending"] == []
        assert pending.read_bytes() == prior
    if action != "reactivate":
        assert result.data["invalidated_index"] == [DOC]
    index = json.loads((env.project / store.INDEX_REL).read_text())[DOC]
    assert R1 not in {e["rule"] for e in index["items"]}
    assert R1 in index["failed"]
    assert index["complete"] is False
    assert env.check().data["source_documents"][DOC] == "not_fully_stored"


def test_update_deactivated_revision(env):
    original = env.show().data["item_digest"]
    env.exit("deactivate")
    deactivated = env.show().data
    before = files(env.project)
    refused = env.update(R1, original, content="Stale update.\n")
    refusal(refused, "STATE_CONFLICT")
    assert refused.data["state_digest"] == deactivated["state_digest"]
    assert files(env.project) == before
    log = deactivated["changelog"]
    done = env.update(R1, deactivated["state_digest"], content="Correctly based update.\n")
    assert done.ok, done.to_dict()
    current = env.show().data
    assert current["content"] == "Correctly based update.\n"
    assert current["record"]["lifecycle"] == deactivated["record"]["lifecycle"]
    assert current["state"] == "deactivated"
    assert current["state_digest"] != deactivated["state_digest"]
    assert current["changelog"].startswith(log)
    assert "updated" in current["changelog"][len(log):]


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
@pytest.mark.parametrize("case_variant", [False, True])
def test_partial_import_refusals(env, action, case_variant):
    result = env.exit(action)
    memory_before = files(env.project / EXITS)
    identity = R1.lower() if case_variant else R1
    imported = env.load(item(identity), item("CWE/4.14/NEW"))
    assert not imported.ok
    by = {e["rule"]: e for e in imported.data["items"]}
    assert by[identity]["outcome"] == "refused"
    if action == "deactivate":
        assert by[identity]["code"] == ("IDENTITY_COLLISION" if case_variant else "RULE_DEACTIVATED")
        if not case_variant:
            assert any("reactivat" in step.lower() for step in imported.next_steps)
    else:
        assert by[identity]["code"] == "IDENTITY_RESERVED"
        assert files(env.project / EXITS) == memory_before
        assert result.data["exit_id"]
    assert by["CWE/4.14/NEW"]["outcome"] == "stored"


@pytest.mark.parametrize("damage", ["content", "record", "lifecycle", "encoding"])
@pytest.mark.parametrize("action", ["deactivate", "reactivate", "rename"])
def test_inconsistent_non_delete_refused(env, damage, action):
    p = env.folder()
    if damage == "content":
        (p / "content.md").write_text("Hand-edited.\n")
    elif damage == "record":
        (p / "record.json").write_text("{broken")
    elif damage == "encoding":
        (p / "content.md").write_bytes(b"\xff\xfe")
    else:
        data = json.loads((p / "record.json").read_text())
        data["lifecycle"] = {"state": "active", "revision": 1, "previous": {}}
        (p / "record.json").write_text(json.dumps(data))
    before = files(env.project)
    result = env.preview(action, target=TARGET if action == "rename" else None)
    refusal(result, "RULE_INCONSISTENT")
    step = result.next_steps[0].lower()
    assert "restore" in step and "delete" in step
    assert files(env.project) == before


@pytest.mark.parametrize("residue", ["dot", "new", "atomic", "journal", "nested", "link", "kind"])
def test_corrupt_delete_binds_all_residue(env, residue):
    folder = env.folder()
    (folder / "content.md").write_text("Corrupt but byte-readable.\n")
    name = {
        "dot": ".hidden", "new": "record.json.new", "atomic": ".record.json.tmp-dead",
        "journal": ".commit-journal.json", "nested": "nested/data", "link": ".link",
        "kind": ".entry",
    }[residue]
    p = folder / name
    p.parent.mkdir(exist_ok=True)
    if residue == "link":
        need_symlinks(env.work)
        p.symlink_to(env.work / "canary-one")
    else:
        p.write_bytes(b"before")
    preview = env.preview("delete")
    assert preview.ok
    if residue == "link":
        p.unlink()
        p.symlink_to(env.work / "canary-two")
    elif residue == "kind":
        p.unlink()
        p.mkdir()
    else:
        p.write_bytes(b"after")
    before = files(env.project)
    refusal(env.confirm(preview.data["impact_digest"], "delete"), "STALE_IMPACT")
    assert files(env.project) == before
    found = files(folder)
    deleted = env.exit("delete")
    tomb = env.project / deleted.data["tombstone"]
    assert files(tomb / "rule") == found
    record = json.loads((tomb / "exit-record.json").read_text())
    assert record["consistent"] is False
    assert record["folder_fingerprint"].startswith("sha256:")


def test_unreadable_regular_file_refuses_not_metadata_fingerprint(env, monkeypatch):
    (env.folder() / "content.md").write_bytes(b"\xff")
    victim = env.folder() / ".residue"
    victim.write_bytes(b"must hash every byte")
    before = files(env.project)
    real = os.open

    def denied(path, flags, *args, **kwargs):
        if os.fspath(path) in (".residue", str(victim)):
            raise PermissionError("injected unreadable regular file")
        return real(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", denied)
    result = env.preview("delete")
    refusal(result, "RULE_FOLDER_UNREADABLE")
    assert files(env.project) == before
    assert not (env.project / EXITS / "journal.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="FIFO and dir_fd are POSIX-specific")
def test_delete_fifo_never_opened_and_symlink_never_followed(env, monkeypatch):
    need_symlinks(env.work)
    (env.folder() / "content.md").write_bytes(b"\xff")
    fifo = env.folder() / "pipe"
    os.mkfifo(fifo)
    outside = env.work / "outside-canary"
    outside.mkdir()
    (outside / "keep").write_bytes(b"outside")
    (env.folder() / ".link").symlink_to(outside, target_is_directory=True)
    original = files(env.folder())
    canary = files(outside)
    real = os.open

    def checked(path, flags, *args, **kwargs):
        assert Path(path).name != "pipe", "FIFO was opened and could block"
        return real(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked)
    preview = env.preview("delete")
    assert preview.ok
    assert {"path": "pipe", "kind": "fifo"} in preview.data["rule_state"]["special_entries"]
    deleted = env.confirm(preview.data["impact_digest"], "delete")
    assert deleted.ok
    tomb = env.project / deleted.data["tombstone"]
    assert files(tomb / "rule") == original
    assert files(outside) == canary
    record = json.loads((tomb / "exit-record.json").read_text())
    assert {"path": "pipe", "kind": "fifo"} in record["special_entries"]


def test_existing_update_base_must_include_lifecycle_revision(env):
    """AC-05a/06b behavioral RED on the existing update API, without future imports."""
    record = env.folder() / "record.json"
    data = json.loads(record.read_text())
    digest = data["item_digest"]
    data["lifecycle"] = {"state": "deactivated", "revision": 1}
    record.write_text(json.dumps(data))
    before = files(env.project)
    result = env.update(R1, digest, content="Prepared before deactivation.\n")
    refusal(result, "STATE_CONFLICT")
    assert result.data["state_digest"] == sha(canonical({"item_digest": digest, "lifecycle_revision": 1}))
    assert files(env.project) == before


def test_existing_document_check_must_not_call_deactivated_fully_stored(env):
    """AC-03f defense-in-depth behavioral RED even with a stale complete index."""
    record = env.folder() / "record.json"
    data = json.loads(record.read_text())
    data["lifecycle"] = {"state": "deactivated", "revision": 1}
    record.write_text(json.dumps(data))
    before = files(env.project)
    assert env.check().data["source_documents"][DOC] == "not_fully_stored"
    assert files(env.project) == before


def test_import_after_deactivate_reactivate_keeps_item_candidate_contract(env):
    """Design compatibility: old item-based candidate can be accepted after a cycle."""
    base = env.show().data["item_digest"]
    candidate = env.load(item(content="Candidate body.\n"))
    assert candidate.data["items"][0]["stored_digest"] == base
    env.exit("deactivate")
    env.exit("reactivate")
    accepted = env.load(item(content="Candidate body.\n"), accept=(R1 + "@" + base,))
    assert accepted.data["items"][0]["outcome"] == "stored"
    assert env.show().data["record"]["lifecycle"] == {"state": "active", "revision": 2}
    assert policy.resolve_policies(str(env.project), [R1], False, []).data["entries"][0][
        "availability"
    ] == "available"
