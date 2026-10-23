"""FEATURE-001-F Integration: Preset store — save, read, update, delete, integrity and safety.

AC-001F-01a…01g, 02b…02e, 02g (write part), 02h…02k, 04f (list order), 08a, 08c, plus CLI
commands. Arrange real initialized projects with imported Local rules; Act the Preset services
(imported at Act) or the CLI; Assert files, outputs and byte-identical trees on refusals.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime

import pytest
from conftest import run_cli, tree_hashes
from knowledge.exithelp import R1, R2, R3, files, item, need_symlinks
from presethelp import CUSTOM, PRESETS, TAGS, PEnv, mod, unchanged_but_lock

from x_ipe_secure_code import atomic
from x_ipe_secure_code.knowledge import durable, store
from x_ipe_secure_code.policy import scope


@pytest.fixture
def env(project, tmp_path):
    result = PEnv(project, tmp_path)
    result.rules(custom=True)
    return result


def code(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code


# AC-001F-01a
def test_save_writes_one_file_fully_qualified_no_content(env):
    result = env.psave(rules=[R1, "CWE/CWE-89", CUSTOM])
    assert result.ok, result.to_dict()
    folder = env.project / PRESETS
    assert sorted(os.listdir(folder)) == ["web-input.json"]
    assert result.data["path"] == f"{PRESETS}/web-input.json"
    assert result.data["rule_count"] == 3
    assert result.data["file_digest"] == "sha256:" + hashlib.sha256(
        env.preset_file().read_bytes()).hexdigest()
    stored = json.loads(env.preset_file().read_text(encoding="utf-8"))
    assert stored["rules"] == [
        {"rule": CUSTOM, "source": "local"}, {"rule": R1, "source": "local"},
        {"rule": R2, "source": "local"},
    ]
    raw = env.preset_file().read_text(encoding="utf-8")
    for forbidden in ("content", "examples", "state_digest", "Rule CWE-79 body", "requirement"):
        assert forbidden not in raw, forbidden
    assert set(stored) == {"schema", "name", "rules", "query_intent", "applicability_summary",
                           "snapshot_at"}


# AC-001F-01b
@pytest.mark.parametrize("selector", [
    "injection", "tag:injection", "CWE/*", "CWE/4.14/CWE-79 or CWE-89", "CWE/4.14/CWE-7?",
])
def test_save_refuses_dynamic_selectors(env, selector):
    before = files(env.project)
    result = env.psave(rules=[R1, selector])
    assert code(result) == "REFERENCES_INVALID"
    refs = {r["requested"]: r for r in result.data["references"]}
    assert refs[selector]["reason"] == "dynamic_selector"
    assert result.next_steps
    unchanged_but_lock(before, files(env.project))


# AC-001F-01c
def test_save_stores_intent_summary_and_offset_snapshot(env):
    start = datetime.now().astimezone()
    result = env.psave(query_intent="injection rules for HTTP input",
                       applicability_summary="Web request handlers in Python services")
    assert result.ok, result.to_dict()
    stored = json.loads(env.preset_file().read_text(encoding="utf-8"))
    assert stored["query_intent"] == "injection rules for HTTP input"
    assert stored["applicability_summary"] == "Web request handlers in Python services"
    snapshot = datetime.fromisoformat(stored["snapshot_at"])
    assert snapshot.utcoffset() is not None
    assert start.replace(microsecond=0) <= snapshot <= datetime.now().astimezone()
    assert result.data["snapshot_at"] == stored["snapshot_at"]


def test_save_without_optional_fields_stores_nulls(env):
    assert env.psave().ok
    stored = json.loads(env.preset_file().read_text(encoding="utf-8"))
    assert stored["query_intent"] is None and stored["applicability_summary"] is None


# AC-001F-01d
def test_reads_resolve_preview_leave_preset_bytes_identical(env):
    assert env.psave(query_intent="intent", applicability_summary="summary").ok
    original = env.preset_file().read_bytes()
    snapshot_at = json.loads(original)["snapshot_at"]
    before = files(env.project)
    assert env.presets.list_presets(str(env.project)).ok
    assert env.pshow().ok
    assert env.presolve().ok
    preview = env.preview("deactivate", R1)
    assert preview.ok, preview.to_dict()
    assert env.preset_file().read_bytes() == original
    assert json.loads(env.preset_file().read_bytes())["snapshot_at"] == snapshot_at
    unchanged_but_lock(before, files(env.project))


# AC-001F-01e
def test_show_states_snapshot_meaning_and_current_availability(env):
    assert env.psave(rules=[R1, R2, R3]).ok
    original = env.preset_file().read_bytes()
    base = env.show(R1).data["state_digest"]
    assert env.update(R1, base, content="Updated after the snapshot.\n").ok
    env.exit("deactivate", R3)
    shown = env.pshow()
    assert shown.ok, shown.to_dict()
    data = shown.data
    assert data["snapshot_note"] == "last confirmed list change; does not freeze rule content"
    rules = {r["rule"]: r for r in data["rules"]}
    assert rules[R1]["availability"] == "available"
    assert rules[R1]["state_digest"] == env.show(R1).data["state_digest"] != base
    assert (rules[R3]["availability"], rules[R3]["reason"]) == ("missing", "deactivated")
    assert data["counts"] == {"available": 2, "missing": 1, "unclear": 0}
    assert data["status"] == "partial"
    assert env.preset_file().read_bytes() == original
    text = shown.to_text()
    assert "does not freeze rule content" in text and "not run" in text


# AC-001F-01f
@pytest.mark.parametrize("reason", ["not_found", "pending_decision", "inconsistent", "multiple_versions"])
def test_save_refuses_unavailable_reference_reasons(env, reason):
    ref = R1
    if reason == "not_found":
        ref = "CWE/4.14/CWE-1"
    elif reason == "pending_decision":
        held = env.load(item("CWE/4.14/CWE-798", content='password = "Zq8vLr2mNp4tXw9y"\n'))
        assert held.data["items"][0]["outcome"] == "needs_decision", held.to_dict()
        ref = "CWE/4.14/CWE-798"
    elif reason == "inconsistent":
        (env.folder(R1) / "content.md").write_text("tampered by hand\n")
    else:
        assert env.load(item("CWE/4.15/CWE-79")).ok
        ref = "CWE/CWE-79"
    before = files(env.project)
    result = env.psave(rules=[ref, R2])
    assert code(result) == "REFERENCES_INVALID"
    refs = {r["requested"]: r for r in result.data["references"]}
    assert refs[ref]["reason"] == reason
    if reason == "multiple_versions":
        assert {c["rule"] for c in refs[ref]["candidates"]} == {R1, "CWE/4.15/CWE-79"}
    assert R2 not in refs
    unchanged_but_lock(before, files(env.project))


# AC-001F-01g
def test_two_updates_show_current_only_no_history_files(env, monkeypatch):
    presets = env.presets
    assert env.psave().ok
    monkeypatch.setattr(presets, "_now", lambda: "2026-10-24T09:00:00+08:00")
    assert env.pupdate(rules=[R1], keep_summary=True).ok
    monkeypatch.setattr(presets, "_now", lambda: "2026-10-25T09:00:00+08:00")
    assert env.pupdate(rules=[R1, R3], applicability_summary="Now with path traversal").ok
    shown = env.pshow()
    assert [r["rule"] for r in shown.data["rules"]] == sorted([R1, R3])
    assert shown.data["snapshot_at"] == "2026-10-25T09:00:00+08:00"
    assert "history" not in json.dumps({k: v for k, v in shown.data.items() if k != "history_note"})
    note = shown.data["history_note"].lower()
    assert "no preset/tag change history" in note and "version control" in note
    assert "snapshot_at is not a history" in note
    assert sorted(os.listdir(env.project / PRESETS)) == ["web-input.json"]
    private = files(env.project / ".x-ipe/private/secure-code")
    assert not [k for k in private if "preset" in k.lower() or "backup" in k.lower()]


# AC-001F-02b
@pytest.mark.parametrize("op", ["save", "update", "delete"])
def test_writes_without_confirmed_refused(env, op):
    if op != "save":
        assert env.psave().ok
    before = files(env.project)
    if op == "save":
        result = env.psave("other", confirmed=False)
    elif op == "update":
        result = env.pupdate(rules=[R1], keep_summary=True, confirmed=False)
    else:
        result = env.pdelete(confirmed=False)
    assert code(result) == "CONFIRMATION_REQUIRED"
    assert "confirm" in result.next_steps[0].lower()
    assert files(env.project) == before


# AC-001F-02c
def test_membership_update_sets_snapshot_metadata_update_keeps_it(env, monkeypatch):
    presets = env.presets
    monkeypatch.setattr(presets, "_now", lambda: "2026-10-23T10:00:00+08:00")
    assert env.psave(query_intent="old intent", applicability_summary="old summary").ok
    monkeypatch.setattr(presets, "_now", lambda: "2026-10-23T11:00:00+08:00")
    meta = env.pupdate(query_intent="new intent", applicability_summary="new summary")
    assert meta.ok, meta.to_dict()
    assert meta.data["membership_changed"] is False
    stored = json.loads(env.preset_file().read_text())
    assert stored["snapshot_at"] == "2026-10-23T10:00:00+08:00"
    assert [r["rule"] for r in stored["rules"]] == [R1, R2]
    assert (stored["query_intent"], stored["applicability_summary"]) == ("new intent", "new summary")
    monkeypatch.setattr(presets, "_now", lambda: "2026-10-23T12:00:00+08:00")
    member = env.pupdate(rules=[R3, R1], keep_summary=True)
    assert member.ok, member.to_dict()
    assert member.data["membership_changed"] is True
    stored = json.loads(env.preset_file().read_text())
    assert [r["rule"] for r in stored["rules"]] == sorted([R1, R3])
    assert stored["snapshot_at"] == "2026-10-23T12:00:00+08:00"
    assert stored["query_intent"] == "new intent"


def test_update_refuses_rename(env):
    assert env.psave().ok
    before = files(env.project)
    path = env.req({"schema": "ai-secure-code-toolkit/preset-request/v1", "name": "renamed-preset",
                    "query_intent": "x"})
    result = env.presets.update_preset(str(env.project), "web-input", path, env.pdigest(), True)
    assert code(result) == "REQUEST_INVALID"
    assert "rename" in result.problems[0].message.lower()
    unchanged_but_lock(before, files(env.project))
    assert not env.preset_file("renamed-preset").exists()


# AC-001F-02d
def test_create_existing_identity_refused_incl_case_variant(env):
    assert env.psave().ok
    before = files(env.project)
    again = env.psave()
    assert code(again) == "PRESET_EXISTS"
    assert "update the existing preset or choose another name" in again.next_steps[0].lower()
    unchanged_but_lock(before, files(env.project))
    hand = env.project / PRESETS / "Other.json"
    hand.write_bytes(b"{}")
    before = files(env.project)
    variant = env.psave("other")
    assert code(variant) == "PRESET_EXISTS"
    unchanged_but_lock(before, files(env.project))


# AC-001F-02g (write part)
@pytest.mark.parametrize("name", ["CON", "lpt1", "a/b", "My_Preset"])
def test_save_identity_invalid_writes_nothing(env, name):
    before = files(env.project)
    result = env.psave(name)
    assert code(result) == "IDENTITY_INVALID"
    assert files(env.project) == before


def test_default_preset_identity_accepted_and_announced(env):
    result = env.psave("default")
    assert result.ok, result.to_dict()
    assert result.data["becomes_default"] is True
    assert env.preset_file("default").is_file()


# AC-001F-02e
def test_delete_removes_file_scope_records_identical_and_load(env):
    assert env.psave().ok
    proposal = env.presolve()
    saved = env.pscope_save("web-input", env.pdecisions(proposal))
    assert saved.ok, saved.to_dict()
    record = env.scope_path(saved.data["scope_id"]).read_bytes()
    deleted = env.pdelete()
    assert deleted.ok, deleted.to_dict()
    assert deleted.data["removed"] is True
    assert "unchanged" in deleted.data["note"]
    assert not env.preset_file().exists()
    assert env.scope_path(saved.data["scope_id"]).read_bytes() == record
    loaded = mod("policy.service").show_scope(str(env.project), saved.data["scope_id"])
    assert loaded.ok, loaded.to_dict()
    assert loaded.data["adopted_rules"] == [R1, R2]


# AC-001F-02h
@pytest.mark.parametrize("op", ["update", "delete"])
@pytest.mark.parametrize("digest", [None, "sha256:" + "0" * 64])
def test_update_delete_require_current_digest(env, op, digest):
    assert env.psave().ok
    current = env.pdigest()
    locks = env.lock_listing()
    before = files(env.project)
    if op == "update":
        result = env.pupdate(digest=digest, query_intent="changed")
    else:
        result = env.pdelete(digest=digest)
    assert code(result) == "STALE_DIGEST"
    assert result.data["current_digest"] == current
    assert files(env.project) == before
    assert env.lock_listing() == locks
    ok = env.pupdate(query_intent="changed") if op == "update" else env.pdelete()
    assert ok.ok, ok.to_dict()
    assert env.lock_listing() == locks


# AC-001F-02i
def test_membership_change_requires_summary_decision(env):
    assert env.psave(applicability_summary="original summary").ok
    before = files(env.project)
    missing = env.pupdate(rules=[R1])
    assert code(missing) == "SUMMARY_DECISION_REQUIRED"
    assert "summary" in missing.next_steps[0].lower()
    unchanged_but_lock(before, files(env.project))
    both = env.pupdate(rules=[R1], keep_summary=True, applicability_summary="x")
    assert code(both) == "REQUEST_INVALID"
    kept = env.pupdate(rules=[R1], keep_summary=True)
    assert kept.ok, kept.to_dict()
    assert kept.data["summary"] == "kept"
    assert json.loads(env.preset_file().read_text())["applicability_summary"] == "original summary"
    assert "kept" in kept.to_text()
    replaced = env.pupdate(rules=[R1, R2], applicability_summary="replacement")
    assert replaced.ok and replaced.data["summary"] == "replaced"
    assert json.loads(env.preset_file().read_text())["applicability_summary"] == "replacement"


# AC-001F-02j
@pytest.mark.parametrize("op", ["preset_save", "preset_update", "preset_delete",
                                "tag_save", "tag_update", "tag_delete"])
def test_write_refused_locked_when_knowledge_lock_held(env, monkeypatch, op):
    assert env.psave().ok
    assert env.tsave().ok
    monkeypatch.setitem(durable.DirLock.__init__.__kwdefaults__, "timeout", 0.3)
    pdigest, tdigest = env.pdigest(), env.tdigest()
    locks = env.lock_listing()
    before = files(env.project)
    fd = os.open(env.project / store.LOCK_REL, os.O_RDWR)
    try:
        atomic._lock(fd)
        if op == "preset_save":
            result = env.psave("other")
        elif op == "preset_update":
            result = env.pupdate(digest=pdigest, query_intent="x")
        elif op == "preset_delete":
            result = env.pdelete(digest=pdigest)
        elif op == "tag_save":
            result = env.tsave("other")
        elif op == "tag_update":
            result = env.tupdate(digest=tdigest)
        else:
            result = env.tdelete(digest=tdigest)
    finally:
        atomic._unlock(fd)
        os.close(fd)
    assert code(result) == "LOCKED"
    assert result.next_steps and "retry" in result.next_steps[0].lower()
    assert files(env.project) == before
    assert env.lock_listing() == locks


# AC-001F-02k
@pytest.mark.parametrize("where", ["file", "presets", "tags", "x-ipe-docs", "secure-code"])
def test_write_paths_with_links_refused(env, tmp_path, where):
    need_symlinks(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("outside content\n")
    project = env.project
    if where == "file":
        assert env.psave().ok
        digest = env.pdigest()
        real = env.preset_file()
        (outside / "web-input.json").write_bytes(real.read_bytes())
        real.unlink()
        real.symlink_to(outside / "web-input.json")
    elif where in ("presets", "tags"):
        rel = PRESETS if where == "presets" else TAGS
        shutil.rmtree(project / rel)
        (project / rel).symlink_to(outside, target_is_directory=True)
    else:
        rel = "x-ipe-docs" if where == "x-ipe-docs" else "x-ipe-docs/secure-code"
        moved = outside / "moved"
        shutil.move(str(project / rel), str(moved))
        (project / rel).symlink_to(moved, target_is_directory=True)
    outside_before = tree_hashes(outside)
    before = files(project)
    if where == "file":
        results = [env.pupdate(digest=digest, query_intent="x"), env.pdelete(digest=digest),
                   env.psave()]
    elif where == "tags":
        results = [env.tsave()]
    elif where == "presets":
        results = [env.psave()]
    else:
        results = [env.psave(), env.tsave()]
    for result in results:
        assert code(result) == "PATH_UNSAFE", result.to_dict()
    assert tree_hashes(outside) == outside_before
    unchanged_but_lock(before, files(project))


# AC-001F-08a
def test_invalid_or_linked_file_refused_others_work(env, tmp_path):
    assert env.psave().ok
    folder = env.project / PRESETS
    (folder / "broken.json").write_text("{")
    (folder / "wrong.json").write_text(json.dumps({"schema": "other", "name": "wrong"}))
    (folder / "mismatch.json").write_bytes(env.preset_file().read_bytes())
    need_symlinks(tmp_path)
    (tmp_path / "elsewhere.json").write_bytes(env.preset_file().read_bytes())
    (folder / "linked.json").symlink_to(tmp_path / "elsewhere.json")
    (folder / ".hidden.json").write_text("{}")
    (folder / "notes.txt").write_text("x")
    before = files(env.project)
    listed = env.presets.list_presets(str(env.project))
    assert listed.ok, listed.to_dict()
    assert [p["name"] for p in listed.data["presets"]] == ["web-input"]
    invalid = {i["file"]: i for i in listed.data["invalid"]}
    assert set(invalid) == {"broken.json", "wrong.json", "mismatch.json", "linked.json"}
    for entry in invalid.values():
        assert "version control" in entry["next_step"].lower() and "re-save" in entry["next_step"].lower()
    assert sorted(listed.data["ignored"]) == [".hidden.json", "notes.txt"]
    for name, expected in (("broken", "PRESET_INVALID"), ("wrong", "PRESET_INVALID"),
                           ("mismatch", "PRESET_INVALID"), ("linked", "PATH_UNSAFE")):
        shown = env.pshow(name)
        assert code(shown) == expected
        resolved = env.presolve(name)
        assert code(resolved) == expected
        assert "entries" not in resolved.data and "proposal_digest" not in resolved.data
    assert "version control" in env.pshow("broken").next_steps[0].lower()
    assert env.pshow().ok and env.presolve().ok
    unchanged_but_lock(before, files(env.project))


def test_invalid_or_linked_tag_file_refused_others_work(env, tmp_path):
    assert env.tsave().ok
    folder = env.project / TAGS
    (folder / "broken.json").write_text("[]")
    need_symlinks(tmp_path)
    (tmp_path / "t.json").write_bytes(env.tag_file().read_bytes())
    (folder / "linked.json").symlink_to(tmp_path / "t.json")
    listed = env.tags.list_tags(str(env.project))
    assert [t["name"] for t in listed.data["tags"]] == ["injection"]
    assert {i["file"] for i in listed.data["invalid"]} == {"broken.json", "linked.json"}
    assert code(env.tshow("broken")) == "TAG_INVALID"
    assert code(env.tshow("linked")) == "PATH_UNSAFE"
    assert env.tshow().ok


# AC-001F-08c
@pytest.mark.parametrize("point", ["temp_fsync", "replace", "dir_fsync"])
@pytest.mark.parametrize("kind", ["preset", "tag"])
def test_interrupted_write_previous_or_new_complete(env, point, kind):
    if kind == "preset":
        assert env.psave().ok
        old = env.preset_file().read_bytes()
        path = env.req({"schema": "ai-secure-code-toolkit/preset-request/v1", "rules": [R1, R3],
                        "keep_summary": True})
        args = ["preset", "update", "web-input", "--request", path, "--digest", env.pdigest()]
        target = env.preset_file()
    else:
        assert env.tsave().ok
        old = env.tag_file().read_bytes()
        path = env.treq(None, [R1, R3])
        args = ["tag", "update", "injection", "--request", path, "--digest", env.tdigest()]
        target = env.tag_file()
    proc = run_cli([*args, "--project", str(env.project), "--confirmed", "--json"], env.trust,
                   env_extra={"SECURE_CODE_TEST_FAIL_AT": f"{point}:{kind}_write"})
    out = json.loads(proc.stdout)
    assert out["ok"] is False and out["problems"][0]["code"] == "IO_ERROR", proc.stdout
    now = target.read_bytes()
    members = [r["rule"] for r in json.loads(now)["rules" if kind == "preset" else "members"]]
    if point == "dir_fsync":
        assert members == sorted([R1, R3])
    else:
        assert now == old
    assert not [n for n in os.listdir(target.parent) if n.endswith(".tmp")]


# AC-001F-04f (list order)
def test_list_name_sorted_every_call_with_summary(env):
    for name in ("zeta", "alpha", "mid"):
        assert env.psave(name, applicability_summary=f"summary of {name}").ok
    for _ in range(3):
        listed = env.presets.list_presets(str(env.project))
        assert [p["name"] for p in listed.data["presets"]] == ["alpha", "mid", "zeta"]
        assert [p["applicability_summary"] for p in listed.data["presets"]] == [
            "summary of alpha", "summary of mid", "summary of zeta"]
        assert {"rule_count", "status", "file_digest", "snapshot_at", "default"} <= set(
            listed.data["presets"][0])
        assert "rank" not in json.dumps(listed.data)


# A4 step 7 (review R-2): refused writes never create the store folders
def test_refused_requests_create_no_folder(env):
    shutil.rmtree(env.project / PRESETS)
    shutil.rmtree(env.project / TAGS)
    user = mod("auth.trust_store").resolve(env.work / "no-qualification")
    before = files(env.project)
    assert code(env.psave(rules=["CWE/4.14/NOPE"])) == "REFERENCES_INVALID"
    assert code(env.pupdate(digest="sha256:" + "0" * 64, query_intent="x")) == "PRESET_NOT_FOUND"
    assert code(env.tsave(paths=user)) == "NOT_AUTHORIZED"
    assert code(env.tsave(members=["CWE/4.14/NOPE"])) == "REFERENCES_INVALID"
    unchanged_but_lock(before, files(env.project))
    assert not (env.project / PRESETS).exists() and not (env.project / TAGS).exists()
    created = env.psave()
    assert created.ok and env.preset_file().is_file()


# Design CLI contract (Step 8)
def test_cli_preset_and_tag_commands(env):
    project = str(env.project)
    request = env.preq("web-input", [R1, R2], applicability_summary="web")
    saved = run_cli(["preset", "save", "--project", project, "--request", request, "--confirmed",
                     "--json"], env.trust)
    assert saved.returncode == 0, saved.stdout + saved.stderr
    data = json.loads(saved.stdout)["data"]
    text = run_cli(["preset", "show", "web-input", "--project", project], env.trust)
    assert text.returncode == 0 and text.stdout.startswith("preset show: OK")
    assert "does not freeze rule content" in text.stdout
    listed = json.loads(run_cli(["preset", "list", "--project", project, "--json"], env.trust).stdout)
    assert listed["data"]["presets"][0]["file_digest"] == data["file_digest"]
    resolved = json.loads(run_cli(["preset", "resolve", "web-input", "--project", project,
                                   "--language", "python", "--json"], env.trust).stdout)
    assert resolved["ok"] and resolved["data"]["preset"]["clue"] == f"preset:web-input@{data['file_digest']}"
    both = run_cli(["preset", "resolve", "web-input", "--default", "--project", project, "--json"],
                   env.trust)
    assert json.loads(both.stdout)["problems"][0]["code"] == "REQUEST_INVALID"
    tag = run_cli(["tag", "save", "--project", project, "--request", env.treq(), "--confirmed",
                   "--json"], env.trust)
    assert tag.returncode == 0, tag.stdout
    shown = run_cli(["tag", "show", "injection", "--project", project], env.trust)
    assert shown.stdout.startswith("tag show: OK") and "never change severity" in shown.stdout
    digest = json.loads(run_cli(["tag", "show", "injection", "--project", project, "--json"],
                                env.trust).stdout)["data"]["file_digest"]
    deleted = run_cli(["tag", "delete", "injection", "--project", project, "--digest", digest,
                       "--confirmed", "--json"], env.trust)
    assert json.loads(deleted.stdout)["ok"], deleted.stdout
    removed = run_cli(["preset", "delete", "web-input", "--project", project, "--digest",
                       data["file_digest"], "--confirmed", "--json"], env.trust)
    assert json.loads(removed.stdout)["data"]["removed"] is True
    assert not list((env.project / scope.SCOPES_REL).glob("*.json"))
