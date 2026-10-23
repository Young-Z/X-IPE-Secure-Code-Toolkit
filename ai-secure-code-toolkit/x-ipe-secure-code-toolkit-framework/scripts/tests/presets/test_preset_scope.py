"""FEATURE-001-F Integration: a Preset as 001-C scope input and the single Preset scope-save path.

AC-001F-04a…04c, 04e, 04g, 04i…04k, 09a, 09e, 09g; DAO-006 (1) parity of the copied 001-C save
sequence (review R-6) and the explicit default orchestration (review R-7).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil

import pytest
from knowledge.exithelp import R1, R2, R3, files, need_symlinks
from presethelp import (
    FIXTURE_NAMES,
    FIXTURES,
    PRESETS,
    FixedDateTime,
    PEnv,
    pre_001f_outputs,
    unchanged_but_lock,
)

from x_ipe_secure_code import atomic
from x_ipe_secure_code.knowledge import durable, store
from x_ipe_secure_code.policy import resolve, scope
from x_ipe_secure_code.policy import service as policy

PROPOSAL_KEYS = {"notices", "status", "mode", "library_size", "pending_count", "counts", "adopted",
                 "adoption", "proposal_digest", "entries"}
RECORD_KEYS = {"schema", "mode", "clues", "language_context", "adopted", "not_adopted", "artifact_scope",
               "confirmation_note", "created_at", "scope_id"}
REPAIR = "repair the default preset or choose another scope"
EXPLICIT = "apply all only if the user explicitly chooses it"
FORBIDDEN = ("is bound", "verified", "tamper-evident", "tamper evident", "still exists", "still matches",
             "structured field", "binding")


@pytest.fixture
def env(project, tmp_path):
    result = PEnv(project, tmp_path)
    result.rules()
    return result


def code(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code


def digest_of(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# AC-001F-04a
def test_preset_resolve_001c_contract_clue_and_unchanged_digest(env):
    assert env.psave(applicability_summary="Web handlers", query_intent="injection").ok
    stored = json.loads(env.preset_file().read_text())
    result = env.presolve()
    assert result.ok, result.to_dict()
    data = result.data
    assert PROPOSAL_KEYS <= set(data)
    assert data["mode"] == "clues" and data["adopted"] == []
    assert "nothing adopted yet" in data["adoption"]
    assert data["library_size"] == 3
    assert [e["requested"] for e in data["entries"]] == [R1, R2]
    direct = policy.resolve_policies(str(env.project), [R1, R2], False, ["python"])
    assert data["proposal_digest"] == direct.data["proposal_digest"]
    assert data["entries"] == direct.data["entries"]
    assert data["proposal_digest"] == resolve.proposal_digest("clues", data["entries"])
    preset = data["preset"]
    assert preset["name"] == "web-input" and preset["default"] is False
    assert preset["snapshot_at"] == stored["snapshot_at"]
    assert preset["applicability_summary"] == "Web handlers"
    assert preset["file_digest"] == digest_of(env.preset_file())
    assert preset["clue"] == f"preset:web-input@{preset['file_digest']}"
    assert "not part of the proposal digest" in preset["clue_note"]
    assert any(n["code"] == "PRESET_PROPOSED" for n in data["notices"])
    steps = " ".join(result.next_steps).lower()
    assert "preset scope-save web-input" in steps and "applicability summary" in steps


# AC-001F-04b
def test_preset_resolve_mixed_availability_file_unchanged(env):
    assert env.psave(rules=[R1, R2, R3]).ok
    original = env.preset_file().read_bytes()
    env.exit("delete", R2)
    assert env.update(R3, env.show(R3).data["state_digest"], content="Changed but available.\n").ok
    result = env.presolve()
    assert result.ok, result.to_dict()
    entries = {e["requested"]: e for e in result.data["entries"]}
    assert (entries[R2]["availability"], entries[R2]["reason"]) == ("missing", "deleted")
    assert entries[R3]["availability"] == "available"
    assert entries[R3]["source_evidence"]["state_digest"] == env.show(R3).data["state_digest"]
    assert result.data["status"] == "partial"
    assert env.preset_file().read_bytes() == original


# AC-001F-04c
def test_scope_save_clues_record_unaffected_by_later_preset_change_or_delete(env):
    assert env.psave().ok
    proposal = env.presolve()
    saved = env.pscope_save("web-input", env.pdecisions(proposal))
    assert saved.ok, saved.to_dict()
    path = env.scope_path(saved.data["scope_id"])
    record = json.loads(path.read_text())
    assert record["mode"] == "clues"
    assert record["clues"] == proposal.data["preset"]["clue"]
    assert {a["rule"]: a["state_digest"] for a in record["adopted"]} == {
        e["rule"]: e["source_evidence"]["state_digest"] for e in proposal.data["entries"]}
    original = path.read_bytes()
    assert env.pupdate(rules=[R1], keep_summary=True).ok
    assert path.read_bytes() == original
    assert env.pdelete().ok
    assert path.read_bytes() == original
    loaded = policy.show_scope(str(env.project), saved.data["scope_id"])
    assert loaded.ok and loaded.data["adopted_rules"] == [R1, R2]


# AC-001F-04e
def test_no_clues_default_proposed_highlighted_saved_as_clues(env):
    assert env.psave("default", [R1, R3], applicability_summary="Default scope").ok
    proposal = env.presolve(None)
    assert proposal.ok, proposal.to_dict()
    notice = next(n for n in proposal.data["notices"] if n["code"] == "DEFAULT_PRESET_PROPOSED")
    assert notice["highlight"] is True
    assert "because no clues were given" in notice["message"]
    assert proposal.data["preset"]["name"] == "default" and proposal.data["preset"]["default"] is True
    assert proposal.data["mode"] == "clues" and proposal.data["adopted"] == []
    assert not list((env.project / scope.SCOPES_REL).glob("*.json"))
    saved = env.pscope_save("default", env.pdecisions(proposal))
    assert saved.ok, saved.to_dict()
    record = json.loads(env.scope_path(saved.data["scope_id"]).read_text())
    assert record["mode"] == "clues"
    assert record["clues"].startswith("preset:default@sha256:")


def test_no_default_points_to_unchanged_apply_all(env):
    before = files(env.project)
    result = env.presolve(None)
    assert result.ok, result.to_dict()
    assert result.data["status"] == "no_default_preset"
    assert result.data["adopted"] == []
    assert "proposal_digest" not in result.data and "entries" not in result.data
    assert any("policy resolve --all" in s for s in result.next_steps)
    unchanged_but_lock(before, files(env.project))
    every = policy.resolve_policies(str(env.project), [], True, [])
    notice = next(n for n in every.data["notices"] if n["code"] == "APPLY_ALL_PROPOSED")
    assert notice["default_preset_exists"] is False


# AC-001F-04g
@pytest.mark.parametrize("case", ["malformed", "schema", "link", "all_missing"])
def test_unusable_default_refused_no_apply_all(env, tmp_path, case):
    target = env.preset_file("default")
    if case == "malformed":
        target.write_text("{")
    elif case == "schema":
        target.write_text(json.dumps({"schema": "other/v1", "name": "default"}))
    elif case == "link":
        need_symlinks(tmp_path)
        assert env.psave("elsewhere").ok
        target.symlink_to(env.preset_file("elsewhere"))
    else:
        assert env.psave("default", [R1]).ok
        env.exit("delete", R1)
    result = env.presolve(None)
    assert not result.ok, result.to_dict()
    expected = {"malformed": "PRESET_INVALID", "schema": "PRESET_INVALID", "link": "PATH_UNSAFE",
                "all_missing": "MAINTENANCE_NEEDED"}[case]
    assert result.problems[0].code == expected
    steps = " ".join(result.next_steps).lower()
    assert REPAIR in steps and EXPLICIT in steps
    assert result.data.get("mode") != "apply_all"
    if case == "all_missing":
        assert result.data["status"] == "maintenance_needed"
        assert result.data["entries"][0]["reason"] == "deleted"


# Review R-7: one read-only default orchestration that never builds Apply All itself
@pytest.mark.parametrize("case", ["absent", "valid", "link", "malformed", "all_missing"])
def test_default_orchestration_paths(env, tmp_path, monkeypatch, case):
    target = env.preset_file("default")
    if case == "valid":
        assert env.psave("default").ok
    elif case == "link":
        need_symlinks(tmp_path)
        (tmp_path / "x.json").write_text("{}")
        target.symlink_to(tmp_path / "x.json")
    elif case == "malformed":
        target.write_text("not json")
    elif case == "all_missing":
        assert env.psave("default", [R2]).ok
        env.exit("deactivate", R2)
    built = []
    real_build = resolve.build
    monkeypatch.setattr(resolve, "build", lambda lib, texts, apply_all, *a, **k: (
        built.append(apply_all), real_build(lib, texts, apply_all, *a, **k))[1])
    monkeypatch.setattr(policy, "resolve_policies", lambda *a, **k: pytest.fail("Apply All built"))
    before = files(env.project)
    result = env.presolve(None)
    assert True not in built
    unchanged_but_lock(before, files(env.project))
    if case == "absent":
        assert result.ok and result.data["status"] == "no_default_preset"
    elif case == "valid":
        assert result.ok and result.data["preset"]["name"] == "default"
    else:
        assert not result.ok


# AC-001F-04i
def test_generated_clue_and_lookalike_user_clue_is_ordinary(env):
    assert env.psave().ok
    proposal = env.presolve()
    assert proposal.data["preset"]["clue"] == "preset:web-input@" + digest_of(env.preset_file())
    shutil.rmtree(env.project / PRESETS)
    lookalike = "preset:ghost@sha256:" + "a" * 64
    path = env.req({
        "schema": scope.DECISIONS_SCHEMA, "mode": "clues", "considered": [R1],
        "proposal_digest": policy.resolve_policies(str(env.project), [R1], False, [])
        .data["proposal_digest"],
        "clues": lookalike, "language_context": [],
        "decisions": [{"ref": R1, "decision": "adopted", "state_digest": env.show(R1).data["state_digest"]}],
        "confirmation_note": "User confirmed",
    })
    saved = policy.save_scope(str(env.project), path, True)
    assert saved.ok, saved.to_dict()
    record = json.loads(env.scope_path(saved.data["scope_id"]).read_text())
    assert record["clues"] == lookalike
    assert not (env.project / PRESETS).exists()


# AC-001F-04j
@pytest.mark.parametrize("change", [("add", [R1, R2, R3]), ("remove", [R1])])
def test_membership_change_between_proposal_and_save_is_stale(env, change):
    assert env.psave().ok
    proposal = env.presolve()
    decisions = env.pdecisions(proposal)
    assert env.pupdate(rules=change[1], keep_summary=True).ok
    before = files(env.project)
    result = env.pscope_save("web-input", decisions)
    assert code(result) == "STALE_CONFIRMATION"
    assert not list((env.project / scope.SCOPES_REL).glob("*.json"))
    unchanged_but_lock(before, files(env.project))


def test_rule_content_change_between_proposal_and_save_is_stale(env):
    assert env.psave().ok
    proposal = env.presolve()
    decisions = env.pdecisions(proposal)
    assert env.update(R2, env.show(R2).data["state_digest"], content="Changed.\n").ok
    result = env.pscope_save("web-input", decisions)
    assert code(result) == "STALE_CONFIRMATION"
    assert not list((env.project / scope.SCOPES_REL).glob("*.json"))


# AC-001F-04k (known limit, asserted as behaviour)
@pytest.mark.parametrize("change", ["summary", "intent", "snapshot"])
def test_metadata_only_change_not_detected_known_limit(env, change, monkeypatch):
    assert env.psave(query_intent="intent", applicability_summary="summary").ok
    proposal = env.presolve()
    decisions = env.pdecisions(proposal)
    if change == "summary":
        assert env.pupdate(applicability_summary="changed summary").ok
    elif change == "intent":
        assert env.pupdate(query_intent="changed intent").ok
    else:
        monkeypatch.setattr(env.presets, "_now", lambda: "2030-01-01T00:00:00+00:00")
        diff = env.recompute([R1, R2])
        assert env.recompute_confirm([R1, R2], diff.data["recompute_digest"], reconfirm=True).ok
    assert digest_of(env.preset_file()) != proposal.data["preset"]["file_digest"]
    saved = env.pscope_save("web-input", decisions)
    assert saved.ok, saved.to_dict()
    record = json.loads(env.scope_path(saved.data["scope_id"]).read_text())
    assert {a["rule"]: a["state_digest"] for a in record["adopted"]} == {
        e["rule"]: e["source_evidence"]["state_digest"] for e in proposal.data["entries"]}
    assert record["clues"] == proposal.data["preset"]["clue"]


# AC-001F-09a
def test_pre_001f_fixtures_byte_identical(project, tmp_path, monkeypatch):
    out = pre_001f_outputs(PEnv(project, tmp_path), monkeypatch)
    for name in FIXTURE_NAMES:
        assert out[name] == (FIXTURES / name).read_bytes(), name
    record = json.loads(out["clues-record.json"])
    assert set(record) == RECORD_KEYS and scope.MODES == ("clues", "apply_all")
    assert scope.RECORD_SCHEMA == "ai-secure-code-toolkit/scope-record/v1"


# AC-001F-09e
def test_preset_scope_record_clues_mode_no_new_field_id_rule(env):
    assert env.psave().ok
    proposal = env.presolve()
    saved = env.pscope_save("web-input", env.pdecisions(proposal))
    assert saved.ok, saved.to_dict()
    record = json.loads(env.scope_path(saved.data["scope_id"]).read_text())
    assert set(record) == RECORD_KEYS
    assert record["mode"] == "clues"
    assert record["clues"] == proposal.data["preset"]["clue"]
    assert scope.with_id(record)["scope_id"] == record["scope_id"] == saved.data["scope_id"]
    assert scope.verify_record(record, record["scope_id"][7:]) == record
    assert saved.data["mode"] == "clues" and saved.data["preset"]["clue"] == record["clues"]


# AC-001F-09g
def test_provenance_only_clue_text_no_binding_claims(env):
    assert env.psave().ok
    proposal = env.presolve()
    saved = env.pscope_save("web-input", env.pdecisions(proposal))
    shown = policy.show_scope(str(env.project), saved.data["scope_id"])
    for result in (proposal, saved, shown):
        text = (result.to_text() + json.dumps(result.to_dict())).lower()
        for phrase in FORBIDDEN:
            assert phrase not in text, (result.command, phrase)
    assert "information-only" in proposal.data["preset"]["clue_note"]
    assert "not re-checked" in saved.data["preset"]["clue_note"]


def test_preset_scope_save_refuses_bad_requests(env):
    assert env.psave().ok
    proposal = env.presolve()
    before = files(env.project)
    unconfirmed = env.pscope_save("web-input", env.pdecisions(proposal), confirmed=False)
    assert code(unconfirmed) == "CONFIRMATION_REQUIRED"
    other = env.pscope_save("web-input", env.pdecisions(proposal, clue="preset:other@sha256:" + "a" * 64))
    assert code(other) == "DECISIONS_INVALID"
    assert "copy the clue exactly" in other.next_steps[0].lower()
    free = env.pscope_save("web-input", env.pdecisions(proposal, clue="registration change"))
    assert code(free) == "DECISIONS_INVALID"
    absent = env.pscope_save("missing-preset", env.pdecisions(
        proposal, clue="preset:missing-preset@sha256:" + "a" * 64))
    assert code(absent) == "PRESET_NOT_FOUND"
    unchanged_but_lock(before, files(env.project))


# Review R-6: parity of the copied 001-C save sequence
def _twin(env, tmp_path):
    copy = tmp_path / "twin project"
    shutil.copytree(env.project, copy, symlinks=True)
    return copy


def _freeze(env, monkeypatch):
    monkeypatch.setattr(policy, "datetime", FixedDateTime)
    monkeypatch.setattr(env.pscope, "datetime", FixedDateTime)


def test_scope_save_parity_with_001c_save(env, tmp_path, monkeypatch):
    assert env.psave().ok
    _freeze(env, monkeypatch)
    proposal = env.presolve()
    decisions = env.pdecisions(proposal)
    twin = _twin(env, tmp_path)
    direct = policy.save_scope(str(twin), decisions, True)
    via = env.pscope_save("web-input", decisions)
    assert direct.ok and via.ok, (direct.to_dict(), via.to_dict())
    assert via.data["scope_id"] == direct.data["scope_id"]
    assert (env.project / via.data["path"]).read_bytes() == (twin / direct.data["path"]).read_bytes()
    assert {k: v for k, v in via.data.items() if k != "preset"} == direct.data
    assert via.next_steps == direct.next_steps


@pytest.mark.parametrize("case", ["confirmation", "decisions_invalid", "stale", "locked", "path_unsafe"])
def test_scope_save_refusal_parity(env, tmp_path, monkeypatch, case):
    assert env.psave().ok
    proposal = env.presolve()
    decisions = env.pdecisions(proposal)
    confirmed = case != "confirmation"
    if case == "decisions_invalid":
        data = json.loads(open(decisions, encoding="utf-8").read())
        data["unexpected"] = True
        decisions = env.req(data)
    elif case == "stale":
        assert env.update(R1, env.show(R1).data["state_digest"], content="Changed.\n").ok
    elif case == "path_unsafe":
        need_symlinks(tmp_path)
        outside = tmp_path / "outside-scopes"
        outside.mkdir()
        shutil.rmtree(env.project / scope.SCOPES_REL, ignore_errors=True)
        (env.project / scope.SCOPES_REL).symlink_to(outside, target_is_directory=True)
    twin = _twin(env, tmp_path)
    fd = None
    if case == "locked":
        monkeypatch.setitem(durable.DirLock.__init__.__kwdefaults__, "timeout", 0.3)
        fd = os.open(env.project / store.LOCK_REL, os.O_RDWR)
        atomic._lock(fd)
        twin_fd = os.open(twin / store.LOCK_REL, os.O_RDWR)
        atomic._lock(twin_fd)
    try:
        direct = policy.save_scope(str(twin), decisions, confirmed)
        via = env.pscope_save("web-input", decisions, confirmed=confirmed)
    finally:
        if fd is not None:
            atomic._unlock(fd)
            os.close(fd)
            atomic._unlock(twin_fd)
            os.close(twin_fd)
    assert code(via) == code(direct)
    assert via.next_steps == direct.next_steps
    if case not in ("locked", "path_unsafe"):
        assert via.problems[0].message == direct.problems[0].message


def test_scope_save_parity_single_exit_exception(env, tmp_path, monkeypatch):
    assert env.psave(rules=[R1, R3]).ok
    _freeze(env, monkeypatch)
    proposal = env.presolve()
    decisions = env.pdecisions(proposal, skipped=(R3,))
    env.exit("deactivate", R3)
    twin = _twin(env, tmp_path)
    direct = policy.save_scope(str(twin), decisions, True)
    via = env.pscope_save("web-input", decisions)
    assert direct.ok and via.ok, (direct.to_dict(), via.to_dict())
    assert via.data["adopted_rules"] == direct.data["adopted_rules"] == [R1]
    assert via.data["not_adopted"] == direct.data["not_adopted"]
    assert (env.project / via.data["path"]).read_bytes() == (twin / direct.data["path"]).read_bytes()
