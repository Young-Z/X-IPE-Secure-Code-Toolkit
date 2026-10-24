"""FEATURE-001-F Integration: Preset/tag exit-impact providers (anticipated 001-D plug-in, A9)
and broken-reference reporting including the bounded `knowledge links` extension (A10).

AC-001F-01d (preview part), 06a…06j and the planned outcome scenario. Concurrency uses the
delivered SECURE_CODE_TEST_PAUSE_AT hook and the 001-D lock probe helpers.
"""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import run_cli
from knowledge.exithelp import (
    R1,
    R2,
    R3,
    TARGET,
    cleanup,
    files,
    finish,
    need_symlinks,
    wait_blocked,
    wait_ready,
)
from presethelp import (
    FIXTURES,
    PRESETS,
    TAGS,
    PEnv,
    mod,
    pre_001f_outputs,
)

from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import scope

NOT_CHECKED = "not checked in this version"
ACTIONS = ["deactivate", "reactivate", "delete", "rename"]


@pytest.fixture
def env(project, tmp_path):
    result = PEnv(project, tmp_path)
    result.rules()
    return result


def code(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code


def fixtures(env):
    """Two Presets and two tags referencing R1, one of each not referencing it."""
    assert env.psave("alpha", [R1, R2]).ok
    assert env.psave("beta", [R1]).ok
    assert env.psave("gamma", [R2, R3]).ok
    assert env.tsave("t-one", [R1]).ok
    assert env.tsave("t-two", [R1, R3]).ok
    assert env.tsave("t-other", [R2]).ok


def names(impact, kind):
    return [i["name"] for i in impact[kind]["items"]]


def preview(env, action, rule=R1):
    target = TARGET if action == "rename" else None
    result = env.preview(action, rule, target=target)
    assert result.ok, result.to_dict()
    return result


# AC-001F-06a
@pytest.mark.parametrize("action", ACTIONS)
def test_preview_lists_exact_referencing_presets_tags(env, action):
    fixtures(env)
    if action == "reactivate":
        env.exit("deactivate", R1)
    before = files(env.project)
    result = preview(env, action)
    impact = result.data["impact"]
    assert names(impact, "presets") == ["alpha", "beta"]
    assert names(impact, "tags") == ["t-one", "t-two"]
    assert impact["presets"]["count"] == impact["tags"]["count"] == 2
    for kind, name in (("presets", "alpha"), ("tags", "t-one")):
        item = next(i for i in impact[kind]["items"] if i["name"] == name)
        file = env.preset_file(name) if kind == "presets" else env.tag_file(name)
        assert item["file_digest"] == mod("knowledge.catalog").file_digest(file.read_bytes())
        assert impact[kind]["unreadable"] == []
    assert impact["presets"] != NOT_CHECKED and impact["tags"] != NOT_CHECKED
    assert impact["reference_cache"]["count"] == 0  # superseded per AC-001E-07c — re-run
    text = result.to_text()
    assert "presets:" in text and "alpha" in text and "t-two" in text
    assert files(env.project) == before


# AC-001F-06b
def test_preview_empty_lists_reference_cache_not_checked(env):
    assert env.psave("gamma", [R2]).ok
    assert env.tsave("t-other", [R2]).ok
    result = preview(env, "deactivate")
    impact = result.data["impact"]
    for kind in ("presets", "tags"):
        assert impact[kind]["items"] == [] and impact[kind]["count"] == 0
        assert impact[kind]["unreadable"] == []
    assert impact["reference_cache"]["items"] == []  # superseded per AC-001E-07c — re-run
    # superseded per AC-001E-07c — re-run
    assert "(none)" in result.to_text() and NOT_CHECKED not in result.to_text()
    assert set(mod("knowledge.impact").UNSUPPORTED) == set()  # superseded per AC-001E-07c — re-run


# AC-001F-06c
@pytest.mark.parametrize("change", ["preset_add", "preset_change", "preset_remove",
                                    "tag_add", "tag_change", "tag_remove"])
def test_preset_or_tag_change_after_preview_confirm_stale(env, change):
    assert env.psave("alpha", [R1, R2]).ok
    assert env.tsave("t-one", [R1, R2]).ok
    shown = preview(env, "deactivate")
    {
        "preset_add": lambda: env.psave("new", [R1]),
        "preset_change": lambda: env.pupdate("alpha", rules=[R1], keep_summary=True),
        "preset_remove": lambda: env.pdelete("alpha"),
        "tag_add": lambda: env.tsave("t-new", [R1]),
        "tag_change": lambda: env.tupdate("t-one", [R1]),
        "tag_remove": lambda: env.tdelete("t-one"),
    }[change]()
    before = files(env.project)
    result = env.confirm(shown.data["impact_digest"])
    assert code(result) == "STALE_IMPACT"
    assert "preview again" in result.next_steps[0].lower()
    assert "presets" in result.data["impact"] and "tags" in result.data["impact"]
    assert files(env.project) == before
    assert env.show(R1).data["state"] == "active"


# AC-001F-06d
@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
def test_confirmed_exits_leave_preset_tag_files_identical(env, action):
    fixtures(env)
    before = {k: v for k, v in files(env.project).items()
              if k.startswith((PRESETS, TAGS))}
    env.exit(action)
    after = {k: v for k, v in files(env.project).items() if k.startswith((PRESETS, TAGS))}
    assert after == before


# AC-001F-06e
@pytest.mark.parametrize("action,reason", [
    ("deactivate", "deactivated"), ("delete", "deleted"), ("rename", "renamed"),
])
def test_broken_references_reported_never_substituted(env, action, reason):
    assert env.psave("alpha", [R1, R2]).ok
    assert env.tsave("t-one", [R1]).ok
    env.exit(action)
    shown = env.pshow("alpha")
    assert shown.ok, shown.to_dict()
    broken = shown.data["broken"]
    assert [(b["owner"], b["name"], b["target"], b["reason"]) for b in broken] == [
        ("preset", "alpha", R1, reason)]
    assert [r["rule"] for r in shown.data["rules"]] == [R1, R2]
    resolved = env.presolve("alpha")
    entry = next(e for e in resolved.data["entries"] if e["requested"] == R1)
    assert (entry["availability"], entry["reason"]) == ("missing", reason)
    tag = env.tshow("t-one")
    assert [(b["owner"], b["name"], b["target"], b["reason"]) for b in tag.data["broken"]] == [
        ("tag", "t-one", R1, reason)]
    if action == "rename":
        assert broken[0]["renamed_to"] == TARGET and tag.data["broken"][0]["renamed_to"] == TARGET
        assert entry["renamed_to"] == TARGET
    considered = [e["requested"] for e in resolved.data["entries"]]
    assert TARGET not in considered and TARGET not in [r["rule"] for r in shown.data["rules"]]
    assert TARGET not in env.preset_file("alpha").read_text()


def test_links_reports_broken_preset_tag_refs_and_unreadable(env, tmp_path):
    assert env.psave("alpha", [R1, R2]).ok
    assert env.psave("clean", [R2]).ok
    assert env.tsave("t-one", [R1]).ok
    env.exit("rename")
    (env.project / PRESETS / "bad.json").write_text("{")
    links = mod("knowledge.exit").links
    before = files(env.project)
    result = links(str(env.project))
    assert result.ok, result.to_dict()
    data = result.data
    assert list(data)[:5] == ["broken_relations", "scopes", "unreadable_sources", "unreadable_scopes",
                              "counts"]
    assert list(data)[-1] == "preset_tag_links"
    extension = data["preset_tag_links"]
    assert extension["presets"] == [{"owner": "preset", "name": "alpha", "target": R1, "reason": "renamed",
                                     "renamed_to": TARGET}]
    assert extension["tags"] == [{"owner": "tag", "name": "t-one", "target": R1, "reason": "renamed",
                                  "renamed_to": TARGET}]
    assert [(u["kind"], u["file"]) for u in extension["unreadable"]] == [("preset", "bad.json")]
    assert extension["counts"] == {"presets": 1, "tags": 1, "unreadable": 1}
    assert data["counts"] == {"broken_relations": len(data["broken_relations"]),
                              "scopes": len(data["scopes"])}
    assert result.next_steps == [
        "Repairing references is a separate, explicit decision by an authorized person"]
    assert files(env.project) == before
    need_symlinks(tmp_path)
    shutil.rmtree(env.project / TAGS)
    (tmp_path / "tags-elsewhere").mkdir()
    (env.project / TAGS).symlink_to(tmp_path / "tags-elsewhere", target_is_directory=True)
    linked = links(str(env.project))
    assert linked.ok, linked.to_dict()
    assert ("tag", "tags/") in [(u["kind"], u["file"]) for u in linked.data["preset_tag_links"]["unreadable"]]
    assert list((tmp_path / "tags-elsewhere").iterdir()) == []


# AC-001F-06e (DAO-007 (2a)): byte-identical links output without Preset/tag files
@pytest.mark.parametrize("case", ["absent", "empty", "dot_temp_only"])
def test_links_output_byte_identical_without_preset_tag_files(project, tmp_path, monkeypatch, case):
    def arrange(env):
        if case == "absent":
            shutil.rmtree(env.project / PRESETS)
            shutil.rmtree(env.project / TAGS)
        elif case == "dot_temp_only":
            (env.project / PRESETS / ".web-input.json.tmp").write_text("{partial")
            (env.project / TAGS / ".DS_Store").write_bytes(b"\0")
            (env.project / TAGS / "readme.txt").write_text("not a tag")

    out = pre_001f_outputs(PEnv(project, tmp_path), monkeypatch, before_links=arrange)
    assert out["links.json"] == (FIXTURES / "links.json").read_bytes()
    assert out["links.txt"] == (FIXTURES / "links.txt").read_bytes()


# AC-001F-06f
def test_unreadable_preset_tag_reported_and_bound_into_digest(env, tmp_path):
    assert env.psave("alpha", [R1]).ok
    (env.project / PRESETS / "bad.json").write_text("{")
    (env.project / TAGS / "broken.json").write_text("[]")
    need_symlinks(tmp_path)
    (tmp_path / "x.json").write_text("{}")
    (env.project / TAGS / "linked.json").symlink_to(tmp_path / "x.json")
    first = preview(env, "deactivate")
    impact = first.data["impact"]
    assert [u["file"] for u in impact["presets"]["unreadable"]] == ["bad.json"]
    assert "content_digest" in impact["presets"]["unreadable"][0]
    tag_unreadable = {u["file"]: u for u in impact["tags"]["unreadable"]}
    assert set(tag_unreadable) == {"broken.json", "linked.json"}
    assert "content_digest" not in tag_unreadable["linked.json"]
    assert impact["tags"]["items"] == [] and impact["tags"] != NOT_CHECKED
    (env.project / PRESETS / "bad.json").write_text("{ still broken")
    second = preview(env, "deactivate")
    assert second.data["impact_digest"] != first.data["impact_digest"]
    before = files(env.project)
    assert code(env.confirm(first.data["impact_digest"])) == "STALE_IMPACT"
    assert files(env.project) == before


# AC-001F-06f/06e/08a (code review TASK-069): a deeply nested file under 1 MiB is a finding, not a crash
def test_deeply_nested_preset_tag_files_are_unreadable_findings(env):
    assert env.psave("alpha", [R1]).ok
    assert env.tsave("t-one", [R1]).ok
    nested = "[" * 100_000
    (env.project / PRESETS / "deep.json").write_text(nested)
    (env.project / TAGS / "deep.json").write_text(nested)
    impact = preview(env, "deactivate").data["impact"]
    assert [i["name"] for i in impact["presets"]["items"]] == ["alpha"]
    assert [u["file"] for u in impact["presets"]["unreadable"]] == ["deep.json"]
    assert [u["file"] for u in impact["tags"]["unreadable"]] == ["deep.json"]
    linked = mod("knowledge.exit").links(str(env.project))
    assert linked.ok, linked.to_dict()
    assert sorted((u["kind"], u["file"]) for u in linked.data["preset_tag_links"]["unreadable"]) == [
        ("preset", "deep.json"), ("tag", "deep.json")]
    listed = mod("knowledge.presets").list_presets(str(env.project))
    assert listed.ok, listed.to_dict()
    assert [p["name"] for p in listed.data["presets"]] == ["alpha"]
    assert [i["file"] for i in listed.data["invalid"]] == ["deep.json"]
    tags = mod("knowledge.tags").list_tags(str(env.project))
    assert tags.ok, tags.to_dict()
    assert [t["name"] for t in tags.data["tags"]] == ["t-one"]
    assert [i["file"] for i in tags.data["invalid"]] == ["deep.json"]


# AC-001F-06f/08a (closing review TASK-071): a non-UTF-8 file name (legal on Linux, kept by Git as raw bytes)
# is an invalid finding with a printable name, never an encoding crash in preview/confirm/links/list.
def test_non_utf8_file_name_is_invalid_finding_not_crash(env, monkeypatch):
    assert env.psave("alpha", [R1]).ok
    assert env.tsave("t-one", [R1]).ok
    bad = b"\xff.json".decode("utf-8", "surrogateescape")
    durable = mod("knowledge.durable")
    real = durable.listdir

    def listdir(dfd):
        entries = real(dfd)
        names = [n for n, _ in entries]
        if "alpha.json" in names or "t-one.json" in names:
            entries = sorted([*entries, (bad, entries[0][1])], key=lambda x: x[0])
        return entries

    monkeypatch.setattr(durable, "listdir", listdir)
    shown = "\\xff.json"
    first = preview(env, "deactivate")
    impact = first.data["impact"]
    assert [i["name"] for i in impact["presets"]["items"]] == ["alpha"]
    assert [u["file"] for u in impact["presets"]["unreadable"]] == [shown]
    assert [u["file"] for u in impact["tags"]["unreadable"]] == [shown]
    json.dumps(first.to_dict(), ensure_ascii=False).encode("utf-8")
    linked = mod("knowledge.exit").links(str(env.project))
    assert linked.ok, linked.to_dict()
    assert sorted((u["kind"], u["file"]) for u in linked.data["preset_tag_links"]["unreadable"]) == [
        ("preset", shown), ("tag", shown)]
    listed = mod("knowledge.presets").list_presets(str(env.project))
    assert listed.ok and [i["file"] for i in listed.data["invalid"]] == [shown], listed.to_dict()
    tags = mod("knowledge.tags").list_tags(str(env.project))
    assert tags.ok and [i["file"] for i in tags.data["invalid"]] == [shown], tags.to_dict()
    assert env.confirm(first.data["impact_digest"]).ok


def _write_args(env, kind, op):
    project = str(env.project)
    if kind == "tag":
        return ["tag", "save", "--project", project, "--request", env.treq("t-new", [R1]), "--confirmed",
                "--json"]
    if op == "create":
        return ["preset", "save", "--project", project, "--request", env.preq("new", [R1]), "--confirmed",
                "--json"]
    if op == "update":
        req = env.req({"schema": "ai-secure-code-toolkit/preset-request/v1", "rules": [R1, R2],
                       "keep_summary": True})
        return ["preset", "update", "alpha", "--project", project, "--request", req, "--digest",
                env.pdigest("alpha"), "--confirmed", "--json"]
    return ["preset", "delete", "alpha", "--project", project, "--digest", env.pdigest("alpha"),
            "--confirmed", "--json"]


def _race(env, kind, op, first):
    """Run one Preset/tag write and one exit confirmation in both lock orders (no deadlock)."""
    if op == "update":
        assert env.psave("alpha", [R2]).ok
    elif op == "delete":
        assert env.psave("alpha", [R1]).ok
    shown = preview(env, "deactivate")
    write_args = _write_args(env, kind, op)
    lock = env.project / store.LOCK_REL
    barrier = env.work / f"{kind}-{op}-{first}"
    holder = contender = None
    try:
        if first == "write":
            holder = env.spawn(write_args,
                               SECURE_CODE_TEST_PAUSE_AT=f"{kind}_write_locked={barrier}")
            wait_ready(holder, barrier)
            probe = env.work / f"probe-{kind}-{op}"
            contender = env.spawn(env.cli_args("deactivate", shown.data["impact_digest"]), probe=probe)
        else:
            holder = env.spawn(env.cli_args("deactivate", shown.data["impact_digest"]),
                               SECURE_CODE_TEST_PAUSE_AT=f"exit_locked={barrier}")
            wait_ready(holder, barrier)
            probe = env.work / f"probe-{kind}-{op}"
            contender = env.spawn(write_args, probe=probe)
        wait_blocked(contender, probe, lock)
        barrier.with_suffix(".go").touch()
        return finish(holder), finish(contender)
    finally:
        cleanup(*[p for p in (holder, contender) if p is not None])


# AC-001F-06g
@pytest.mark.parametrize("kind", ["preset", "tag"])
@pytest.mark.parametrize("first", ["write", "exit"])
def test_preset_and_tag_save_serialized_with_exit_confirm(env, kind, first):
    holder, contender = _race(env, kind, "create", first)
    created = env.preset_file("new") if kind == "preset" else env.tag_file("t-new")
    if first == "write":
        assert holder["ok"] is True, holder
        assert contender["ok"] is False and contender["problems"][0]["code"] == "STALE_IMPACT"
        assert env.show(R1).data["state"] == "active"
        assert created.is_file()
    else:
        assert holder["ok"] is True, holder
        assert contender["ok"] is False and contender["problems"][0]["code"] == "REFERENCES_INVALID"
        assert contender["data"]["references"][0]["reason"] == "deactivated"
        assert not created.exists()


# AC-001F-06i
@pytest.mark.parametrize("op", ["create", "update", "delete"])
@pytest.mark.parametrize("first", ["write", "exit"])
def test_preset_write_and_exit_confirm_serialized_no_deadlock(env, op, first):
    before_scopes = files(env.project / scope.SCOPES_REL)
    holder, contender = _race(env, "preset", op, first)
    write, exit_result = (holder, contender) if first == "write" else (contender, holder)
    if first == "write":
        assert write["ok"] is True, write
        assert exit_result["problems"][0]["code"] == "STALE_IMPACT"
        assert env.show(R1).data["state"] == "active"
    else:
        assert exit_result["ok"] is True, exit_result
        assert env.show(R1).data["state"] == "deactivated"
        if op == "delete":
            assert write["ok"] is True and not env.preset_file("alpha").exists()
        else:
            assert write["ok"] is False and write["problems"][0]["code"] == "REFERENCES_INVALID"
            assert write["data"]["references"][0]["reason"] == "deactivated"
    assert files(env.project / scope.SCOPES_REL) == before_scopes


# AC-001F-06h
def test_deactivate_reactivate_restores_availability_file_unchanged(env):
    assert env.psave("alpha", [R1, R2]).ok
    original = env.preset_file("alpha").read_bytes()
    env.exit("deactivate")
    assert env.pshow("alpha").data["status"] == "partial"
    env.exit("reactivate")
    shown = env.pshow("alpha")
    rules = {r["rule"]: r for r in shown.data["rules"]}
    assert rules[R1]["availability"] == "available" and shown.data["broken"] == []
    assert shown.data["status"] == "complete"
    assert env.presolve("alpha").data["status"] == "complete"
    assert env.preset_file("alpha").read_bytes() == original


# AC-001F-06j
def test_pre_upgrade_preview_stale_once_then_repreview(env, monkeypatch):
    assert env.psave("alpha", [R1]).ok
    saved = env.save()
    assert saved.ok, saved.to_dict()
    impact = mod("knowledge.impact")
    # superseded per AC-001E-07c — re-run
    delivered = tuple(p for p in impact.PROVIDERS if p.kind not in ("presets", "tags", "reference_cache"))
    assert [p.kind for p in delivered] == ["relations", "scopes", "guard_runs", "copilot_collaborations",
                                           "pending_decisions", "document_index"]
    with monkeypatch.context() as old:
        old.setattr(impact, "PROVIDERS", delivered)
        old.setattr(impact, "UNSUPPORTED", ("presets", "tags", "reference_cache"))
        before_upgrade = preview(env, "deactivate")
        assert before_upgrade.data["impact"]["presets"] == NOT_CHECKED
    kept = env.dependent_bytes()
    before = files(env.project)
    stale = env.confirm(before_upgrade.data["impact_digest"])
    assert code(stale) == "STALE_IMPACT"
    assert "preview again" in stale.next_steps[0].lower()
    assert files(env.project) == before
    assert env.show(R1).data["state"] == "active"
    again = preview(env, "deactivate")
    assert again.data["impact_digest"] != before_upgrade.data["impact_digest"]
    assert names(again.data["impact"], "presets") == ["alpha"]
    assert env.confirm(again.data["impact_digest"]).ok
    assert env.dependent_bytes() == kept
    assert env.scope_path(saved.data["scope_id"]).is_file()


# Planned outcome scenario (delivery check only; stakeholder outcome not measured)
def test_outcome_scenario_end_to_end(env, monkeypatch):
    assert env.psave("web-input", [R1, R2], query_intent="injection rules for HTTP input",
                     applicability_summary="Web request handlers").ok
    original = env.preset_file("web-input").read_bytes()
    assert env.tsave("injection", [R1, R2]).ok
    assert env.preset_file("web-input").read_bytes() == original
    proposal = env.presolve("web-input")
    saved = env.pscope_save("web-input", env.pdecisions(proposal))
    assert saved.ok, saved.to_dict()
    diff = env.recompute([R1, R2, R3])
    assert env.preset_file("web-input").read_bytes() == original
    assert env.recompute_confirm([R1, R2, R3], diff.data["recompute_digest"], keep_summary=True).ok
    renamed = "CWE/4.14/CWE-89-NEW"
    first = env.preview("rename", R2, target=renamed)
    assert names(first.data["impact"], "presets") == ["web-input"]
    assert names(first.data["impact"], "tags") == ["injection"]
    updated = env.preset_file("web-input").read_bytes()
    assert env.confirm(first.data["impact_digest"], "rename", R2, target=renamed).ok
    assert env.preset_file("web-input").read_bytes() == updated
    shown = env.pshow("web-input")
    assert shown.data["broken"][0]["reason"] == "renamed"
    assert shown.data["broken"][0]["renamed_to"] == renamed
    links = run_cli(["knowledge", "links", "--project", str(env.project), "--json"], env.trust)
    extension = json.loads(links.stdout)["data"]["preset_tag_links"]
    assert {(p["name"], p["reason"]) for p in extension["presets"]} == {("web-input", "renamed")}
