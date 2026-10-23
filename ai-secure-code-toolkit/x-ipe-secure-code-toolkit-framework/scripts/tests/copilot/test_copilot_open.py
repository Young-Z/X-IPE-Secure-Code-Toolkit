"""FEATURE-003-A open and artifact updates: scope precondition (AC-003A-02*) and artifacts (03a-03c, 03i)."""

from __future__ import annotations

import os

import pytest
from cphelp import PRIVATE, R1, R2, R3, Env

from x_ipe_secure_code.copilot import manifest
from x_ipe_secure_code.copilot import service as copilot

SELECT_STEP = (
    "Resolve, select and confirm Policies with the Framework skill (secure-code policy resolve, "
    "then secure-code scope save), then pass its scope_id"
)
MAINTAIN_STEP = (
    "Knowledge maintenance is needed: an authorized Maintainer imports or fixes Local rules with the "
    "Framework skill, then a scope is confirmed"
)
PARTIAL_STEP = "Re-propose and confirm a new scope (secure-code policy resolve, scope save), then open again"
posix = pytest.mark.skipif(os.name == "nt", reason="symbolic links need POSIX in these tests")


@pytest.fixture
def cp(project, tmp_path):
    return Env(project, tmp_path)


def _nothing_opened(cp):
    assert cp.private_entries() == [] and cp.rounds("") == []


# ---------- AC-003A-02


def test_02a_maintenance_needed_opens_nothing(cp):
    scope = cp.save_scope([R1])
    cp.change_rule(R1, "Changed body.\n")
    result = cp.open(scope_id=scope)
    assert not result.ok and result.problems[0].code == "MAINTENANCE_NEEDED"
    assert result.next_steps == [MAINTAIN_STEP]
    assert result.data == {"adopted": [], "needs_reconfirmation": [R1], "missing": []}
    _nothing_opened(cp)


def test_02b_partial_scope_refused_with_lists(cp):
    scope = cp.save_scope([R1, R2, R3])
    cp.change_rule(R2, "Changed.\n")
    cp.remove_rule(R3)
    result = cp.open(scope_id=scope)
    assert result.problems[0].code == "SCOPE_PARTIAL" and result.next_steps == [PARTIAL_STEP]
    assert result.data == {"adopted": [R1], "needs_reconfirmation": [R2], "missing": [R3]}
    _nothing_opened(cp)


def test_02c_scope_and_rule_digests_recorded(cp):
    cid = cp.opened()
    scope = cp.state(cid)["scope"]
    assert scope["scope_id"] == cp.scope and [a["rule"] for a in scope["adopted"]] == [R1, R2]
    assert all(a["state_digest"].startswith("sha256:") for a in scope["adopted"])
    opened = cp.open()
    assert opened.data["scope_id"] == cp.scope and opened.data["adopted_rules"] == [R1, R2]
    report = cp.report(cid)
    data = cp.result_json(cid, 1)
    assert data["scope"]["scope_id"] == cp.scope
    assert [(a["rule"], a["state_digest"]) for a in data["scope"]["adopted"]] == [
        (a["rule"], a["state_digest"]) for a in scope["adopted"]
    ]
    md = cp.report_md(cid, 1)
    assert cp.scope in md and all(a["state_digest"] in md for a in scope["adopted"])
    assert report.ok


@pytest.mark.parametrize("scope_id", [None, ""])
def test_02e_no_scope_is_select_and_confirm(cp, scope_id):
    over = {"scope_id": scope_id} if scope_id is not None else {}
    doc_scope = cp.open(**over) if scope_id is not None else _open_without_scope(cp)
    assert doc_scope.problems[0].code == "SCOPE_REQUIRED" and doc_scope.next_steps == [SELECT_STEP]
    assert "maint" not in doc_scope.next_steps[0].lower()
    _nothing_opened(cp)


def _open_without_scope(cp):
    import json

    from cphelp import S_OPEN

    doc = {"schema": S_OPEN, "stage": "design", "task": "t", "artifacts": [{"path": "docs/design.md"}]}
    path = cp.tmp / "noscope.json"
    path.write_text(json.dumps(doc))
    return copilot.open_collaboration(str(cp.project), str(path))


def test_02e_unknown_scope_is_select_and_confirm(cp):
    result = cp.open(scope_id="sha256:" + "0" * 64)
    assert result.problems[0].code == "SCOPE_NOT_FOUND" and result.next_steps == [SELECT_STEP]
    _nothing_opened(cp)


def test_not_initialized_project_refused(tmp_path):
    from cphelp import S_OPEN

    root = tmp_path / "plain"
    root.mkdir()
    req = tmp_path / "r.json"
    req.write_text(f'{{"schema": "{S_OPEN}"}}')
    result = copilot.open_collaboration(str(root), str(req))
    assert result.problems[0].code == "PROJECT_NOT_INITIALIZED" and "secure-code init" in result.next_steps[0]


# ---------- AC-003A-03a…03c


def test_03a_collaboration_and_manifest_recorded(cp):
    (cp.project / "docs" / "sub").mkdir()
    (cp.project / "docs" / "sub" / "flow.md").write_text("flow\n")
    result = cp.open(
        stage="design",
        task="Change the registration design",
        artifacts=[
            {"path": "src/register.py", "change": "modified"},
            {"path": "src/new.py", "change": "deleted"},
            {"path": "src/util.py", "change": "renamed", "old_path": "src/helpers.py"},
            {"path": "docs", "change": "modified"},
            {"path": "README.md"},
        ],
    )
    assert result.ok, result.to_text()
    cid = result.data["collaboration_id"]
    assert copilot.COLLAB_ID.fullmatch(cid)
    state = cp.state(cid)
    assert state["stage"] == "design" and state["task"] == "Change the registration design"
    assert state["status"] == "open" and state["collaboration_id"] == cid
    assert [(a["path"], a["kind"], a["change"]) for a in state["artifacts"]] == [
        ("src/register.py", "file", "modified"),
        ("src/new.py", "file", "deleted"),
        ("src/util.py", "file", "renamed"),
        ("docs", "dir", "modified"),
        ("README.md", "file", "unspecified"),
    ]
    m = state["manifest"]
    assert m["src/register.py"]["digest"] == cp.digest("src/register.py")
    assert m["src/new.py"]["digest"] is None and m["src/new.py"]["change"] == "deleted"
    assert m["src/util.py"]["old_path"] == "src/helpers.py" and m["src/util.py"]["digest"]
    assert m["src/helpers.py"]["change"] == "renamed_away" and m["src/helpers.py"]["digest"] is None
    for rel in ("docs/design.md", "docs/api.md", "docs/sub/flow.md"):
        assert m[rel]["digest"] == cp.digest(rel) and m[rel]["source"] == "docs"
    assert m["README.md"]["change"] == "unspecified"
    assert result.data["manifest"]["docs/sub/flow.md"] == cp.digest("docs/sub/flow.md")


@pytest.mark.parametrize(
    "over,code",
    [
        ({"artifacts": []}, "ARTIFACTS_REQUIRED"),
        ({"artifacts": None}, "ARTIFACTS_REQUIRED"),
        ({"artifacts": [{"path": "."}]}, "WHOLE_PROJECT_REFUSED"),
        ({"artifacts": [{"path": "./"}]}, "WHOLE_PROJECT_REFUSED"),
        ({"whole_project": True}, "WHOLE_PROJECT_REFUSED"),
    ],
)
def test_03b_explicit_artifacts_required(cp, over, code):
    result = cp.open(**over)
    assert result.problems[0].code == code
    assert result.next_steps and "name the changed artifact" in result.next_steps[0].lower()
    _nothing_opened(cp)


@pytest.mark.parametrize(
    "entry,fragment",
    [
        ({"path": "missing.py"}, "missing.py"),
        ({"path": "../outside.py"}, "../outside.py"),
        ({"path": "docs", "change": "deleted"}, "docs"),
        ({"path": "docs", "change": "renamed", "old_path": "old-docs"}, "docs"),
        ({"path": "src/register.py", "change": "deleted"}, "src/register.py"),
        ({"path": ".x-ipe/private/secure-code"}, ".x-ipe/private/secure-code"),
        ({"path": "x-ipe-docs/secure-code/reports"}, "x-ipe-docs/secure-code/reports"),
    ],
)
def test_03c_invalid_artifact_refused_naming_path(cp, entry, fragment):
    result = cp.open(artifacts=[entry])
    assert not result.ok and result.problems[0].code in ("TARGET_INVALID", "REQUEST_INVALID")
    assert fragment in result.problems[0].message and result.next_steps
    _nothing_opened(cp)


def test_03c_folder_deleted_or_renamed_message_names_individual_files(cp):
    result = cp.open(artifacts=[{"path": "docs", "change": "renamed", "old_path": "old"}])
    assert "individual files" in result.next_steps[0]


@posix
def test_03c_symbolic_link_refused(cp):
    os.symlink("register.py", cp.project / "src" / "link.py")
    result = cp.open(artifacts=[{"path": "src/link.py"}])
    assert result.problems[0].code == "TARGET_INVALID" and "src/link.py" in result.problems[0].message
    _nothing_opened(cp)


@posix
def test_03a_links_inside_folder_listed_not_bindable(cp):
    os.symlink("design.md", cp.project / "docs" / "alias.md")
    result = cp.open(artifacts=[{"path": "docs", "change": "modified"}])
    assert result.ok
    assert result.data["not_bindable"] == [
        {"path": "docs/alias.md", "reason": "symbolic link (not followed)"}
    ]
    assert "docs/alias.md" not in cp.state(result.data["collaboration_id"])["manifest"]


def test_03c_artifact_update_refusals(cp):
    cid = cp.opened(artifacts=[{"path": "docs", "change": "modified"}, {"path": "src/register.py"}])
    assert (
        cp.artifacts(cid, [{"path": "nowhere.py", "change": "modified"}]).problems[0].code == "TARGET_INVALID"
    )
    (cp.project / "docs" / "design.md").unlink()
    (cp.project / "docs" / "api.md").unlink()
    (cp.project / "docs").rmdir()
    folder = cp.artifacts(cid, [{"path": "docs", "change": "deleted"}])
    assert folder.problems[0].code == "TARGET_INVALID" and "docs" in folder.problems[0].message
    assert "individual files" in folder.next_steps[0]
    assert cp.artifacts(cid, [{"path": "."}]).problems[0].code == "WHOLE_PROJECT_REFUSED"
    assert cp.artifacts(cid, []).problems[0].code == "ARTIFACTS_REQUIRED"


def test_manifest_too_large_refused(cp, monkeypatch):
    monkeypatch.setattr(manifest, "MAX_MANIFEST_FILES", 2)
    result = cp.open(artifacts=[{"path": "docs"}, {"path": "src/register.py"}])
    assert result.problems[0].code == "MANIFEST_TOO_LARGE" and "narrower" in result.next_steps[0]
    _nothing_opened(cp)
    cid = cp.opened(artifacts=[{"path": "src/register.py"}])
    assert cp.artifacts(cid, [{"path": "docs"}]).problems[0].code == "MANIFEST_TOO_LARGE"


def test_context_paths_recorded_read_only(cp):
    cid = cp.opened(context=[{"path": "README.md"}])
    assert cp.state(cid)["context"] == [
        {"path": "README.md", "kind": "file", "digest": cp.digest("README.md")}
    ]
    assert "README.md" not in cp.state(cid)["manifest"]
    clash = cp.open(context=[{"path": "src/register.py"}])
    assert clash.problems[0].code == "ROLE_CONFLICT"


def test_request_shape_errors(cp):
    assert cp.open(stage="requirements").problems[0].code == "REQUEST_INVALID"
    assert cp.open(task="").problems[0].code == "REQUEST_INVALID"
    assert cp.open(extra=1).problems[0].code == "REQUEST_INVALID"
    dup = cp.open(artifacts=[{"path": "src/util.py"}, {"path": "./src/util.py"}])
    assert dup.problems[0].code == "REQUEST_INVALID" and "twice" in dup.problems[0].message
    _nothing_opened(cp)


# ---------- AC-003A-03i


def test_03i_artifact_update_records_changes(cp):
    cid = cp.opened(artifacts=[{"path": "src/register.py"}, {"path": "src/util.py"}, {"path": "docs"}])
    assert cp.suggest(
        cid,
        [
            {
                "id": "S1",
                "rule": R1,
                "files": ["src/register.py"],
                "location": "l",
                "action": "a",
                "reason": "r",
            },
            {"id": "S2", "rule": R2, "files": ["src/util.py"], "location": "l", "action": "a", "reason": "r"},
            {"id": "S3", "rule": R2, "files": ["docs/api.md"], "location": "l", "action": "a", "reason": "r"},
        ],
    ).ok
    before = {s["id"]: s for s in cp.state(cid)["suggestions"]}
    (cp.project / "src" / "new.py").write_text("new\n")
    os.rename(cp.project / "src" / "util.py", cp.project / "src" / "utils.py")
    (cp.project / "docs" / "api.md").unlink()
    (cp.project / "src" / "register.py").write_text("changed\n")
    result = cp.artifacts(
        cid,
        [
            {"path": "src/new.py", "change": "added"},
            {"path": "src/utils.py", "change": "renamed", "old_path": "src/util.py"},
            {"path": "docs/api.md", "change": "deleted"},
            {"path": "src/register.py", "change": "modified"},
        ],
    )
    assert result.ok, result.to_text()
    m = cp.state(cid)["manifest"]
    assert m["src/new.py"] == {**m["src/new.py"], "change": "added", "digest": cp.digest("src/new.py")}
    assert m["src/utils.py"]["change"] == "renamed" and m["src/utils.py"]["old_path"] == "src/util.py"
    assert m["src/util.py"]["change"] == "renamed_away" and m["src/util.py"]["digest"] is None
    assert m["docs/api.md"]["change"] == "deleted" and m["docs/api.md"]["digest"] is None
    assert m["src/register.py"]["digest"] == cp.digest("src/register.py")
    assert all(m[p]["recorded_at"] for p in m)
    assert {s["id"]: s for s in cp.state(cid)["suggestions"]} == before
    assert cp.suggest(
        cid,
        [
            {
                "id": "S4",
                "rule": R1,
                "files": ["src/new.py", "src/utils.py"],
                "location": "l",
                "action": "a",
                "reason": "r",
            }
        ],
    ).ok
    assert [a["change"] for a in cp.state(cid)["artifacts"][-4:]] == [
        "added",
        "renamed",
        "deleted",
        "modified",
    ]


def test_03i_file_added_inside_folder_not_bindable_until_update(cp):
    cid = cp.opened(artifacts=[{"path": "docs"}])
    (cp.project / "docs" / "later.md").write_text("later\n")
    s = {"id": "S1", "rule": R1, "files": ["docs/later.md"], "location": "l", "action": "a", "reason": "r"}
    assert cp.suggest(cid, [s]).problems[0].code == "SUGGESTION_INVALID"
    assert cp.artifacts(cid, [{"path": "docs", "change": "modified"}]).ok
    assert cp.suggest(cid, [s]).ok


def test_unknown_or_malformed_collaboration_id(cp):
    for cid in ("cp-nope", "cp-20261021T101500Z-1a2b3c4d", "../x"):
        assert cp.show(cid).problems[0].code == "COLLAB_NOT_FOUND"
        assert cp.report(cid).problems[0].code == "COLLAB_NOT_FOUND"
        assert "copilot open" in cp.report(cid).next_steps[0]
    assert cp.private_entries() == []


def test_open_returns_next_step_and_scope_groups(cp):
    result = cp.open()
    assert result.ok and "copilot suggest" in result.next_steps[0]
    assert (cp.project / PRIVATE / result.data["collaboration_id"] / "state.json").is_file()
