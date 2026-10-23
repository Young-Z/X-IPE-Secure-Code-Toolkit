"""FEATURE-003-A suggestions (AC-003A-03d…03g) and closed collaborations (06d)."""

from __future__ import annotations

import json

import pytest
from cphelp import R2, R3, TOKEN, Env, adoption, sug


@pytest.fixture
def cp(project, tmp_path):
    return Env(project, tmp_path)


def test_03d_batch_recorded_with_all_fields(cp):
    cid = cp.opened()
    result = cp.suggest(
        cid,
        [
            sug("S1"),
            sug("S2", rule=R2, files=("src/register.py", "src/util.py"), severity="medium", stage="refactor"),
        ],
    )
    assert result.ok, result.to_text()
    assert result.data["recorded"] == ["S1", "S2"] and result.data["batch"] == 1
    stored = cp.state(cid)["suggestions"]
    assert [s["id"] for s in stored] == ["S1", "S2"]
    s2 = stored[1]
    assert s2["rule"] == R2 and s2["files"] == ["src/register.py", "src/util.py"]
    assert s2["location"] == "register(), line 2" and s2["action"].startswith("Use a parameterized")
    assert (
        s2["reason"] == "User input reaches SQL" and s2["severity"] == "medium" and s2["stage"] == "refactor"
    )
    assert stored[0]["stage"] == "implementation" and s2["batch"] == 1 and s2["recorded_at"]
    assert cp.suggest(cid, [sug("S3", severity="critical")]).data["batch"] == 2


def test_03d_deleted_manifest_member_is_bindable(cp):
    cid = cp.opened(artifacts=[{"path": "src/register.py"}, {"path": "src/gone.py", "change": "deleted"}])
    assert cp.suggest(cid, [sug("S1", files=("src/gone.py",))]).ok


@pytest.mark.parametrize(
    "bad,fragment",
    [
        (sug("S9", rule=R3), "adopted scope"),
        (sug("S9", files=()), "files"),
        (sug("S9", files=("README.md",)), "not a manifest member"),
        (sug("S9", location=""), "location"),
        (sug("S9", action="  "), "action"),
        (sug("S9", reason=None), "reason"),
        (sug("S1"), "already used"),
        (sug("S9", severity="severe"), "severity"),
        (sug("S9", stage="testing"), "stage"),
        (sug("bad id!"), "id"),
        (sug("S9", location="x" * 8193), "longer than"),
        ({**sug("S9"), "extra": 1}, "unknown fields"),
    ],
)
def test_03e_invalid_suggestion_refuses_whole_batch(cp, bad, fragment):
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1")]).ok
    before = cp.state(cid)
    result = cp.suggest(cid, [sug("S5"), bad])
    assert not result.ok and result.problems[0].code == "SUGGESTION_INVALID"
    assert fragment in result.problems[0].message and result.next_steps
    assert cp.state(cid) == before


def test_03e_duplicate_inside_one_batch(cp):
    cid = cp.opened()
    result = cp.suggest(cid, [sug("S1"), sug("S1")])
    assert result.problems[0].code == "SUGGESTION_INVALID" and cp.state(cid)["suggestions"] == []


def test_03e_empty_batch_refused(cp):
    cid = cp.opened()
    assert cp.suggest(cid, []).problems[0].code == "SUGGESTION_INVALID"


def test_03f_missing_severity_is_unknown(cp):
    cid = cp.opened()
    raw = sug("S1")
    del raw["severity"]
    assert cp.suggest(cid, [raw, sug("S2", severity=None)]).ok
    assert [s["severity"] for s in cp.state(cid)["suggestions"]] == ["unknown", "unknown"]
    cp.report(cid)
    attention = cp.result_json(cid, 1)["attention"]
    assert [a["id"] for a in attention] == ["S1", "S2"] and all(a["severity"] == "unknown" for a in attention)


def _masked_everywhere(cp, cid, label_fragment):
    state_text = json.dumps(cp.state(cid))
    report = cp.report(cid)
    assert report.ok, report.to_text()
    n = report.data["round"]
    for text in (state_text, json.dumps(cp.result_json(cid, n)), cp.report_md(cid, n)):
        assert TOKEN not in text and "[masked:credential.token]" in text
    md = cp.report_md(cid, n)
    assert label_fragment in md
    return cp.result_json(cid, n)


def test_03g_task_masked_and_labelled(cp):
    cid = cp.opened(task=f"Register users; token {TOKEN}")
    assert cp.state(cid)["masked"] == ["task"]
    data = _masked_everywhere(cp, cid, "Task (masked)")
    assert data["masked"] == ["task"]


@pytest.mark.parametrize("field", ["location", "action", "reason"])
def test_03g_suggestion_fields_masked_and_labelled(cp, field):
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1", **{field: f"use {TOKEN} here"})]).ok
    assert cp.state(cid)["suggestions"][0]["masked"] == [field]
    data = _masked_everywhere(cp, cid, f"masked: {field}")
    assert data["suggestions"][0]["masked"] == [field]
    assert cp.state(cid)["masked"] == []


@pytest.mark.parametrize("field", ["requirement", "basis"])
def test_03g_review_fields_masked_and_labelled(cp, field):
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1")]).ok
    if field == "requirement":
        result = cp.review(cid, [adoption("S1")], requirement=f"check {TOKEN}")
        label = "requirement"
    else:
        result = cp.review(cid, [adoption("S1", basis=f"seen {TOKEN}")])
        label = "subjects[0].basis"
    assert result.ok, result.to_text()
    assert cp.state(cid)["reviews"][0]["masked"] == [label]
    data = _masked_everywhere(cp, cid, f"masked: {label}")
    assert data["reviews"][0]["masked"] == [label]
    if field == "basis":
        assert "[masked:credential.token]" in data["suggestions"][0]["basis"]


def test_03g_unmasked_items_not_labelled(cp):
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1")]).ok
    cp.report(cid)
    md = cp.report_md(cid, 1)
    assert "masked:" not in md and "(masked)" not in md
    assert cp.result_json(cid, 1)["suggestions"][0]["masked"] == []


# ---------- AC-003A-06d


def test_06d_closed_collaboration_refuses_recording(cp):
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1")]).ok
    closed = cp.close(cid)
    assert closed.ok and closed.data["status"] == "closed"
    files = {
        name: (cp.project / "x-ipe-docs/secure-code/reports/copilot" / name).read_bytes()
        for name in cp.rounds(cid)
    }
    for result in (
        cp.suggest(cid, [sug("S2")]),
        cp.review(cid, [adoption("S1")]),
        cp.artifacts(cid, [{"path": "README.md"}]),
    ):
        assert result.problems[0].code == "COLLAB_CLOSED"
        assert "copilot open" in result.next_steps[0]
    assert cp.report(cid).ok and cp.report(cid).data["published"] is False
    assert {
        n: (cp.project / "x-ipe-docs/secure-code/reports/copilot" / n).read_bytes() for n in cp.rounds(cid)
    } == files
    assert cp.close(cid).problems[0].code == "COLLAB_CLOSED"
