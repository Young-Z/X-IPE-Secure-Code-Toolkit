"""FEATURE-003-A Reviewer records with `adoption` subjects (AC-003A-04a…04d, 04f, 04h)."""

from __future__ import annotations

import pytest
from cphelp import R2, Env, adoption, by_id, sug


@pytest.fixture
def cp(project, tmp_path):
    env = Env(project, tmp_path)
    env.cid = env.opened()
    assert env.suggest(env.cid, [sug("S1"), sug("S2", rule=R2, files=("src/util.py",), severity="low")]).ok
    return env


# ---------- AC-003A-04a


def test_04a_shared_envelope_with_adoption_subjects(cp):
    results = ("adopted", "partial", "not_adopted", "not_applicable", "cannot_verify")
    for i, res in enumerate(results):
        r = cp.review(cp.cid, [adoption("S1", res, f"basis {i}")])
        assert r.ok, r.to_text()
        assert r.data["seq"] == i + 1 and r.data["completeness"] == [] and r.data["wrong_version"] == []
    stored = cp.state(cp.cid)["reviews"][0]
    assert stored["invocation"] == {
        "host": "github-copilot",
        "agent": "copilot-reviewer",
        "read_only": True,
        "invoked_at": "2026-10-21T10:00:00Z",
        "declared": True,
    }
    assert stored["requirement"].startswith("Check adoption")
    assert stored["reviewed_targets"] == [{"path": "src/register.py", "digest": cp.digest("src/register.py")}]
    assert stored["subjects"] == [{"type": "adoption", "id": "S1", "result": "adopted", "basis": "basis 0"}]
    assert stored["reviewed_at"] == "2026-10-21T10:05:00Z" and stored["seq"] == 1 and stored["recorded_at"]
    bad = cp.review(cp.cid, [{**adoption("S1"), "result": "confirmed"}])
    assert bad.problems[0].code == "REVIEW_INVALID"
    wrong_type = cp.review(cp.cid, [{**adoption("S1"), "type": "finding"}])
    assert wrong_type.problems[0].code == "REVIEW_INVALID"


# ---------- AC-003A-04b


@pytest.mark.parametrize(
    "subject,fragment",
    [
        ({"type": "adoption", "id": "S1", "result": "adopted"}, "basis"),
        ({"type": "adoption", "id": "S1", "result": "not_adopted", "basis": ""}, "basis"),
        ({"type": "adoption", "id": "S1", "basis": "   "}, "basis"),
        (adoption("S9"), "unknown suggestion"),
    ],
)
def test_04b_subject_without_basis_or_unknown_refuses_record(cp, subject, fragment):
    result = cp.review(cp.cid, [adoption("S2"), subject], files=["src/register.py", "src/util.py"])
    assert result.problems[0].code == "REVIEW_INVALID" and fragment in result.problems[0].message
    assert cp.state(cp.cid)["reviews"] == []


def test_04b_duplicate_subject_refused(cp):
    result = cp.review(cp.cid, [adoption("S1"), adoption("S1")])
    assert result.problems[0].code == "REVIEW_INVALID" and cp.state(cp.cid)["reviews"] == []


# ---------- AC-003A-04c


def test_04c_absent_marker_and_missing_bound_file(cp):
    (cp.project / "src" / "util.py").unlink()
    ok = cp.review(cp.cid, [adoption("S2", "not_applicable", "util removed")], files=["src/util.py"])
    assert ok.ok and cp.state(cp.cid)["reviews"][0]["reviewed_targets"] == [
        {"path": "src/util.py", "digest": "absent"}
    ]
    assert ok.data["wrong_version"] == []
    missing = cp.review(cp.cid, [adoption("S1"), adoption("S2")], files=["src/register.py"])
    assert missing.problems[0].code == "REVIEW_INVALID" and "src/util.py" in missing.problems[0].message
    assert len(cp.state(cp.cid)["reviews"]) == 1


def test_04c_reviewed_path_must_be_manifest_member(cp):
    result = cp.review(cp.cid, [adoption("S1")], files=["src/register.py", "README.md"])
    assert result.problems[0].code == "REVIEW_INVALID" and "README.md" in result.problems[0].message


# ---------- AC-003A-04d


@pytest.mark.parametrize("key", ["suggestions", "artifacts", "manifest", "scope", "stage", "scope_id"])
def test_04d_reviewer_has_no_extra_authority(cp, key):
    result = cp.review(cp.cid, [adoption("S1")], **{key: []})
    assert result.problems[0].code == "REVIEW_AUTHORITY" and key in result.problems[0].message
    assert "no extra authority" in result.problems[0].message and cp.state(cp.cid)["reviews"] == []


@pytest.mark.parametrize("key", ["attempt", "usage"])
def test_04d_no_attempt_or_usage_for_copilot(cp, key):
    result = cp.review(cp.cid, [adoption("S1")], **{key: "a1"})
    assert result.problems[0].code == "REVIEW_INVALID" and key in result.problems[0].message


# ---------- AC-003A-04f


@pytest.mark.parametrize(
    "over,warning",
    [
        ({"invocation": {"agent": "a", "read_only": True, "invoked_at": "t"}}, "invocation.host is missing"),
        ({"invocation": {"host": "h", "read_only": True, "invoked_at": "t"}}, "invocation.agent is missing"),
        ({"invocation": {"host": "h", "agent": "a", "invoked_at": "t"}}, "invocation.read_only is not true"),
        ({"invocation": {"host": "h", "agent": "a", "read_only": True}}, "invocation.invoked_at is missing"),
        ({"requirement": ""}, "requirement is missing"),
        ({"reviewed_targets": []}, "reviewed_targets is missing"),
        ({"subjects": []}, "subjects is missing"),
        ({"subjects": [{"type": "adoption", "id": "S1", "basis": "b"}]}, "subjects[0].result is missing"),
    ],
)
def test_04f_incomplete_record_kept_but_invalid(cp, over, warning):
    subjects = over.pop("subjects", [adoption("S1")])
    result = cp.review(cp.cid, subjects, files=["src/register.py"], **over)
    assert result.ok and warning in result.data["completeness"]
    assert result.data["valid"] is False and "will not count" in result.next_steps[0]
    assert cp.state(cp.cid)["reviews"][0]["completeness"] == result.data["completeness"]
    cp.report(cp.cid)
    data = cp.result_json(cp.cid, 1)
    assert data["reviews"][0]["valid"] is False and warning in data["reviews"][0]["reasons"]
    assert by_id(data)["S1"]["state"] == "not_reviewed"
    assert warning in cp.report_md(cp.cid, 1)


def test_04f_missing_digest_list_does_not_refuse_coverage(cp):
    result = cp.review(cp.cid, [adoption("S1")], files=[])
    assert result.ok and "reviewed_targets is missing" in result.data["completeness"]


# ---------- AC-003A-04h


def test_04h_wrong_version_at_recording(cp):
    doc_digest = cp.digest("src/register.py")
    (cp.project / "src" / "register.py").write_text("edited before the record arrived\n")
    result = cp.review(
        cp.cid,
        [adoption("S1"), adoption("S2", "adopted", "util fine")],
        reviewed_targets=[
            {"path": "src/register.py", "digest": doc_digest},
            {"path": "src/util.py", "digest": cp.digest("src/util.py")},
        ],
    )
    assert result.ok and result.data["wrong_version"] == ["src/register.py"]
    assert result.data["valid"] is False
    cp.report(cp.cid)
    data = cp.result_json(cp.cid, 1)
    s = by_id(data)
    assert s["S1"]["state"] == "not_reviewed" and s["S2"]["state"] == "adopted"
    review = data["reviews"][0]
    assert "wrong version: src/register.py" in review["reasons"]
    assert {"id": "S1", "reason": "wrong version of src/register.py"} in review["not_counted"]
    assert review["counted"] == ["S2"]
    assert "wrong version: src/register.py" in cp.report_md(cp.cid, 1)


def test_04h_absent_given_for_existing_file_is_wrong_version(cp):
    result = cp.review(
        cp.cid, [adoption("S2")], reviewed_targets=[{"path": "src/util.py", "digest": "absent"}]
    )
    assert result.ok and result.data["wrong_version"] == ["src/util.py"]
