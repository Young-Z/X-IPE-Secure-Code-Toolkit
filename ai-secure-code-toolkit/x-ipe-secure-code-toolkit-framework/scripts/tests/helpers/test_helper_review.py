"""FEATURE-002-F Reviewer `helper` subject (AC-002F-03c, 03d, 03f, 03h, 08c; design §6)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

from helperhelp import (  # noqa: F401 - fixture reuse
    Flow,
    attempt,
    env,
    fake,
    flow,
    helper_run,
    henv,
    mod,
    state_of,
)

from x_ipe_secure_code.guard import service as guard


def refused(out, code, text):
    assert not out.ok and out.problems[0].code == code, out.to_text()
    assert text in out.problems[0].message, out.problems[0].message


# ---------- AC-002F-03c
def test_03c_batch_reviewer_helper_subjects(flow):
    vid = helper_run(flow.env)
    h1 = flow.submit(vid).data["helper"]
    h2 = flow.submit(vid).data["helper"]
    a = attempt(flow.env, vid, "reviewer", {"helpers": [h1, h2]})
    assert a.ok and a.data["extra"] == 0
    helpers = {h["id"]: h for h in state_of(flow.env, vid)["helpers"]}
    subjects = [
        {
            "type": "helper",
            "id": hid,
            "phase": "pre_execution",
            "result": res,
            "helper_digest": helpers[hid]["helper_digest"],
            "basis": "goal, read scope, judgement basis, script and sample adequacy fit the check",
        }
        for hid, res in ((h1, "accepted"), (h2, "rejected"))
    ]
    doc = {
        "schema": "ai-secure-code-toolkit/reviewer-record/v1",
        "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
        "requirement": "Review each helper",
        "subjects": subjects,
        "attempt": a.data["attempt"],
        "reviewed_targets": [
            {"path": "src", "digest": state_of(flow.env, vid)["artifact"]["targets"][0]["digest"]}
        ],
    }
    from helperhelp import req

    out = guard.record_review(str(flow.root), vid, req(flow.env, doc))
    assert out.ok, out.to_text()
    stored = state_of(flow.env, vid)["reviews"][0]
    assert stored["attempt"] == a.data["attempt"] and [s["id"] for s in stored["subjects"]] == [h1, h2]
    assert {s["type"] for s in stored["subjects"]} == {"helper"}
    events = {h["id"]: [e["step"] for e in h["events"]] for h in state_of(flow.env, vid)["helpers"]}
    assert "reviewed" in events[h1] and "reviewed" in events[h2]
    rejected = [e for e in state_of(flow.env, vid)["evidence"] if (e.get("helper") or {}).get("id") == h2]
    assert any("rejected by the Reviewer" in e["summary"] for e in rejected)


def test_03c_subject_validation(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    refused(
        flow.review(vid, hid, subject={"helper_digest": "sha256:" + "0" * 64}),
        "REVIEW_INVALID",
        "not bound to the current helper",
    )
    refused(flow.review(vid, hid, subject={"phase": "later"}), "REVIEW_INVALID", "phase")
    refused(flow.review(vid, hid, subject={"id": "h-9-00000000"}), "REVIEW_INVALID", "another verification")
    refused(flow.review(vid, hid, subject={"result": "maybe"}), "REVIEW_INVALID", "result")
    refused(
        flow.review(vid, hid, subject={"phase": "post_run", "run": 1, "result_sha256": "sha256:" + "1" * 64}),
        "REVIEW_INVALID",
        "not a clean run",
    )


# ---------- AC-002F-03d
def test_03d_changed_helper_needs_new_review_and_grant(flow):
    vid, hid = flow.ready()
    script = flow.root / ".x-ipe/private/secure-code/guard" / vid / f"helpers/{hid}/script.py"
    script.chmod(0o644)
    script.write_text(script.read_text() + "# changed\n")
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.problems[0].code == "HELPER_NOT_EXECUTED" and out.data["reason_code"] == "helper_files_changed"
    new = flow.submit(vid, flow.request(vid, flow.generation(vid)))
    nid = new.data["helper"]
    out = flow.run(vid, nid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == "not_reviewed"
    assert flow.review(vid, nid).ok
    assert flow.run(vid, nid, flow.helper_attempt(vid)).data["reason_code"] == "not_granted"


# ---------- AC-002F-03f
def test_03f_state_wording_separates(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    assert flow.review(vid, hid).ok
    shown = mod("grant").show(str(flow.root), vid).data["helpers"][0]
    assert shown["state"] == "reviewed (accepted, not granted)"
    assert shown["review"] == "accepted (not permission to execute)" and shown["grant"] == "not granted"
    assert shown["execution"] == "not executed" and "executable" not in str(shown).lower()
    assert flow.grant(vid).ok
    shown = mod("grant").show(str(flow.root), vid).data["helpers"][0]
    assert shown["state"] == "granted (not executed)" and shown["grant"].startswith("granted hg-1")
    concluded = guard.conclude(str(flow.root), vid)
    assert concluded.ok
    md = (flow.root / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.md").read_text()
    section = md.split("## Temporary helper checks", 1)[1]
    assert "accepted (not permission to execute)" in section and "executable" not in section.lower()


# ---------- AC-002F-03h
def test_03h_one_post_run_decision_per_run(flow):
    vid, hid, out = flow.executed()
    assert out.data["outcome"] == "clean"
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    refused(
        flow.review(vid, hid, phase="post_run", run=1), "REVIEW_INVALID", "post-run decision already recorded"
    )


def test_03h_stale_acceptance_target_changed_after_run(flow, monkeypatch):
    vid, hid, out = flow.executed()
    assert out.data["outcome"] == "clean"
    (flow.root / "src" / "config" / "app.yaml").write_text("name: app\ndebug: true\n")
    from x_ipe_secure_code.guard import targets

    calls = []
    real = targets.observe
    monkeypatch.setattr(targets, "observe", lambda root, rel: calls.append(rel) or real(root, rel))
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    assert calls == ["src"]  # computed once by record_review; the hook reads no target itself
    h = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)
    assert h["runs"][0]["acceptance"]["state"] == "stale"
    items = [e for e in state_of(flow.env, vid)["evidence"] if (e.get("helper") or {}).get("id") == hid]
    assert all(e["method_status"] == "failed" for e in items)
    assert any("not valid when recorded" in e["summary"] for e in items)


# ---------- AC-002F-08c
def test_08c_earlier_run_helper_not_accepted(flow):
    vid1, hid1 = flow.ready()
    vid2 = helper_run(flow.env)
    refused(_review_foreign(flow, vid2, hid1, vid1), "REVIEW_INVALID", "belongs to another verification")
    out = flow.run(vid2, hid1, None)
    assert out.problems[0].code == "HELPER_UNKNOWN" and "another verification" in out.problems[0].message
    granted = flow.grant(vid2, helpers=[hid1])
    assert granted.problems[0].code == "HELPER_UNKNOWN"


def _review_foreign(flow, vid, hid, origin):
    helper = next(h for h in state_of(flow.env, origin)["helpers"] if h["id"] == hid)
    a = attempt(flow.env, vid, "reviewer", {"na": ["policy:CWE/4.14/CWE-89"]})
    from helperhelp import req

    doc = {
        "schema": "ai-secure-code-toolkit/reviewer-record/v1",
        "invocation": {"host": "h", "agent": "a", "read_only": True},
        "requirement": "r",
        "reviewed_targets": [],
        "attempt": a.data["attempt"],
        "subjects": [
            {
                "type": "helper",
                "id": hid,
                "phase": "pre_execution",
                "result": "accepted",
                "helper_digest": helper["helper_digest"],
            }
        ],
    }
    return guard.record_review(str(flow.root), vid, req(flow.env, doc))
