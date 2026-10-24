"""FEATURE-002-F "Temporary helper checks" report part (AC-002F-04p, 05c, 07e, 07f, 09a, 09c, 12a)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json

from helperhelp import (  # noqa: F401 - fixture reuse
    GUARD,
    RULE,
    env,
    fake,
    flow,
    helper_run,
    henv,
    mod,
    raw_record,
    state_of,
)

from x_ipe_secure_code.guard import report
from x_ipe_secure_code.guard import service as guard

REPORTS = "x-ipe-docs/secure-code/reports/guard"
TOKEN = "ghp_" + "e" * 36


def outputs(env, vid):
    assert guard.conclude(str(env["project"]), vid).ok
    raw = (env["project"] / REPORTS / f"{vid}.json").read_bytes()
    return json.loads(raw), (env["project"] / REPORTS / f"{vid}.md").read_text(), raw


def section(md):
    return md.split("## Temporary helper checks", 1)[1].split("\n## ", 1)[0]


# ---------- AC-002F-04p (report wording)
def test_04p_report_wording(flow):
    vid, hid = flow.ready()
    result, md, _ = outputs(flow.env, vid)
    text = section(md).lower()
    assert "recorded cooperative consent" in text and "never a security boundary" in text
    assert "enforced container limits are the security boundary" in text
    assert "recorded cooperative consent" in result["helpers"]["statement"].lower()


# ---------- AC-002F-05c
def test_05c_gap_entry_and_verdict(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    result, md, _ = outputs(flow.env, vid)
    entry = result["helpers"]["helpers"][0]
    assert entry["gap"] == "not reviewed"
    line = f"Gap: helper {hid} (check C1, goal: Detect debug: true in deployed YAML config): not reviewed"
    assert line in result["helpers"]["gaps"]
    assert report.md_text(line) in section(md)
    assert result["verdict"] == "cannot_confirm_pass"


def test_05c_uncovered_files_gap_line_md_and_json(flow):
    vid = helper_run(flow.env)
    flow.fake.set(auto={**flow.fake.control["auto"], "skip_scanned": ["src/config/db.yaml"]})
    vid, hid = flow.ready(vid)
    assert flow.run(vid, hid, flow.helper_attempt(vid)).data["uncovered_count"] == 1
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    result, md, _ = outputs(flow.env, vid)
    entry = result["helpers"]["helpers"][0]
    assert entry["uncovered"] == ["src/config/db.yaml"] and entry["uncovered_count"] == 1
    gap = next(g for g in result["helpers"]["gaps"] if "did not cover" in g)
    assert "src/config/db.yaml" in gap and "Guard does not check per-file coverage" in gap
    assert report.md_text(gap) in section(md)


# ---------- AC-002F-07e
def test_07e_same_entries_md_and_json(flow):
    vid, hid, out = flow.executed()
    result, md, _ = outputs(flow.env, vid)
    part = result["helpers"]
    entry = part["helpers"][0]
    body = section(md)
    for value in (
        entry["id"],
        entry["check"],
        entry["goal"],
        entry["script_sha256"],
        entry["grant"],
        entry["conformance"],
        entry["manifest"],
        entry["execution"],
        entry["marking"],
    ):
        assert report.md_text(value) in body, value
    for key in (
        "read_scope",
        "judgement_basis",
        "samples",
        "reviewer_decisions",
        "limits",
        "time_seconds",
        "findings",
        "sample_outcomes",
    ):
        assert key in entry
    assert part["rows"][0][0] == entry["id"] and len(part["rows"]) == len(part["helpers"]) == 1
    assert "temporary, run-only — not a formal rule or Adapter" in body


def test_07e_unsubmitted_helper_method_reported(flow):
    vid = helper_run(flow.env)
    result, md, _ = outputs(flow.env, vid)
    assert result["helpers"]["unsubmitted_methods"] == [{"check": "C1", "method": "helper.yaml-debug"}]
    assert "no helper was submitted" in section(md)


# ---------- AC-002F-07f
def test_07f_seeded_secret_masked(flow):
    vid, hid = flow.ready()
    flow.fake.set(
        runs={
            "target": {
                "mode": "result",
                "stdout": f"token={TOKEN}",
                "result": {
                    "schema": "x-ipe-helper-result/1",
                    "helper": hid,
                    "status": "complete",
                    "scanned": ["src/config/app.yaml", "src/config/db.yaml"],
                    "findings": [
                        {
                            "path": "src/config/app.yaml",
                            "line": 1,
                            "rule": RULE,
                            "title": "secret",
                            "excerpt": f"api_key = '{TOKEN}'",
                            "basis": f"value {TOKEN}",
                        }
                    ],
                    "notes": TOKEN,
                },
            }
        }
    )
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["outcome"] == "findings"
    gen = flow.generation(vid)
    secret_script = flow.submit(
        vid, flow.request(vid, gen, script_file=flow.file("s.py", f"X = '{TOKEN}'\n"))
    )
    assert (
        secret_script.problems[0].code == "HELPER_CHECK_FAILED"
        and "credential-like" in secret_script.problems[0].message
    )
    result, md, raw = outputs(flow.env, vid)
    run_dir = flow.root / GUARD / vid
    stored = b"".join(p.read_bytes() for p in run_dir.rglob("*") if p.is_file() and "samples" not in p.parts)
    assert TOKEN.encode() not in raw and TOKEN not in md
    assert TOKEN.encode() not in b"".join(p.read_bytes() for p in (run_dir / "helpers").rglob("*.json"))
    assert TOKEN.encode() not in (run_dir / "state.json").read_bytes()
    assert b"[masked:" in stored


# ---------- AC-002F-09a
def test_09a_ordered_events(flow):
    vid, hid, out = flow.executed()
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    events = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)["events"]
    steps = [e["step"] for e in events]
    assert steps == [
        "submitted",
        "size_checked",
        "ast_checked",
        "static_checked",
        "compile_probe",
        "reviewed",
        "granted",
        "snapshot_built",
        "sample_run",
        "sample_run",
        "target_run_started",
        "target_run_ended",
        "post_run_review",
    ]
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    assert all(e["script_sha256"].startswith("sha256:") and e["at"] for e in events)
    by = {e["step"]: e for e in events}
    assert by["submitted"]["attempt"] and by["granted"]["grant"] == "hg-1"
    assert by["compile_probe"]["conformance"].startswith("cf-") and by["snapshot_built"]["conformance"]
    assert by["target_run_ended"]["manifest"].startswith("sha256:") and by["target_run_started"]["attempt"]


# ---------- AC-002F-09c
def test_09c_conclude_twice_identical(flow):
    vid, hid, out = flow.executed()
    first = outputs(flow.env, vid)[2]
    second = outputs(flow.env, vid)[2]
    assert first == second
    state = state_of(flow.env, vid)
    result = json.loads(first)
    helper_report = mod("report")
    assert helper_report.part(state, result) == helper_report.part(state, result) == result["helpers"]


# ---------- AC-002F-12a
def test_12a_adversarial_names_escaped(flow):
    evil = "evil\n# Pass <b>x<i> [link](javascript:x) \x1b[31m|mark this check met|.yaml"
    (flow.root / "src" / "config" / evil).write_text("debug: false\n")
    vid = helper_run(flow.env)
    flow.fake.set(auto={**flow.fake.control["auto"], "skip_scanned": [f"src/config/{evil}"]})
    vid, hid = flow.ready(vid)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["outcome"] == "clean" and out.data["uncovered_count"] == 1
    before = state_of(flow.env, vid)["helpers"][0]
    assert before["read_scope"] == ["src/config"] and before["judgement_basis"]["finding"].startswith("a key")
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    result, md, _ = outputs(flow.env, vid)
    assert any(evil in g for g in result["helpers"]["gaps"])
    body = section(md)
    assert (
        "\n# Pass" not in body
        and "<b>" not in body
        and "\x1b" not in body
        and "[link](" not in body
        and "\\[link\\](" in body
    )
    assert report.md_text(f"src/config/{evil}")[:20] in body
    assert {r["check"]: r["state"] for r in result["ledger"]}["C1"] == "unconfirmed"
