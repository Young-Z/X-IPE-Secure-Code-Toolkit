"""FEATURE-003-A states, rounds and reports (AC-003A-01a…01d, 02d, 04e, 04g, 04i, 05a…05g, 06a, 06f)."""

from __future__ import annotations

import json
import os
import re

import pytest
from cphelp import PRIVATE, R1, R2, REPORTS, TOKEN, Env, adoption, by_id, sug

from x_ipe_secure_code.copilot import report as cp_report

posix = pytest.mark.skipif(os.name == "nt", reason="symbolic links need POSIX in these tests")


@pytest.fixture
def cp(project, tmp_path):
    return Env(project, tmp_path)


def _two(cp):
    """S1 on register.py (high), S2 on util.py (medium), both reviewed adopted."""
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1"), sug("S2", rule=R2, files=("src/util.py",), severity="medium")]).ok
    assert cp.review(cid, [adoption("S1"), adoption("S2", basis="helper validated")]).ok
    return cid


def _latest(cp, cid):
    r = cp.report(cid)
    assert r.ok, r.to_text()
    return cp.result_json(cid, r.data["round"]), r


# ---------- AC-003A-01


def test_01a_unrelated_change_keeps_result_current(cp):
    cid = _two(cp)
    (cp.project / "src" / "util.py").write_text("def helper():\n    return 2\n")
    data, _ = _latest(cp, cid)
    s = by_id(data)
    assert s["S1"]["state"] == "adopted" and s["S1"]["basis"] == "found in register() line 2"
    assert s["S2"]["state"] == "stale"
    assert data["re_review"] == ["S2"] and "S1" not in data["re_review"]
    (cp.project / "README.md").write_text("unrelated\n")
    data2, _ = _latest(cp, cid)
    assert by_id(data2)["S1"]["state"] == "adopted" and data2["re_review"] == ["S2"]


@pytest.mark.parametrize("how", ["modified", "deleted", "renamed_away"])
def test_01b_bound_file_change_makes_suggestion_stale(cp, how):
    cid = _two(cp)
    target = cp.project / "src" / "register.py"
    if how == "modified":
        target.write_text("changed\n")
    elif how == "deleted":
        target.unlink()
    else:
        os.rename(target, cp.project / "src" / "signup.py")
        assert cp.artifacts(
            cid, [{"path": "src/signup.py", "change": "renamed", "old_path": "src/register.py"}]
        ).ok
    data, _ = _latest(cp, cid)
    s1 = by_id(data)["S1"]
    assert s1["state"] == "stale" and s1["changed"] == [{"path": "src/register.py", "change": how}]
    assert s1["basis"] is None
    assert s1["history"] == [{"seq": 1, "result": "adopted", "basis": "found in register() line 2"}]
    assert by_id(data)["S2"]["state"] == "adopted"
    md = cp.report_md(cid, 1)
    assert f"src/register.py ({how})" in md and "history" in md.lower()


def test_01c_show_lists_stale_for_re_review(cp):
    cid = _two(cp)
    assert cp.suggest(cid, [sug("S3", rule=R1, files=("src/util.py",), severity="low")]).ok
    (cp.project / "src" / "register.py").write_text("changed\n")
    shown = cp.show(cid)
    assert shown.ok
    assert shown.data["re_review"] == ["S1", "S3"]
    states = {s["id"]: s["state"] for s in shown.data["suggestions"]}
    assert states == {"S1": "stale", "S2": "adopted", "S3": "not_reviewed"}
    assert "S2" not in shown.data["re_review"]


def test_01d_targeted_re_review(cp):
    cid = _two(cp)
    (cp.project / "src" / "register.py").unlink()
    assert cp.artifacts(cid, [{"path": "src/register.py", "change": "deleted"}]).ok
    second = cp.review(
        cid, [adoption("S1", "not_applicable", "registration removed")], files=["src/register.py"]
    )
    assert second.ok and cp.state(cid)["reviews"][1]["reviewed_targets"] == [
        {"path": "src/register.py", "digest": "absent"}
    ]
    data, _ = _latest(cp, cid)
    s = by_id(data)
    assert s["S1"]["state"] == "not_applicable" and s["S1"]["review_seq"] == 2
    assert s["S1"]["history"] == [{"seq": 1, "result": "adopted", "basis": "found in register() line 2"}]
    assert s["S2"]["state"] == "adopted" and s["S2"]["review_seq"] == 1
    assert data["re_review"] == []


def test_01d_most_recent_valid_record_decides(cp):
    cid = _two(cp)
    assert cp.review(cid, [adoption("S1", "partial", "only half")]).ok
    assert cp.review(cid, [adoption("S1", "adopted", "late")], requirement="").ok  # incomplete: ignored
    data, _ = _latest(cp, cid)
    s1 = by_id(data)["S1"]
    assert s1["state"] == "partial" and s1["review_seq"] == 2
    assert [h["seq"] for h in s1["history"]] == [1]
    assert {"id": "S1", "reason": "superseded by review 2"} in data["reviews"][0]["not_counted"]


# ---------- AC-003A-02d


@pytest.mark.parametrize("how", ["changed", "removed"])
def test_02d_policy_changed_is_permanent(cp, how):
    cid = _two(cp)
    (cp.project / "src" / "util.py").write_text("touch\n")  # S2 stale: precedence check below
    if how == "changed":
        cp.change_rule(R2, "Changed body.\n")
    else:
        cp.remove_rule(R2)
    data, report = _latest(cp, cid)
    s2 = by_id(data)["S2"]
    assert s2["state"] == "policy_changed"
    assert s2["history"] == [{"seq": 1, "result": "adopted", "basis": "helper validated"}]
    assert by_id(data)["S1"]["state"] == "adopted"
    assert [g["id"] for g in data["gaps"]] == ["S2"]
    assert R2 in data["scope"]["invalidated"]
    assert "open a new collaboration" in data["policy_next_step"]
    assert any("open a new collaboration" in s for s in report.next_steps)
    assert "open a new collaboration" in cp.report_md(cid, 1)
    assert R2 in cp.state(cid)["invalidated_rules"]


def test_02d_restored_policy_stays_policy_changed(cp):
    cid = _two(cp)
    original = cp.project / "x-ipe-docs/secure-code/knowledge/local/CWE/4.14/CWE-89"
    saved = {p.relative_to(original): p.read_bytes() for p in original.rglob("*") if p.is_file()}
    cp.change_rule(R2, "Changed body.\n")
    assert cp.suggest(cid, [sug("S3")]).ok  # a mutating command persists the invalidation
    import shutil

    shutil.rmtree(original)
    for rel, data in saved.items():
        (original / rel).parent.mkdir(parents=True, exist_ok=True)
        (original / rel).write_bytes(data)
    data, _ = _latest(cp, cid)
    adopted_now = {a["rule"]: a["now"] for a in data["scope"]["adopted"]}
    assert adopted_now[R2] == "unchanged"
    assert by_id(data)["S2"]["state"] == "policy_changed"
    assert by_id(data)["S2"]["history"] == [{"seq": 1, "result": "adopted", "basis": "helper validated"}]
    assert (
        data["scope"]["invalidated"][R2]["now"] == "changed"
        and data["scope"]["invalidated"][R2]["detected_at"]
    )


# ---------- AC-003A-04e, 04g, 04i


def test_04e_never_reviewed_is_not_reviewed_and_snapshot(cp):
    cid = cp.opened()
    assert cp.suggest(cid, [sug("S1"), sug("S2", severity="low")]).ok
    data, _ = _latest(cp, cid)
    assert {s["id"]: s["state"] for s in data["suggestions"]} == {"S1": "not_reviewed", "S2": "not_reviewed"}
    assert data["snapshot_before_review"] is True and data["counts"]["adopted"] == 0
    assert "snapshot before review" in cp.report_md(cid, 1).lower()


def test_04g_review_bound_to_old_digest_does_not_count(cp):
    cid = _two(cp)
    (cp.project / "src" / "register.py").write_text("changed later\n")
    data, _ = _latest(cp, cid)
    assert by_id(data)["S1"]["state"] == "stale"
    assert {"id": "S1", "reason": "stale: src/register.py modified since the review"} in (
        data["reviews"][0]["not_counted"]
    )
    assert "stale: src/register.py modified since the review" in cp.report_md(cid, 1)


def test_04i_attention_and_gaps_matrix(cp):
    cid = cp.opened()
    severities = ("critical", "high", "unknown", "medium", "low", "info")
    results = ("adopted", "not_applicable", "partial", "not_adopted", "cannot_verify")
    suggestions, subjects = [], []
    for sev in severities:
        for res in (*results, "none"):
            sid = f"{sev[:3]}-{res[:6]}"
            suggestions.append(sug(sid, severity=sev))
            if res != "none":
                subjects.append(adoption(sid, res, f"basis {res}"))
    assert cp.suggest(cid, suggestions).ok
    assert cp.review(cid, subjects, files=["src/register.py"]).ok
    data, _ = _latest(cp, cid)
    attention = {a["id"] for a in data["attention"]}
    gaps = {g["id"] for g in data["gaps"]}
    for s in data["suggestions"]:
        flagged = s["state"] not in ("adopted", "not_applicable")
        high = s["severity"] in ("critical", "high", "unknown")
        assert (s["id"] in attention) == (flagged and high), s
        assert (s["id"] in gaps) == (flagged and not high), s
    assert all(a["reason"] for a in data["attention"] + data["gaps"])
    order = [a["severity"] for a in data["attention"]]
    assert order == sorted(order, key=("critical", "high", "unknown").index)
    md = cp.report_md(cid, 1)
    assert md.index("## Attention") < md.index("## Gaps") < md.index("## Suggestions")


def test_04i_stale_and_policy_changed_in_attention(cp):
    cid = _two(cp)
    (cp.project / "src" / "register.py").write_text("x\n")
    cp.change_rule(R2, "Changed.\n")
    assert cp.suggest(cid, [sug("S3", rule=R2, severity="critical")]).ok
    data, _ = _latest(cp, cid)
    assert [(a["id"], a["state"]) for a in data["attention"]] == [("S3", "policy_changed"), ("S1", "stale")]
    assert [(g["id"], g["state"]) for g in data["gaps"]] == [("S2", "policy_changed")]


# ---------- AC-003A-05


def test_05a_05c_report_and_json_from_same_data(cp):
    cid = _two(cp)
    (cp.project / "src" / "util.py").write_text("x\n")
    assert cp.suggest(cid, [sug("S3", severity="unknown", location="loc | *bold* <b>")]).ok
    data, r = _latest(cp, cid)
    assert r.data["report"] == f"{REPORTS}/{cid}-r1.md" and r.data["result"] == f"{REPORTS}/{cid}-r1.json"
    md = cp.report_md(cid, 1)
    code, cell = cp_report.code, cp_report.cell
    assert md.startswith(f"# Copilot Adoption Report {cid} — round 1")
    table = _section(md, "Suggestions")
    for s in data["suggestions"]:
        row = next(line for line in table.splitlines() if line.startswith(f"| {code(s['id'])} |"))
        for value in (s["state"], s["severity"], s["rule"]):
            assert code(value) in row
        if s["basis"]:
            assert cell(s["basis"]) in row
    attention = _section(md, "Attention")
    gaps = _section(md, "Gaps")
    assert [a["id"] for a in data["attention"]] == _ids(attention)
    assert [g["id"] for g in data["gaps"]] == _ids(gaps)
    assert [(a["state"], a["severity"]) for a in data["attention"]] == _cols(attention, 2, 1)
    for value in (
        code(data["stage"]),
        cell(data["task"]),
        code(data["scope"]["scope_id"]),
        data["opened_at"],
    ):
        assert value in md
    for m in data["manifest"]:
        assert code(m["path"]) in md and code(m["current_digest"]) in md
    for rv in data["reviews"]:
        assert f"| {rv['seq']} | {'yes' if rv['valid'] else 'no'} |" in md
        assert code(rv["counted"]) in md
    for rule in data["scope"]["adopted"]:
        assert f"| {code(rule['rule'])} | {code(rule['state_digest'])} | {code(rule['now'])} |" in md
    assert "loc \\| \\*bold\\* \\<b\\>" in md
    assert "snapshot before review" not in md.lower()
    assert cp_report.footer_digest(md) == cp_report.sha256_hex((cp.project / r.data["result"]).read_bytes())


def _section(md, title):
    return md.split(f"## {title}\n", 1)[1].split("\n## ", 1)[0]


def _cols(section, *index):
    rows = [line.strip().strip("|").split(" | ") for line in section.splitlines() if line.startswith("| ")][
        1:
    ]
    return [tuple(r[i].strip().strip("`") for i in index) for r in rows]


def _ids(section):
    return [r[0] for r in _cols(section, 0)]


_REVIEW_KEYS = {
    "seq",
    "valid",
    "reasons",
    "invocation",
    "requirement",
    "reviewed_targets",
    "reviewed_at",
    "subjects",
    "masked",
    "recorded_at",
    "counted",
    "not_counted",
}


def _row(cells):
    return "| " + " | ".join(cells) + " |"


def _record_block(section, seq):
    return section.split(f"\n### Reviewer record {seq}\n", 1)[1].split("\n### ", 1)[0]


def _reviewer_records_scenario(cp):
    """Four records: incomplete with masked text and no result, valid, `absent` target, wrong version."""
    cid = cp.opened()
    assert cp.suggest(
        cid,
        [
            sug("S1"),
            sug("S2", rule=R2, files=("src/util.py",), severity="medium"),
            sug("S3", files=("src/register.py", "src/util.py"), severity="critical"),
        ],
    ).ok
    no_agent = {"host": "github-copilot", "read_only": True, "invoked_at": "2026-10-21T09:00:00Z"}
    assert cp.review(
        cid,
        [{"type": "adoption", "id": "S1", "basis": f"token {TOKEN} removed | *kept*"}],
        invocation=no_agent,
        requirement=f"Check that {TOKEN} is gone",
    ).ok
    assert cp.review(
        cid,
        [
            adoption("S1"),
            adoption("S2", "partial", "helper half done"),
            adoption("S3", "cannot_verify", "n/a"),
        ],
    ).ok
    old = cp.digest("src/register.py")
    (cp.project / "src" / "util.py").unlink()
    assert cp.review(cid, [adoption("S2", "not_applicable", "util.py was removed")]).ok
    (cp.project / "src" / "register.py").write_text("def register(u):\n    return db.run(u, ())\n")
    assert cp.review(cid, [adoption("S1")], reviewed_targets=[{"path": "src/register.py", "digest": old}]).ok
    return cid


def test_05a_reviewer_records_identical_in_markdown(cp):
    """AC-003A-05a: every Reviewer-record field of the JSON appears in the Markdown, field by field."""
    cid = _reviewer_records_scenario(cp)
    data, r = _latest(cp, cid)
    md = cp.report_md(cid, r.data["round"])
    code, cell = cp_report.code, cp_report.cell
    section = _section(md, "Reviewer Records")
    assert [rv["seq"] for rv in data["reviews"]] == [1, 2, 3, 4]
    assert TOKEN not in md
    for rv in data["reviews"]:
        assert set(rv) == _REVIEW_KEYS
        inv = rv["invocation"]
        assert set(inv) == {"host", "agent", "read_only", "invoked_at", "declared"}
        fields = {
            "seq": str(rv["seq"]),
            "valid": "yes" if rv["valid"] else "no",
            "host": cell(inv["host"]),
            "agent": cell(inv["agent"]),
            "read_only": "yes" if inv["read_only"] else "no",
            "invoked_at": cell(inv["invoked_at"]),
            "reviewed_at": cell(rv["reviewed_at"]),
            "recorded_at": code(rv["recorded_at"]),
            "requirement": cell(rv["requirement"]),
            "reasons": code(rv["reasons"]),
            "counted": code(rv["counted"]),
            "not_counted": code([f"{x['id']}: {x['reason']}" for x in rv["not_counted"]]),
            "masked": code([f"masked: {label}" for label in rv["masked"]]),
        }
        summary = _row(list(fields.values()))
        assert summary in section.splitlines(), (rv["seq"], summary)
        block = _record_block(section, rv["seq"])
        declared = "declared by the agent, not proven" if inv["declared"] else "not declared"
        assert f"Invocation {declared}." in block
        targets = [_row([code(t["path"]), code(t["digest"])]) for t in rv["reviewed_targets"]]
        lines = block.splitlines()
        for row in targets:
            assert row in lines, (rv["seq"], row)
        for i, s in enumerate(rv["subjects"]):
            assert set(s) == {"type", "id", "result", "basis"}
            labels = [
                m.removeprefix(f"subjects[{i}].") for m in rv["masked"] if m.startswith(f"subjects[{i}].")
            ]
            row = _row(
                [
                    code(s["id"]),
                    code(s["type"]),
                    code(s["result"]),
                    cell(s["basis"]),
                    code([f"masked: {label}" for label in labels]),
                ]
            )
            assert row in lines, (rv["seq"], row)
        target_rows = [line for line in lines if line.startswith("| `") and line.count(" | ") == 1]
        subject_rows = [line for line in lines if line.startswith("| `") and line.count(" | ") == 4]
        assert len(target_rows) == len(rv["reviewed_targets"]) and len(subject_rows) == len(rv["subjects"])


def test_05a_reviewer_record_values_shown_raw(cp):
    """Identifiers, paths and digests are code spans; `absent`, masked labels and missing values are named."""
    cid = _reviewer_records_scenario(cp)
    data, r = _latest(cp, cid)
    section = _section(cp.report_md(cid, r.data["round"]), "Reviewer Records")
    first, second, third, fourth = data["reviews"]
    assert first["valid"] is False and first["invocation"]["agent"] is None
    assert (
        "invocation.agent is missing" in first["reasons"]
        and "subjects[0].result is missing" in first["reasons"]
    )
    block1 = _record_block(section, 1)
    assert "| `S1` | `adoption` | — | " in block1 and "`masked: basis`" in block1
    assert "`[masked:credential" in block1 and "\\*kept\\*" in block1 and "\\|" in block1
    block2 = _record_block(section, 2)
    for t in second["reviewed_targets"]:
        assert f"| `{t['path']}` | `{t['digest']}` |" in block2 and t["digest"].startswith("sha256:")
    assert "| `S3` | `adoption` | `cannot_verify` | n/a | — |" in block2
    assert third["reviewed_targets"] == [{"path": "src/util.py", "digest": "absent"}]
    assert "| `src/util.py` | `absent` |" in _record_block(section, 3)
    assert fourth["valid"] is False and "wrong version: src/register.py" in fourth["reasons"]
    assert "`wrong version: src/register.py`" in section
    for rv in data["reviews"]:
        assert f"`{rv['recorded_at']}`" in section and rv["reviewed_at"] in section
    assert "<" not in section.replace("\\<", "") and "](" not in section


def test_05b_earlier_rounds_immutable(cp):
    cid = _two(cp)
    first = _latest(cp, cid)[1]
    j1 = (cp.project / first.data["result"]).read_bytes()
    m1 = (cp.project / first.data["report"]).read_bytes()
    (cp.project / "src" / "register.py").write_text("x\n")
    data, second = _latest(cp, cid)
    assert second.data["round"] == 2 and second.data["published"] is True
    assert data["supersedes"] == f"{cid}-r1" and data["round"] == 2
    assert f"This round supersedes {cid}-r1" in cp.report_md(cid, 2)
    assert cp.result_json(cid, 1)["supersedes"] is None
    assert (cp.project / first.data["result"]).read_bytes() == j1
    assert (cp.project / first.data["report"]).read_bytes() == m1


def test_05d_boundaries(cp):
    cid = cp.opened(stage="design", artifacts=[{"path": "docs/design.md"}])
    assert cp.suggest(cid, [sug("S1", files=("docs/design.md",))]).ok
    data, _ = _latest(cp, cid)
    md = cp.report_md(cid, 1).lower()
    text = " ".join(data["boundaries"]).lower()
    for phrase in (
        "not a pass, approval or security verification",
        "not a correctness guarantee",
        "does not replace guard verification",
        "adoption in the design does not show the measure is implemented",
    ):
        assert phrase in text and phrase in md
    impl = cp.opened()
    assert cp.suggest(impl, [sug("S1")]).ok
    other, _ = _latest(cp, impl)
    assert "design does not show" not in " ".join(other["boundaries"])


def test_05e_structured_result_has_no_verdict(cp):
    cid = _two(cp)
    data, _ = _latest(cp, cid)
    for key in ("suggestions", "attention", "gaps", "re_review"):
        assert key in data
    keys = set()

    def walk(value):
        if isinstance(value, dict):
            keys.update(value)
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)

    walk(data)
    assert not keys & {"pass", "passed", "approved", "verdict", "completed_safely", "safe", "ok"}


def test_05f_no_change_no_new_round_and_render_deterministic(cp):
    cid = _two(cp)
    first = cp.report(cid)
    again = cp.report(cid)
    assert again.data["round"] == 1 and again.data["published"] is False
    assert again.data["report"] == first.data["report"] and cp.rounds(cid) == [
        f"{cid}-r1.json",
        f"{cid}-r1.md",
    ]
    data = cp.result_json(cid, 1)
    assert cp_report.render(data) == cp_report.render(json.loads(json.dumps(data)))
    assert cp_report.render(data) == cp.report_md(cid, 1)
    assert cp.result_json(cid, 1)["state_signature"].startswith("sha256:")
    (cp.project / "src" / "util.py").write_text("x\n")
    assert cp.report(cid).data["round"] == 2
    assert cp.report(cid).data["round"] == 2


def test_05g_retention_statements_and_show_existence(cp):
    cid = _two(cp)
    data, r = _latest(cp, cid)
    assert data["retention"]["reports"] == "kept until the user removes them"
    assert "no automatic expiry" in data["retention"]["private_data"]
    assert data["private_data_present_as_of_publication"] is True
    md = cp.report_md(cid, 1)
    assert f"as of publication {data['published_at']}" in md and "no automatic expiry" in md
    (cp.project / REPORTS / f"{cid}-r1.md").unlink()
    shown = cp.show(cid)
    assert shown.data["private_data_present"] is True
    assert shown.data["reports"] == [
        {
            "round": 1,
            "json": f"{REPORTS}/{cid}-r1.json",
            "json_exists": True,
            "md": f"{REPORTS}/{cid}-r1.md",
            "md_exists": False,
        }
    ]
    assert shown.data["latest_round"] == 1
    import shutil

    shutil.rmtree(cp.project / PRIVATE / cid)
    gone = cp.show(cid)
    assert gone.ok and gone.data["private_data_present"] is False
    assert gone.data["reports"][0]["json_exists"] is True and gone.data["latest_round"] == 1


# ---------- AC-003A-06f


def test_06f_close_publishes_final_round_when_changed(cp):
    cid = _two(cp)
    assert cp.report(cid).data["round"] == 1
    (cp.project / "src" / "register.py").write_text("x\n")
    closed = cp.close(cid)
    assert closed.ok and closed.data["round"] == 2 and closed.data["published"] is True
    assert closed.data["report"] == f"{REPORTS}/{cid}-r2.md"
    state = cp.state(cid)
    assert state["status"] == "closed" and state["closed_at"]


def test_06f_close_without_change_publishes_nothing(cp):
    cid = _two(cp)
    assert cp.report(cid).data["round"] == 1
    closed = cp.close(cid)
    assert closed.data["round"] == 1 and closed.data["published"] is False
    assert cp.rounds(cid) == [f"{cid}-r1.json", f"{cid}-r1.md"]


def test_06f_close_without_any_report_publishes_first(cp):
    cid = cp.opened()
    closed = cp.close(cid)
    assert closed.data["round"] == 1 and closed.data["published"] is True


# ---------- AC-003A-06a


def _snapshot(root):
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            out[path.relative_to(root).as_posix()] = path.read_bytes()
    return out


def test_06a_artifacts_byte_identical_and_only_copilot_paths_written(cp):
    artifacts = ("src/register.py", "src/util.py", "docs/design.md", "docs/api.md")
    cp.opened()  # warm the knowledge lock file so it is not counted as a Copilot write
    before = _snapshot(cp.project)
    originals = {a: (cp.project / a).read_bytes() for a in artifacts}

    def unchanged():
        assert {a: (cp.project / a).read_bytes() for a in artifacts} == originals

    cid = cp.opened(artifacts=[{"path": "src/register.py"}, {"path": "src/util.py"}, {"path": "docs"}])
    unchanged()
    assert cp.artifacts(cid, [{"path": "docs", "change": "modified"}]).ok
    unchanged()
    assert cp.suggest(cid, [sug("S1"), sug("S2", files=("docs/api.md",))]).ok
    unchanged()
    assert cp.review(cid, [adoption("S1"), adoption("S2")]).ok
    unchanged()
    assert cp.report(cid).ok
    unchanged()
    assert cp.show(cid).ok
    unchanged()
    assert cp.close(cid).ok
    unchanged()
    after = _snapshot(cp.project)
    changed = {p for p in set(before) | set(after) if before.get(p) != after.get(p)}
    allowed = (f"{PRIVATE}/{cid}/", f"{REPORTS}/{cid}-r", ".x-ipe/private/secure-code/locks/")
    assert changed and all(p.startswith(allowed) for p in changed), sorted(changed)


# ---------- path safety


@posix
@pytest.mark.parametrize("which", ["reports", "private", "locks"])
def test_symlinked_copilot_folders_refused(cp, which, tmp_path):
    cid = cp.opened() if which == "reports" else None
    outside = tmp_path / "outside"
    outside.mkdir()
    rel = {"reports": REPORTS, "private": PRIVATE, "locks": ".x-ipe/private/secure-code/locks"}[which]
    folder = cp.project / rel
    if folder.exists():
        import shutil

        shutil.rmtree(folder)
    folder.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, folder)
    result = cp.report(cid) if cid else cp.open()
    assert not result.ok and result.problems[0].code == "PATH_UNSAFE"
    assert list(outside.iterdir()) == []


# ---------- result envelope


def test_report_next_steps_hand_over_to_caller(cp):
    cid = _two(cp)
    (cp.project / "src" / "register.py").write_text("x\n")
    result = cp.report(cid)
    assert any("upstream caller" in s for s in result.next_steps)
    assert [a["id"] for a in result.data["attention"]] == ["S1"]
    assert re.fullmatch(r"cp-\d{8}T\d{6}Z-[0-9a-f]{8}", cid)
