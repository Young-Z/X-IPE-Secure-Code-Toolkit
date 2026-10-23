"""Unit tests for Guard masking, targets/digests and request validation (FEATURE-002-A)."""

from __future__ import annotations

import os

import pytest

from x_ipe_secure_code.guard import records, targets
from x_ipe_secure_code.guard.mask import mask_text
from x_ipe_secure_code.guard.model import GuardError

TOKEN = "ghp_" + "a" * 36
RULE = "CWE/4.14/CWE-79"
RULE2 = "CWE/4.14/CWE-89"


# ---------- mask (AC-002A-01d)


def test_mask_replaces_token_assignment_and_private_key_block():
    text = (
        f'token {TOKEN}\npassword = "Zq8vLr2mNp4tXw9y"\n'
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\nend"
    )
    masked, kinds = mask_text(text)
    assert TOKEN not in masked and "Zq8vLr2mNp4tXw9y" not in masked and "MIIEow" not in masked
    assert kinds == ["credential.assignment", "credential.private_key", "credential.token"]
    assert "[masked:credential.token]" in masked and masked.endswith("end")


def test_mask_keeps_placeholders_and_documented_examples():
    text = 'password = "changeme"\nkey AKIAIOSFODNN7EXAMPLE\ntoken = "${API_TOKEN}"'
    assert mask_text(text) == (text, [])


def test_mask_unterminated_private_key_masks_to_end():
    masked, kinds = mask_text("a\n-----BEGIN PRIVATE KEY-----\nsecret material")
    assert masked == "a\n[masked:credential.private_key]" and kinds == ["credential.private_key"]


# ---------- targets and digests (AC-002A-02c…02f)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "proj"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print(1)\n")
    (root / "src" / "pkg" / "b.py").write_text("print(2)\n")
    (root / "docs").mkdir()
    (root / "docs" / "d.md").write_text("# d\n")
    return root


def _open(**over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-open/v1",
        "scope_id": "sha256:" + "a" * 64,
        "targets": [{"path": "src/a.py"}],
    }
    doc.update(over)
    return doc


def test_tree_digest_is_stable_and_excludes_toolkit_data(tree):
    first = targets.snapshot(tree, "src", "dir")
    (tree / ".git").mkdir()
    (tree / ".git" / "HEAD").write_text("x")
    (tree / "x-ipe-docs" / "secure-code" / "reports").mkdir(parents=True)
    (tree / "x-ipe-docs" / "secure-code" / "reports" / "r.md").write_text("r")
    whole_a = targets.snapshot(tree, ".", "dir")
    (tree / ".git" / "HEAD").write_text("y")
    (tree / "x-ipe-docs" / "secure-code" / "reports" / "r.md").write_text("changed")
    assert targets.snapshot(tree, ".", "dir") == whole_a
    assert targets.snapshot(tree, "src", "dir") == first and not first["incomplete"]
    (tree / "src" / "pkg" / "b.py").write_text("print(3)\n")
    assert targets.snapshot(tree, "src", "dir")["digest"] != first["digest"]


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_tree_symlink_inside_outside_dangling_and_retarget(tree, tmp_path):
    base = targets.snapshot(tree, "src", "dir")
    os.symlink(tree / "src" / "a.py", tree / "src" / "inside.py")
    inside = targets.snapshot(tree, "src", "dir")
    assert inside["digest"] != base["digest"] and not inside["incomplete"]
    assert inside["not_followed"] == [{"path": "src/inside.py", "inside_tree": True}]
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("x")
    os.symlink(outside_file, tree / "src" / "out.py")
    out = targets.snapshot(tree, "src", "dir")
    assert out["incomplete"] and {"path": "src/out.py", "inside_tree": False} in out["not_followed"]
    os.remove(tree / "src" / "out.py")
    os.symlink(tree / "src" / "pkg" / "b.py", tree / "src" / "inside.py.2")
    os.remove(tree / "src" / "inside.py")
    os.symlink(tree / "src" / "pkg" / "b.py", tree / "src" / "inside.py")
    assert targets.snapshot(tree, "src", "dir")["digest"] != inside["digest"]  # retargeted
    os.symlink(tree / "nowhere", tree / "src" / "dangling")
    dangling = targets.snapshot(tree, "src", "dir")
    assert dangling["incomplete"] and "src/dangling" in dangling["unreadable"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs (POSIX)")
def test_tree_special_entry_marks_incomplete(tmp_path):
    root = tmp_path / "p"
    (root / "s").mkdir(parents=True)
    before = targets.snapshot(root, "s", "dir")
    os.mkfifo(root / "s" / "fifo")
    snap = targets.snapshot(root, "s", "dir")
    assert snap["incomplete"] and "s/fifo" in snap["unreadable"] and snap["digest"] != before["digest"]


def test_parse_open_records_roles_changes_and_digests(tree):
    (tree / "src" / "new.py").write_text("n")
    doc = _open(
        targets=[
            {"path": "src/a.py", "change": "modified"},
            {"path": "src/new.py", "change": "added"},
            {"path": "src/gone.py", "change": "deleted"},
            {"path": "src/pkg", "change": "renamed", "old_path": "src/oldpkg"},
        ],
        context=[{"path": "docs/d.md"}],
        suggested=[{"path": "docs", "reason": "related docs"}],
        request="Verify login",
        baseline="main@abc",
    )
    parsed = targets.parse_open(tree, doc)
    t = {e["path"]: e for e in parsed["artifact"]["targets"]}
    assert t["src/gone.py"]["digest"] is None and t["src/gone.py"]["kind"] is None
    assert t["src/pkg"]["old_path"] == "src/oldpkg" and t["src/pkg"]["kind"] == "dir"
    assert t["src/a.py"]["digest"].startswith("sha256:") and t["src/new.py"]["change"] == "added"
    assert parsed["artifact"]["context"][0]["digest"].startswith("sha256:")
    assert parsed["artifact"]["suggested"] == [{"path": "docs", "reason": "related docs"}]
    assert parsed["request"] == "Verify login" and parsed["artifact"]["whole_project"] is False


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"targets": []}, "TARGETS_REQUIRED"),
        ({"targets": [{"path": "."}]}, "WHOLE_PROJECT_NOT_EXPLICIT"),
        ({"targets": [{"path": "./"}]}, "WHOLE_PROJECT_NOT_EXPLICIT"),
        ({"targets": [{"path": "missing.py"}]}, "TARGET_INVALID"),
        ({"targets": [{"path": "../x.py"}]}, "TARGET_INVALID"),
        ({"targets": [{"path": "/etc/passwd"}]}, "TARGET_INVALID"),
        ({"targets": [{"path": "src/a.py", "change": "deleted"}]}, "TARGET_INVALID"),
        ({"targets": [{"path": "src/a.py", "change": "renamed"}]}, "REQUEST_INVALID"),
        ({"targets": [{"path": "src/a.py", "old_path": "x.py"}]}, "REQUEST_INVALID"),
        ({"targets": [{"path": "src/a.py"}], "context": [{"path": "src/a.py"}]}, "ROLE_CONFLICT"),
        ({"targets": [{"path": "src/a.py"}, {"path": "src/a.py"}]}, "ROLE_CONFLICT"),
        ({"whole_project": True}, "REQUEST_INVALID"),
        ({"targets": [{"path": ".x-ipe/private/secure-code/x"}]}, "TARGET_INVALID"),
        ({"surprise": 1}, "REQUEST_INVALID"),
        ({"scope_id": ""}, "MAINTENANCE_NEEDED"),
    ],
)
def test_parse_open_refusals(tree, over, code):
    with pytest.raises(GuardError) as exc:
        targets.parse_open(tree, _open(**over))
    assert exc.value.code == code and exc.value.next_step


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_parse_open_refuses_symlink_target_and_symlinked_parent(tree):
    os.symlink(tree / "src" / "a.py", tree / "link.py")
    os.symlink(tree / "src", tree / "linkdir")
    for path in ("link.py", "linkdir/a.py"):
        with pytest.raises(GuardError) as exc:
            targets.parse_open(tree, _open(targets=[{"path": path}]))
        assert exc.value.code == "TARGET_INVALID"


def test_parse_open_whole_project(tree):
    parsed = targets.parse_open(tree, _open(targets=[], whole_project=True))
    assert parsed["artifact"]["whole_project"] is True
    assert [t["path"] for t in parsed["artifact"]["targets"]] == ["."]
    assert targets.owning_target(parsed["artifact"], "src/pkg/b.py") == "."


def test_owning_target_for_descendants(tree):
    artifact = targets.parse_open(tree, _open(targets=[{"path": "src/pkg"}, {"path": "src/a.py"}]))[
        "artifact"
    ]
    assert targets.owning_target(artifact, "src/pkg/b.py") == "src/pkg"
    assert targets.owning_target(artifact, "src/a.py") == "src/a.py"
    assert targets.owning_target(artifact, "src/a.pyx") is None
    assert targets.owning_target(artifact, "docs/d.md") is None


# ---------- records validation (AC-002A-03d, 04a, 04b, 04e, 05a, 05e, 05g)


def _state(tree):
    parsed = targets.parse_open(
        tree, _open(targets=[{"path": "src/a.py"}, {"path": "src/pkg"}], context=[{"path": "docs/d.md"}])
    )
    return {
        "scope": {
            "scope_id": parsed["scope_id"],
            "mode": "clues",
            "adopted": [
                {"rule": RULE, "state_digest": "sha256:" + "1" * 64},
                {"rule": RULE2, "state_digest": "sha256:" + "2" * 64},
            ],
        },
        "artifact": parsed["artifact"],
        "plan": None,
        "evidence": [],
        "findings": [],
        "ledger": {},
        "conflicts": [],
        "reviews": [],
    }


def _plan(**over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": [
            {
                "id": "C1",
                "rule": RULE,
                "object": ["src/a.py"],
                "object_part": "render()",
                "methods": [
                    {"name": "semantic-review", "kind": "reading", "required": True},
                    {"name": "custom-scan", "kind": "runtime", "required": False},
                ],
                "minimum_evidence": ["reading", "runtime"],
                "method_choice": {"considered": ["semantic-review", "custom-scan"],
                                  "selected": ["semantic-review"],
                                  "reason": "reading first, scan as supplement"},
            }
        ],
        "not_applicable": [{"rule": RULE2, "reason": "no database access"}],
    }
    doc.update(over)
    return doc


def test_plan_valid_and_masks_text(tree):
    plan = records.validate_plan(
        _state(tree), _plan(not_applicable=[{"rule": RULE2, "reason": f"x {TOKEN}"}])
    )
    assert plan["checks"][0]["id"] == "C1" and plan["checks"][0]["methods"][1]["required"] is False
    assert TOKEN not in plan["not_applicable"][0]["reason"]


@pytest.mark.parametrize(
    ("over", "code", "text"),
    [
        (
            {
                "checks": [
                    {
                        "id": "C1",
                        "rule": "CWE/4.14/CWE-1",
                        "object": ["src/a.py"],
                        "methods": [{"name": "m", "kind": "reading", "required": True}],
                        "minimum_evidence": ["reading"],
                    }
                ]
            },
            "PLAN_INVALID",
            "not in the adopted scope",
        ),
        (
            {
                "checks": [
                    {
                        "id": "C1",
                        "rule": RULE,
                        "object": ["src/a.py"],
                        "methods": [],
                        "minimum_evidence": ["reading"],
                    }
                ]
            },
            "PLAN_INVALID",
            "methods",
        ),
        (
            {
                "checks": [
                    {
                        "id": "C1",
                        "rule": RULE,
                        "object": [],
                        "methods": [{"name": "m", "kind": "reading", "required": True}],
                        "minimum_evidence": ["reading"],
                    }
                ]
            },
            "PLAN_INVALID",
            "object",
        ),
        (
            {
                "checks": [
                    {
                        "id": "C1",
                        "rule": RULE,
                        "object": ["src/a.py"],
                        "methods": [{"name": "m", "kind": "reading", "required": True}],
                    }
                ]
            },
            "PLAN_INVALID",
            "minimum_evidence",
        ),
        (
            {
                "checks": [
                    {
                        "id": "C1",
                        "rule": RULE,
                        "object": ["docs/d.md"],
                        "methods": [{"name": "m", "kind": "reading", "required": True}],
                        "minimum_evidence": ["reading"],
                    }
                ]
            },
            "PLAN_INVALID",
            "not a target",
        ),
        (
            {
                "checks": [
                    {
                        "id": "C1",
                        "rule": RULE,
                        "object": ["src/a.py"],
                        "methods": [{"name": "m", "kind": "guess", "required": True}],
                        "minimum_evidence": ["reading"],
                    }
                ]
            },
            "PLAN_INVALID",
            "kind",
        ),
        ({"not_applicable": [{"rule": RULE2, "reason": ""}]}, "PLAN_INVALID", "reason"),
        ({"not_applicable": []}, "PLAN_INCOMPLETE", RULE2),
        ({"exclusions": [{"rule": RULE2, "check": "C1", "reason": "x"}]}, "PLAN_INVALID", "exactly one"),
    ],
)
def test_plan_refusals(tree, over, code, text):
    with pytest.raises(GuardError) as exc:
        records.validate_plan(_state(tree), _plan(**over))
    assert exc.value.code == code and text in exc.value.message


def test_plan_checks_may_cover_descendants_and_exclusions_cover_rules(tree):
    plan = records.validate_plan(
        _state(tree),
        _plan(
            checks=[
                {
                    "id": "C1",
                    "rule": RULE,
                    "object": ["src/pkg/b.py"],
                    "methods": [{"name": "m", "kind": "reading", "required": True}],
                    "minimum_evidence": ["reading"],
                }
            ],
            not_applicable=[],
            exclusions=[{"rule": RULE2, "reason": "user: later"}],
        ),
    )
    assert plan["exclusions"] == [{"rule": RULE2, "check": None, "reason": "user: later"}]


def _planned(tree):
    state = _state(tree)
    state["plan"] = records.validate_plan(state, _plan())
    return state


def _record(**over):
    doc = {"schema": "ai-secure-code-toolkit/guard-record/v1"}
    doc.update(over)
    return doc


def _ev(eid="E1", **over):
    e = {
        "id": eid,
        "kind": "reading",
        "method": "semantic-review",
        "method_status": "ok",
        "checks": ["C1"],
        "paths": ["src/a.py"],
        "summary": "looked at render()",
    }
    e.update(over)
    return e


def test_record_applies_evidence_findings_ledger_and_masks_content(tree):
    state = _planned(tree)
    new, writes = records.apply_record(
        tree,
        state,
        _record(
            evidence=[_ev(content=f"line {TOKEN}")],
            findings=[
                {
                    "id": "F1",
                    "rule": RULE,
                    "check": "C1",
                    "location": {"path": "src/a.py", "line": 3},
                    "title": "XSS",
                    "description": f"leaks {TOKEN}",
                    "source": "semantic",
                    "severity": "high",
                    "evidence": ["E1"],
                }
            ],
            ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}],
        ),
    )
    assert state["evidence"] == []  # input state untouched
    ev = new["evidence"][0]
    assert (
        ev["masked"] is True
        and ev["masked_types"] == ["credential.token"]
        and ev["stored"] == "evidence/E1.txt"
    )
    assert writes == [("E1", "line [masked:credential.token]")]
    assert TOKEN not in new["findings"][0]["description"]
    assert new["ledger"]["C1"]["state"] == "not_met"


@pytest.mark.parametrize(
    ("over", "code", "text"),
    [
        ({"evidence": [_ev(kind="reading", method="custom-scan")]}, "RECORD_INVALID", "kind"),
        ({"evidence": [_ev(method="nope")]}, "RECORD_INVALID", "method"),
        ({"evidence": [_ev(paths=["README.md"])]}, "RECORD_INVALID", "not a recorded path"),
        ({"evidence": [_ev(eid="../x")]}, "RECORD_INVALID", "id"),
        ({"evidence": [_ev(), _ev()]}, "RECORD_INVALID", "duplicate"),
        ({"evidence": [_ev(content="x" * (1024 * 1024 + 1))]}, "RECORD_INVALID", "longer"),
        ({"evidence": [_ev(summary="s" * 8193)]}, "RECORD_INVALID", "longer"),
        (
            {
                "ledger": [
                    {"check": "C1", "state": "n/a", "reason_type": "method_unavailable", "reason": "no tool"}
                ]
            },
            "NA_NOT_OBJECTIVE",
            "unconfirmed",
        ),
        ({"ledger": [{"check": "C1", "state": "met", "evidence": []}]}, "RECORD_INVALID", "evidence"),
        ({"ledger": [{"check": "C9", "state": "met", "evidence": []}]}, "RECORD_INVALID", "unknown check"),
        ({"ledger": [{"check": "C1", "state": "unconfirmed"}]}, "RECORD_INVALID", "reason"),
        (
            {
                "findings": [
                    {
                        "id": "F1",
                        "rule": RULE,
                        "location": {"path": "docs/d.md"},
                        "title": "t",
                        "source": "semantic",
                        "severity": "high",
                    }
                ]
            },
            "RECORD_INVALID",
            "target",
        ),
        (
            {
                "findings": [
                    {
                        "id": "F1",
                        "rule": RULE,
                        "location": {"path": "src/a.py"},
                        "title": "t",
                        "source": "semantic",
                        "severity": "severe",
                    }
                ]
            },
            "RECORD_INVALID",
            "severity",
        ),
        (
            {
                "conflicts": [
                    {
                        "id": "K1",
                        "kind": "requirement",
                        "description": "d",
                        "verdict_affecting": True,
                        "resolved": True,
                    }
                ]
            },
            "RECORD_INVALID",
            "resolution",
        ),
    ],
)
def test_record_refusals(tree, over, code, text):
    with pytest.raises(GuardError) as exc:
        records.apply_record(tree, _planned(tree), _record(**over))
    assert exc.value.code == code and text in exc.value.message


def test_record_content_file_must_be_safe_project_file(tree, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    for bad in (str(outside), "../secret.txt", "missing.txt"):
        with pytest.raises(GuardError) as exc:
            records.apply_record(tree, _planned(tree), _record(evidence=[_ev(content_file=bad)]))
        assert exc.value.code == "RECORD_INVALID"
    (tree / ".x-ipe" / "private" / "secure-code" / "tmp").mkdir(parents=True)
    (tree / ".x-ipe" / "private" / "secure-code" / "tmp" / "out.txt").write_text(f"tool {TOKEN}")
    _, writes = records.apply_record(
        tree, _planned(tree), _record(evidence=[_ev(content_file=".x-ipe/private/secure-code/tmp/out.txt")])
    )
    assert writes == [("E1", "tool [masked:credential.token]")]


def test_record_merge_needs_bound_evidence(tree):
    state = _planned(tree)
    f = {
        "rule": RULE,
        "location": {"path": "src/a.py", "line": 1},
        "title": "t",
        "source": "semantic",
        "severity": "high",
        "cwe": "CWE-79",
    }
    state, _ = records.apply_record(tree, state, _record(evidence=[_ev()], findings=[{"id": "F1", **f}]))
    with pytest.raises(GuardError) as exc:
        records.apply_record(tree, state, _record(findings=[{"id": "F2", **f, "merged_from": ["F1"]}]))
    assert "merge_evidence" in exc.value.message
    new, _ = records.apply_record(
        tree,
        state,
        _record(
            findings=[{"id": "F2", **f, "severity": "low", "merged_from": ["F1"], "merge_evidence": ["E1"]}]
        ),
    )
    assert next(x for x in new["findings"] if x["id"] == "F1")["merged_into"] == "F2"


def test_record_ledger_replacement_counts_superseded(tree):
    state, _ = records.apply_record(
        tree,
        _planned(tree),
        _record(evidence=[_ev()], ledger=[{"check": "C1", "state": "unconfirmed", "reason": "pending"}]),
    )
    state, _ = records.apply_record(
        tree, state, _record(ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])
    )
    assert state["ledger"]["C1"]["state"] == "met" and state["ledger"]["C1"]["superseded"] == 1


def _review(**over):
    doc = {
        "schema": "ai-secure-code-toolkit/reviewer-record/v1",
        "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
        "requirement": "Re-check F1",
        "reviewed_targets": [{"path": "src/a.py", "digest": "sha256:" + "0" * 64}],
        "subjects": [{"type": "finding", "id": "F1", "result": "confirmed", "basis": "seen"}],
    }
    doc.update(over)
    return doc


def _with_finding(tree):
    state, _ = records.apply_record(
        tree,
        _planned(tree),
        _record(
            evidence=[_ev(), _ev("E2", paths=["docs/d.md"]), _ev("E3", method_status="failed")],
            findings=[
                {
                    "id": "F1",
                    "rule": RULE,
                    "location": {"path": "src/a.py"},
                    "title": "t",
                    "source": "semantic",
                    "severity": "high",
                    "evidence": ["E1"],
                }
            ],
        ),
    )
    return state


def test_review_incomplete_is_stored_with_warnings(tree):
    record, warnings = records.validate_review(_with_finding(tree), _review(requirement="", invocation={}))
    assert record["requirement"] is None
    assert any("requirement" in w for w in warnings) and any("invocation.host" in w for w in warnings)


@pytest.mark.parametrize("key", ["targets", "scope", "ledger", "risk_acceptances", "findings", "plan"])
def test_review_extra_authority_refused(tree, key):
    with pytest.raises(GuardError) as exc:
        records.validate_review(_with_finding(tree), _review(**{key: []}))
    assert exc.value.code == "REVIEW_AUTHORITY" and key in exc.value.message


@pytest.mark.parametrize(
    ("subject", "text"),
    [
        ({"type": "adoption", "id": "F1", "result": "confirmed"}, "type"),
        ({"type": "finding", "id": "F9", "result": "confirmed"}, "unknown"),
        ({"type": "finding", "id": "F1", "result": "false_positive", "evidence": []}, "evidence"),
        ({"type": "finding", "id": "F1", "result": "false_positive", "evidence": ["E2"]}, "bound"),
        ({"type": "finding", "id": "F1", "result": "false_positive", "evidence": ["E3"]}, "bound"),
        (
            {
                "type": "finding",
                "id": "F1",
                "result": "confirmed",
                "severity_opinion": {"severity": "unknown"},
            },
            "severity",
        ),
        ({"type": "na_decision", "id": "C7", "result": "confirmed"}, "unknown"),
    ],
)
def test_review_subject_refusals(tree, subject, text):
    with pytest.raises(GuardError) as exc:
        records.validate_review(_with_finding(tree), _review(subjects=[subject]))
    assert exc.value.code == "REVIEW_INVALID" and text in exc.value.message


def test_review_accepts_bound_false_positive_and_policy_na(tree):
    record, warnings = records.validate_review(
        _with_finding(tree),
        _review(
            subjects=[
                {
                    "type": "finding",
                    "id": "F1",
                    "result": "false_positive",
                    "basis": "escaped",
                    "evidence": ["E1"],
                },
                {"type": "na_decision", "id": f"policy:{RULE2}", "result": "confirmed", "basis": "no db"},
            ]
        ),
    )
    assert warnings == [] and record["subjects"][1]["id"] == f"policy:{RULE2}"


# ---------- code re-review regressions (TASK-023)


@pytest.mark.parametrize("path", ["src/ghp_" + "Q" * 36, "AKIAQQQQQQQQQQQQQQQQ"])
def test_credential_shaped_paths_refused(tree, path):
    with pytest.raises(GuardError) as exc:
        targets.normalize(path, "x")
    assert exc.value.code == "REQUEST_INVALID" and "credential" in exc.value.message


def test_credential_shaped_paths_refused_in_plan_and_review(tree):
    state = _state(tree)
    bad = _plan(checks=[{**_plan()["checks"][0], "object": ["src/pkg/ghp_" + "Q" * 36]}])
    with pytest.raises(GuardError) as exc:
        records.validate_plan(state, bad)
    assert "credential" in exc.value.message
    with pytest.raises(GuardError) as exc:
        records.validate_review(
            _with_finding(tree),
            _review(reviewed_targets=[{"path": "AKIAQQQQQQQQQQQQQQQQ", "digest": "sha256:" + "0" * 64}]),
        )
    assert "credential" in exc.value.message


def test_non_utf8_names_in_tree_stay_serializable(tmp_path):
    from x_ipe_secure_code.atomic import dumps_json

    root = tmp_path / "p"
    (root / "s").mkdir(parents=True)
    try:
        os.symlink(b"/nowhere", os.fsencode(root / "s") + b"/lnk\xff")
    except (OSError, UnicodeError, NotImplementedError):
        pytest.skip("file system rejects non-UTF-8 names")
    snap = targets.snapshot(root, "s", "dir")
    assert snap["incomplete"] and len(snap["unreadable"]) == 1
    assert "\\xff" in snap["unreadable"][0]
    dumps_json(snap)


def test_display_name_escapes_surrogates():
    assert targets.display_name("a\udcffb") == "a\\xffb" and targets.display_name("ok/ü") == "ok/ü"


# ---------- closing review regressions (Bug Fix TASK-026)


@pytest.mark.parametrize(
    ("text", "secret", "kind"),
    [
        (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
            "lQOYBF",
            "credential.private_key",
        ),
        (
            "OPENAI_API_KEY=sk-proj-AbCdEf0123456789AbCdEf0123",
            "sk-proj-AbCdEf0123456789AbCdEf0123",
            "credential.token",
        ),
        (
            "key sk-ant-api03-AbCdEf0123456789_AbCdEf-0123",
            "sk-ant-api03-AbCdEf0123456789_AbCdEf-0123",
            "credential.token",
        ),
        (
            "the key is sk-None-Ab3dEf0123456789AbCdEf0123456789xyzT3BlbkFJ",
            "sk-None-Ab3dEf0123456789AbCdEf0123456789xyzT3BlbkFJ",
            "credential.token",
        ),
        ("export DB_PASSWORD=Zq8vLr2mNp4tXw9y", "Zq8vLr2mNp4tXw9y", "credential.assignment"),
        ("SERVICE_TOKEN: hunter2hunter2", "hunter2hunter2", "credential.assignment"),
    ],
)
def test_guard_masks_more_credential_formats(text, secret, kind):
    masked, kinds = mask_text(text)
    assert secret not in masked and kind in kinds


def test_unquoted_placeholders_stay():
    for text in ("API_KEY=changeme", "TOKEN=${API_TOKEN}", "PASSWORD=<your-password>", "SECRET_COUNT=3"):
        assert mask_text(text) == (text, []), text


@pytest.mark.parametrize("text", ["key." * 50000, "KEY" * 70000, "tokentoken" * 20000])
def test_masking_stays_linear_on_degenerate_lines(text):
    import time

    start = time.perf_counter()
    mask_text(text)
    assert time.perf_counter() - start < 2.0


@pytest.mark.parametrize(
    "path", ["src/sk-learn-model-preprocessing-pipeline.py", "css/sk-circle-bounce-animation-delay.css"]
)
def test_ordinary_sk_slugs_are_not_credentials(path):
    assert targets.normalize(path, "targets[0]") == path
    assert mask_text(path) == (path, [])
