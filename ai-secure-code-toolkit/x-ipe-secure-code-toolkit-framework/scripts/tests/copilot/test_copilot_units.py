"""Unit tests for FEATURE-003-A shared helpers and Copilot modules (manifest, engine, report)."""

from __future__ import annotations

import os

import pytest

from x_ipe_secure_code.guard import targets
from x_ipe_secure_code.policy import service as policy_service
from x_ipe_secure_code.results import Result

posix = pytest.mark.skipif(os.name == "nt", reason="symbolic links need POSIX in these tests")

# Captured from guard.targets._tree BEFORE the walk was split (FEATURE-003-A step 2).
TREE_DIGEST = "sha256:563939f1a573d4508940dc8dd60bd43287988f7ad7e464847d00ff4dc1b436e7"


def _fixed_tree(root):
    t = root / "t"
    (t / "sub").mkdir(parents=True)
    (t / ".git").mkdir()
    (t / "a.txt").write_bytes(b"alpha\n")
    (t / "sub" / "b.py").write_bytes(b"print(1)\n")
    (t / ".git" / "x").write_bytes(b"x")
    os.symlink("a.txt", t / "ln")
    os.symlink("../outside", t / "out")
    return t


@posix
def test_tree_digest_unchanged_by_walk_split(tmp_path):
    _fixed_tree(tmp_path)
    tree = targets._tree(tmp_path, "t")
    assert tree == {
        "digest": TREE_DIGEST,
        "incomplete": True,
        "not_followed": [{"path": "t/ln", "inside_tree": True}],
        "unreadable": ["t/out"],
    }


@posix
def test_tree_files_lists_regular_files_and_not_bindable(tmp_path):
    _fixed_tree(tmp_path)
    found = targets.tree_files(tmp_path, "t")
    assert found["files"] == {
        "t/a.txt": targets.file_digest(tmp_path / "t" / "a.txt"),
        "t/sub/b.py": targets.file_digest(tmp_path / "t" / "sub" / "b.py"),
    }
    assert [n["path"] for n in found["not_bindable"]] == ["t/ln", "t/out"]
    assert all(n["reason"] for n in found["not_bindable"]) and found["truncated"] is False


def test_tree_files_stops_after_limit(tmp_path):
    (tmp_path / "d").mkdir()
    for i in range(5):
        (tmp_path / "d" / f"f{i}.txt").write_text(str(i))
    found = targets.tree_files(tmp_path, "d", limit=3)
    assert found["truncated"] is True and len(found["files"]) == 4


def test_tree_files_marks_credential_like_names_not_bindable(tmp_path):
    (tmp_path / "d").mkdir()
    name = "ghp_" + "a" * 36
    (tmp_path / "d" / name).write_text("x")
    (tmp_path / "d" / "ok.txt").write_text("x")
    found = targets.tree_files(tmp_path, "d")
    assert list(found["files"]) == ["d/ok.txt"]
    assert found["not_bindable"] == [
        {"path": "d/[masked:credential.token]", "reason": "name looks like a credential"}
    ]


# --------------------------------------------------------------------------- adoption_now
def _loaded(entries):
    return {"status": "complete", "entries": entries}


ADOPTED = [
    {"rule": "A/1/X", "state_digest": "sha256:1"},
    {"rule": "A/1/Y", "state_digest": "sha256:2"},
    {"rule": "A/1/Z", "state_digest": "sha256:3"},
    {"rule": "A/1/W", "state_digest": "sha256:4"},
]


def test_adoption_now_compares_confirmed_digests(monkeypatch, tmp_path):
    entries = [
        {"rule": "A/1/X", "adoption": "adopted", "confirmed_state_digest": "sha256:1"},
        {"rule": "A/1/Y", "adoption": "adopted", "confirmed_state_digest": "sha256:other"},
        {"rule": "A/1/Z", "adoption": "missing", "confirmed_state_digest": "sha256:3"},
    ]
    monkeypatch.setattr(policy_service, "load_adopted", lambda *a: _loaded(entries))
    now = policy_service.adoption_now(tmp_path, "sha256:s", ADOPTED, "copilot report")
    assert now == {"A/1/X": "unchanged", "A/1/Y": "changed", "A/1/Z": "missing", "A/1/W": "missing"}


@pytest.mark.parametrize("code,returned", [("LOCKED", True), ("IO_ERROR", True), ("SCOPE_NOT_FOUND", False)])
def test_adoption_now_refusals(monkeypatch, tmp_path, code, returned):
    refused = Result.refused("x", code, "m", "n")
    monkeypatch.setattr(policy_service, "load_adopted", lambda *a: refused)
    now = policy_service.adoption_now(tmp_path, "sha256:s", ADOPTED, "x")
    assert (now is refused) if returned else (now == {})


def test_guard_policy_now_delegates(monkeypatch, tmp_path):
    from x_ipe_secure_code.guard import service as guard_service
    from x_ipe_secure_code.guard.model import GuardError

    calls = []

    def fake(root, scope_id, adopted, command):
        calls.append((scope_id, command))
        return {"A/1/X": "unchanged"} if scope_id == "ok" else Result.refused(command, "LOCKED", "busy", "r")

    monkeypatch.setattr(guard_service, "adoption_now", fake)
    state = {"scope": {"scope_id": "ok", "adopted": ADOPTED[:1]}}
    assert guard_service._policy_now(tmp_path, state, "guard conclude") == {"A/1/X": "unchanged"}
    state["scope"]["scope_id"] = "busy"
    with pytest.raises(GuardError) as err:
        guard_service._policy_now(tmp_path, state, "guard conclude")
    assert err.value.code == "LOCKED" and calls == [("ok", "guard conclude"), ("busy", "guard conclude")]


# --------------------------------------------------------------------------- engine
R = "CWE/4.14/CWE-79"
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64


def _state(suggestions, reviews, manifest=None, invalidated=None):
    return {
        "schema": "ai-secure-code-toolkit/copilot-collab/v1",
        "collaboration_id": "cp-20261021T101500Z-1a2b3c4d",
        "status": "open",
        "opened_at": "2026-10-21T10:15:00Z",
        "closed_at": None,
        "revision": 1,
        "stage": "implementation",
        "task": "t",
        "masked": [],
        "scope": {
            "scope_id": "sha256:s",
            "mode": "clues",
            "adopted": [{"rule": R, "state_digest": "sha256:r"}],
        },
        "artifacts": [],
        "manifest": manifest
        or {
            "a.py": {
                "digest": D1,
                "change": "modified",
                "old_path": None,
                "source": "a.py",
                "recorded_at": "t",
            },
            "b.py": {
                "digest": D1,
                "change": "modified",
                "old_path": None,
                "source": "b.py",
                "recorded_at": "t",
            },
        },
        "context": [],
        "suggestions": suggestions,
        "reviews": reviews,
        "invalidated_rules": invalidated or {},
        "rounds": [],
    }


def _s(sid, files=("a.py",), severity="high", rule=R):
    return {
        "id": sid,
        "rule": rule,
        "files": list(files),
        "location": "l",
        "action": "a",
        "reason": "r",
        "severity": severity,
        "stage": "implementation",
        "masked": [],
        "batch": 1,
        "recorded_at": "t",
    }


def _r(seq, subjects, reviewed, completeness=(), wrong=()):
    return {
        "seq": seq,
        "invocation": {"host": "h", "agent": "a", "read_only": True, "invoked_at": "t", "declared": True},
        "requirement": "q",
        "reviewed_targets": [{"path": p, "digest": d} for p, d in reviewed],
        "subjects": [{"type": "adoption", "id": i, "result": res, "basis": f"b{seq}"} for i, res in subjects],
        "reviewed_at": "t",
        "completeness": list(completeness),
        "wrong_version": list(wrong),
        "masked": [],
        "recorded_at": "t",
    }


def _eval(state, current=None, policy=None):
    from x_ipe_secure_code.copilot import engine

    current = current if current is not None else {"a.py": D1, "b.py": D1}
    return engine.evaluate(state, current, policy if policy is not None else {R: "unchanged"})


def _states(content):
    return {s["id"]: s["state"] for s in content["suggestions"]}


def test_engine_not_reviewed_then_result_then_stale():
    st = _state([_s("S1"), _s("S2", files=("b.py",))], [])
    assert _states(_eval(st)) == {"S1": "not_reviewed", "S2": "not_reviewed"}
    st["reviews"] = [_r(1, [("S1", "adopted"), ("S2", "not_adopted")], [("a.py", D1), ("b.py", D1)])]
    assert _states(_eval(st)) == {"S1": "adopted", "S2": "not_adopted"}
    content = _eval(st, {"a.py": D2, "b.py": D1})
    assert _states(content) == {"S1": "stale", "S2": "not_adopted"}
    assert content["suggestions"][0]["changed"] == [{"path": "a.py", "change": "modified"}]
    assert content["suggestions"][0]["history"] == [{"seq": 1, "result": "adopted", "basis": "b1"}]


def test_engine_policy_changed_has_precedence_and_is_monotonic():
    from x_ipe_secure_code.copilot import engine

    st = _state([_s("S1")], [_r(1, [("S1", "adopted")], [("a.py", D1)])])
    assert _states(_eval(st, policy={R: "changed"})) == {"S1": "policy_changed"}
    assert _states(_eval(st, policy={})) == {"S1": "policy_changed"}
    st["invalidated_rules"] = {R: {"detected_at": "t", "now": "changed"}}
    assert _states(_eval(st, policy={R: "unchanged"})) == {"S1": "policy_changed"}
    assert engine.invalidated(st, {R: "unchanged"}) == {R: {"detected_at": "t", "now": "changed"}}
    fresh = engine.invalidated(_state([], []), {R: "missing"})
    assert fresh == {R: {"detected_at": None, "now": "missing"}}


def test_engine_absent_marker_matches_missing_file():
    manifest = {
        "a.py": {"digest": None, "change": "deleted", "old_path": None, "source": "a.py", "recorded_at": "t"}
    }
    st = _state([_s("S1")], [_r(1, [("S1", "not_applicable")], [("a.py", "absent")])], manifest=manifest)
    assert _states(_eval(st, {"a.py": None})) == {"S1": "not_applicable"}
    content = _eval(st, {"a.py": D1})
    assert _states(content) == {"S1": "stale"}
    assert content["suggestions"][0]["changed"] == [{"path": "a.py", "change": "modified"}]


def test_engine_invalid_records_never_count():
    st = _state(
        [_s("S1"), _s("S2", files=("b.py",))],
        [
            _r(1, [("S1", "adopted")], [("a.py", D1)], completeness=["requirement is missing"]),
            _r(2, [("S2", "adopted")], [("b.py", D2)], wrong=["b.py"]),
            _r(3, [("S1", None)], [("a.py", D1)], completeness=["subjects[0].result is missing"]),
        ],
    )
    content = _eval(st)
    assert _states(content) == {"S1": "not_reviewed", "S2": "not_reviewed"}
    assert content["snapshot_before_review"] is True
    assert [r["valid"] for r in content["reviews"]] == [False, False, False]
    assert content["reviews"][1]["not_counted"] == [{"id": "S2", "reason": "wrong version of b.py"}]
    assert content["reviews"][0]["not_counted"] == [{"id": "S1", "reason": "record incomplete"}]


def test_engine_attention_gaps_and_order():
    sugs = [
        _s("A", severity="unknown"),
        _s("B", severity="critical"),
        _s("C", severity="low"),
        _s("D", severity="high"),
        _s("E", severity="info"),
    ]
    st = _state(sugs, [_r(1, [("E", "adopted"), ("D", "partial")], [("a.py", D1)])])
    content = _eval(st)
    assert [(a["id"], a["state"]) for a in content["attention"]] == [
        ("B", "not_reviewed"),
        ("D", "partial"),
        ("A", "not_reviewed"),
    ]
    assert [g["id"] for g in content["gaps"]] == ["C"]
    assert content["re_review"] == ["A", "B", "C"]
    assert content["counts"] == {
        "adopted": 1,
        "partial": 1,
        "not_adopted": 0,
        "not_applicable": 0,
        "cannot_verify": 0,
        "not_reviewed": 3,
        "stale": 0,
        "policy_changed": 0,
    }


def test_engine_signature_stable_and_sensitive():
    from x_ipe_secure_code.copilot import engine

    st = _state([_s("S1")], [])
    a = engine.signature(_eval(st))
    assert a == engine.signature(_eval(st)) and a.startswith("sha256:")
    assert engine.signature(_eval(st, {"a.py": D2, "b.py": D1})) != a
    assert engine.signature(_eval(st, policy={R: "changed"})) != a


def test_engine_content_has_no_round_fields_or_verdict():
    content = _eval(_state([_s("S1")], []))
    for key in ("round", "supersedes", "published_at", "state_signature", "pass", "verdict", "approved"):
        assert key not in content


# --------------------------------------------------------------------------- records helpers
def test_labelling_checker_records_masked_fields():
    from x_ipe_secure_code.copilot.records import LabellingChecker

    ck = LabellingChecker("X", "fix")
    assert ck.text("plain", "a") == "plain"
    masked = ck.text("token ghp_" + "e" * 36, "subjects[1].basis")
    assert "[masked:credential.token]" in masked and ck.masked == ["subjects[1].basis"]
    assert ck.text(None, "b", required=False) is None and ck.masked == ["subjects[1].basis"]


def test_labelling_checker_refuses_literal_mask_markers():
    """Review TASK-045: agent text must not pose as toolkit-masked content."""
    from x_ipe_secure_code.copilot.records import LabellingChecker
    from x_ipe_secure_code.guard.model import GuardError

    ck = LabellingChecker("X", "fix")
    with pytest.raises(GuardError) as err:
        ck.text("see [masked:credential.token](https://evil.example/phish)", "action")
    assert err.value.code == "X" and "mask marker" in err.value.message and ck.masked == []


def test_report_mask_marker_never_forms_a_link():
    from x_ipe_secure_code.copilot.report import cell

    out = cell("[masked:credential.token](https://evil.example/phish)")
    assert "](https://" not in out.replace("`](https://", "")
    assert "`[masked:credential.token]`" in out


# --------------------------------------------------------------------------- report
def test_report_render_escapes_and_footer():
    from x_ipe_secure_code.atomic import dumps_json
    from x_ipe_secure_code.copilot import report

    st = _state([_s("S1")], [])
    st["task"] = "# heading <script>"
    content = _eval(st)
    result = {
        **content,
        "round": 1,
        "supersedes": None,
        "published_at": "2026-10-21T11:00:00Z",
        "private_data_present_as_of_publication": True,
        "state_signature": "sha256:x",
    }
    md = report.render(result)
    assert "\\# heading \\<script\\>" in md and "<script>" not in md
    assert report.footer_digest(md) == report.sha256_hex(dumps_json(result))
    assert md == report.render(result)
    assert report.footer_digest("no footer") is None
