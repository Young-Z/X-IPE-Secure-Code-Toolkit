"""Lifecycle and concurrency interplay of drafts (FEATURE-001-G, AC-001G-06a…06d, 06g, 06h; Step 11)."""

from __future__ import annotations

import json
import time

import pytest
from drafthelp import A03, FIXTURES, PY, R78, R89, DEnv, codes, fixture_items, mod
from knowledge.exithelp import REASON, cleanup, finish, wait_ready

from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import service as policy


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


# AC-001G-06a
def test_06a_second_draft_stale_after_first_approval(env):
    first = env.drafted(name="first")
    second = env.drafted(
        examples={"python": dict(PY, safe=PY["safe"] + "\nconnection.close()")}, name="second"
    )
    digest = env.check(*second).data["validation_digest"]
    assert env.checked_approve(*first).ok
    checked = env.check(*second)
    assert checked.data["status"] == "stale_base" and checked.data["base"] == "stale_base"
    before = env.tree()
    refused = env.approve(*second, digest)
    assert codes(refused)[0] == "STATE_CONFLICT" and env.tree() == before


# AC-001G-06b: update, accepted import update, deactivate and reactivate all make a pending draft stale.
@pytest.mark.parametrize("change", ["update", "import_update", "deactivate", "reactivate"])
def test_06b_stale_after_update_import_deactivate_reactivate(env, change):
    if change == "reactivate":
        env.exit("deactivate", R89)
    draft, review = env.drafted()
    files = env.rule_files()
    if change == "update":
        assert env.update(R89, env.state(), examples={"java": "// other\nrun();\n"}).ok
    elif change == "import_update":
        item = dict(fixture_items("seed_batch.json")[0], content="# changed\n\n- MUST change.\n")
        digest = env.show(R89).data["item_digest"]
        result = env.load(item, accept=(f"{R89}@{digest}",))
        assert result.data["items"][0]["outcome"] == "stored", result.to_dict()
    else:
        env.exit(change, R89)
    checked = env.check(draft, review)
    assert checked.data["base"] == "stale_base"
    assert checked.data["status"] == ("rule_inactive" if change == "deactivate" else "stale_base")
    assert checked.data.get("validation_digest") is None
    after = env.rule_files()
    assert all(b"x-ipe-ai-supplement" not in text for text in after.values())
    assert set(after) >= set(files) - {"changelog.md", "record.json"}


# AC-001G-06c
def test_06c_deactivated_rule_inactive_next_step(env):
    draft, review = env.drafted()
    env.exit("deactivate", R89)
    env.write_draft(env.draft_doc(), "cwe-89--python")
    review = env.write_review(draft)
    checked = env.check(draft, review)
    assert checked.data["status"] == "rule_inactive" and codes(checked) == ["RULE_INACTIVE"]
    assert "reactivate" in checked.next_steps[0].lower()
    refused = env.approve(draft, review, "sha256:" + "3" * 64)
    assert codes(refused) == ["RULE_INACTIVE"] and "reactivate" in refused.next_steps[0].lower()


# AC-001G-06d: deleted or renamed-away rules are not found; the draft never follows a rename.
@pytest.mark.parametrize("action", ["delete", "rename"])
def test_06d_deleted_or_renamed_refused_new_identity_untouched(env, action):
    draft, review = env.drafted()
    target = "CWE/Top25-2025/CWE-89-NEW"
    env.exit(action, R89, target=target if action == "rename" else None)
    renamed = env.rule_files(target) if action == "rename" else None
    before = env.tree()
    for result in (env.check(draft, review), env.approve(draft, review, "sha256:" + "4" * 64)):
        assert codes(result) == ["RULE_NOT_FOUND"]
    if renamed is not None:
        assert env.rule_files(target) == renamed
    assert env.tree() == before


# AC-001G-06g: an adopted scope reports the rule needs_reconfirmation (unchanged 001-C behaviour).
def test_06g_adopted_scope_needs_reconfirmation(env):
    saved = env.save(env.decisions((R89, A03)))
    assert saved.ok, saved.to_dict()
    assert env.checked_approve(*env.drafted()).ok
    shown = policy.show_scope(str(env.project), saved.data["scope_id"])
    states = {e["rule"]: e["adoption"] for e in shown.data["entries"]}
    assert states == {R89: "needs_reconfirmation", A03: "adopted"}


# AC-001G-06h: approval vs 001-D exit-confirm on the same rule are serialized by the delivered lock.
def test_06h_approve_vs_exit_confirm_serialized_and_locked(env, tmp_path):
    draft, review = env.drafted()
    digest = env.check(draft, review).data["validation_digest"]
    preview = env.preview("deactivate", R89)
    pause = tmp_path / "exit-pause"
    holder = env.spawn(
        [
            "knowledge",
            "exit-confirm",
            "--project",
            str(env.project),
            "--rule",
            R89,
            "--action",
            "deactivate",
            "--reason",
            REASON,
            "--impact-digest",
            preview.data["impact_digest"],
            "--json",
        ],
        SECURE_CODE_TEST_PAUSE_AT=f"exit_locked={pause}",
    )
    try:
        wait_ready(holder, pause)
        before = env.tree()
        started = time.monotonic()
        locked = env.approve(draft, review, digest)
        assert codes(locked) == ["LOCKED"] and time.monotonic() - started >= 5
        assert env.tree() == before
        pause.with_suffix(".go").write_text("go")
        assert finish(holder)["ok"] is True
    finally:
        cleanup(holder)
    shown = env.show(R89)
    assert shown.data["consistent"] and shown.data["state"] == "deactivated"
    assert codes(env.approve(draft, review, digest)) == ["RULE_INACTIVE"]


def test_06h_race_loop_consistent(project, tmp_path):
    outcomes = set()
    for run in range(20):
        root = tmp_path / f"race-{run}"
        root.mkdir()
        env = DEnv(root, tmp_path / f"work-{run}")
        draft, review = env.drafted()
        digest = env.check(draft, review).data["validation_digest"]
        preview = env.preview("deactivate", R89)
        approve = env.spawn(
            [
                "knowledge",
                "draft-approve",
                "--project",
                str(root),
                "--draft",
                str(draft),
                "--review",
                str(review),
                "--validation-digest",
                digest,
                "--json",
            ]
        )
        exits = env.spawn(
            [
                "knowledge",
                "exit-confirm",
                "--project",
                str(root),
                "--rule",
                R89,
                "--action",
                "deactivate",
                "--reason",
                REASON,
                "--impact-digest",
                preview.data["impact_digest"],
                "--json",
            ]
        )
        try:
            a, e = finish(approve), finish(exits)
        finally:
            cleanup(approve, exits)
        shown = env.show(R89)
        assert shown.data["consistent"], shown.to_dict()
        text = env.rule_files().get("example-python.md", b"")
        assert a["ok"] == (b"x-ipe-ai-supplement" in text)
        if not a["ok"]:
            assert a["problems"][0]["code"] in ("STATE_CONFLICT", "RULE_INACTIVE", "LOCKED"), a
        if not e["ok"]:
            assert e["problems"][0]["code"] in ("STALE_IMPACT", "LOCKED"), e
        outcomes.add((a["ok"], e["ok"]))
        assert not list((root / ".x-ipe/private/secure-code/drafting-staging").glob("payload-*"))
    assert outcomes
    assert json.dumps(sorted(outcomes)) and FIXTURES.is_dir() and store.LOCAL_REL and mod and R78
