"""Owner-only, lease-held staging of the reviewed payload (FEATURE-001-G, DEC-3, DAO-015; Step 9).

Review tests R5…R10 and R14…R16: crash leftovers and sweep, active leases never targeted, concurrent
approvals, link races, permissions, no knowledge lock across `update_rule`, post-write WRITE_MISMATCH
detection of a same-account swap, and the pre-call STAGING_CHANGED refusal.
"""

from __future__ import annotations

import json
import os
import re
import stat

import pytest
from conftest import posix_only, run_cli
from drafthelp import PY, R78, R89, STAGING, DEnv, codes, mod
from knowledge.exithelp import cleanup, finish, need_symlinks, wait_ready

from x_ipe_secure_code.knowledge import durable, store

R78_EXAMPLE = {
    "unsafe": "subprocess.run('ls ' + name, shell=True)",
    "safe": "subprocess.run(['ls', name])",
    "demonstrates": ["MUST NOT pass untrusted input to a command interpreter."],
}


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


def approve_args(env, draft, review, digest):
    return [
        "knowledge",
        "draft-approve",
        "--project",
        str(env.project),
        "--draft",
        str(draft),
        "--review",
        str(review),
        "--validation-digest",
        digest,
        "--json",
    ]


def checked(env, rule=R89, examples=None, name="cwe-89--python"):
    draft, review = env.drafted(rule, examples, name=name)
    return draft, review, env.check(draft, review).data["validation_digest"]


def staging(env):
    folder = env.project / STAGING
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


def knowledge_tree(env):
    return {k: v for k, v in env.tree().items() if "drafting-staging" not in k}


# R5 + R10: crash after staging; knowledge unchanged; owner-only leftovers; next approval sweeps them.
def test_crash_before_update_call_swept_next_approve(env):
    draft, review, digest = checked(env)
    before = env.rule_files()
    process = run_cli(
        approve_args(env, draft, review, digest),
        env.trust,
        env_extra={"SECURE_CODE_TEST_CRASH_AT": "drafting_staged"},
    )
    assert process.returncode == 86, process.stdout + process.stderr
    assert env.rule_files() == before
    left = staging(env)
    assert len(left) == 2 and {re.sub(r"[0-9a-f]{32}", "X", n) for n in left} == {
        "lease-X.lock",
        "payload-X.json",
    }
    if os.name != "nt":
        assert stat.S_IMODE((env.project / STAGING).stat().st_mode) == 0o700
        for name in left:
            assert stat.S_IMODE((env.project / STAGING / name).stat().st_mode) == 0o600
    result = env.approve(draft, review, digest)
    assert result.ok, result.to_dict()
    assert staging(env) == []


# R6: crash inside the delivered update_rule (store commit crash point); delivered recovery; sweep.
def test_crash_during_update_call_recovered_and_swept(env):
    draft, review, digest = checked(env)
    old_state = env.state()
    process = run_cli(
        approve_args(env, draft, review, digest),
        env.trust,
        env_extra={"SECURE_CODE_TEST_CRASH_AT": "after_journal"},
    )
    assert process.returncode == 86, process.stdout + process.stderr
    assert any(n.startswith("payload-") for n in staging(env))
    shown = env.show(R89)
    assert shown.data["consistent"] and shown.data["state_digest"] != old_state
    other, other_review, other_digest = checked(env, R78, {"python": R78_EXAMPLE}, "cwe-78--python")
    result = env.approve(other, other_review, other_digest)
    assert result.ok, result.to_dict()
    assert staging(env) == []
    assert "x-ipe-ai-supplement" in env.show(R89).data["examples"]["example-python.md"]


# R7: the sweep never targets an active lease.
def test_cleanup_never_targets_active_lease(env, tmp_path):
    draft, review, digest = checked(env)
    pause = tmp_path / "staged"
    paused = env.spawn(
        approve_args(env, draft, review, digest), SECURE_CODE_TEST_PAUSE_AT=f"drafting_staged={pause}"
    )
    try:
        wait_ready(paused, pause)
        active = staging(env)
        other, other_review, other_digest = checked(env, R78, {"python": R78_EXAMPLE}, "cwe-78--python")
        result = env.approve(other, other_review, other_digest)
        assert result.ok, result.to_dict()
        assert staging(env) == active
        pause.with_suffix(".go").write_text("go")
        assert finish(paused)["ok"] is True
    finally:
        cleanup(paused)
    assert staging(env) == []


# R8: two rules approved in parallel; no partial writes or cross-deletion.
def test_concurrent_approvals_distinct_leases(env):
    a = checked(env)
    b = checked(env, R78, {"python": R78_EXAMPLE}, "cwe-78--python")
    first, second = env.spawn(approve_args(env, *a)), env.spawn(approve_args(env, *b))
    try:
        results = [finish(first), finish(second)]
    finally:
        cleanup(first, second)
    for result, rule in zip(results, (R89, R78), strict=True):
        assert result["ok"] or result["problems"][0]["code"] == "LOCKED", result
        has_block = b"x-ipe-ai-supplement" in env.rule_files(rule).get("example-python.md", b"")
        assert has_block == result["ok"]
        assert env.show(rule).data["consistent"]
    assert staging(env) == []


# R9: link races in the staging area.
@posix_only
@pytest.mark.parametrize("case", ["staging_dir_link", "payload_name_link", "matching_non_regular_entry"])
def test_symlink_races(env, tmp_path, monkeypatch, case):
    need_symlinks(tmp_path)
    draft, review, digest = checked(env)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_text("victim\n")
    folder = env.project / STAGING
    fixed = "f" * 32
    calls = []
    service = mod("drafting_service")
    real = service.service.update_rule
    monkeypatch.setattr(service.service, "update_rule", lambda *a, **k: calls.append(a) or real(*a, **k))
    if case == "staging_dir_link":
        folder.symlink_to(outside, target_is_directory=True)
    else:
        folder.mkdir(mode=0o700)
        monkeypatch.setattr(service.secrets, "token_hex", lambda n: fixed)
        if case == "payload_name_link":
            (folder / f"payload-{fixed}.json").symlink_to(outside / "victim.json")
        else:
            (folder / f"payload-{'e' * 32}.json").mkdir()
    before = knowledge_tree(env)
    result = env.approve(draft, review, digest)
    assert codes(result) == ["PATH_UNSAFE"], result.to_dict()
    assert calls == [] and knowledge_tree(env) == before
    assert sorted(p.name for p in outside.iterdir()) == ["victim.json"]
    assert (outside / "victim.json").read_text() == "victim\n"
    if case == "matching_non_regular_entry":
        assert (folder / f"payload-{'e' * 32}.json").is_dir()


# R10: an own pre-existing permissive staging folder is tightened to owner-only.
@posix_only
def test_staging_permissions_posix(env):
    folder = env.project / STAGING
    folder.mkdir(mode=0o755)
    os.chmod(folder, 0o755)
    assert env.checked_approve(*env.drafted()).ok
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


# R14: no knowledge lock is held across update_rule (no self-deadlock).
def test_no_knowledge_lock_held_across_update_rule(env, monkeypatch):
    import time

    service = mod("drafting_service")
    real = service.service.update_rule
    seen = []

    def wrapped(*args, **kwargs):
        with durable.Tree(env.project) as tree, durable.DirLock(tree, store.LOCK_REL, create=True, timeout=0):
            seen.append("free")
        started = time.monotonic()
        result = real(*args, **kwargs)
        seen.append(time.monotonic() - started)
        return result

    monkeypatch.setattr(service.service, "update_rule", wrapped)
    result = env.checked_approve(*env.drafted())
    assert result.ok, result.to_dict()
    assert seen[0] == "free" and seen[1] < 5


# R15: a same-account swap after the final re-read is detected after the write (WRITE_MISMATCH).
def test_staging_swap_after_reread_write_mismatch(env, tmp_path):
    draft, review, digest = checked(env)
    pause = tmp_path / "reread"
    entries_before = env.rule_files()["changelog.md"].decode().count("\n## ")
    paused = env.spawn(
        approve_args(env, draft, review, digest), SECURE_CODE_TEST_PAUSE_AT=f"drafting_after_reread={pause}"
    )
    try:
        wait_ready(paused, pause)
        payload = next((env.project / STAGING).glob("payload-*.json"))
        swapped = payload.with_name("swap.tmp")
        swapped.write_text(
            json.dumps(
                {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "examples": {"python": "x = 1\n"}}
            )
        )
        os.replace(swapped, payload)
        pause.with_suffix(".go").write_text("go")
        out = finish(paused)
    finally:
        cleanup(paused)
    assert out["ok"] is False and out["problems"][0]["code"] == "WRITE_MISMATCH", out
    shown = env.show(R89)
    message = out["problems"][0]["message"]
    assert (
        R89 in message
        and shown.data["state_digest"] in message
        and "differ from the reviewed payload" in message
    )
    log = env.rule_files()["changelog.md"].decode()
    assert log.count("\n## ") == entries_before + 1 and out["data"]["changelog_entry"] in log
    assert env.rule_files()["example-python.md"] == b"x = 1\n"
    assert "knowledge show" in out["next_steps"][0] and "knowledge update" in out["next_steps"][1]
    assert out["data"]["applied"] is False


# R16: a payload altered before the re-read → STAGING_CHANGED, update_rule never called.
def test_staging_changed_before_call_not_written(env, tmp_path):
    draft, review, digest = checked(env)
    pause = tmp_path / "staged"
    before = knowledge_tree(env)
    paused = env.spawn(
        approve_args(env, draft, review, digest), SECURE_CODE_TEST_PAUSE_AT=f"drafting_staged={pause}"
    )
    try:
        wait_ready(paused, pause)
        payload = next((env.project / STAGING).glob("payload-*.json"))
        payload.write_text(payload.read_text().replace("fetchall", "fetchone"))
        pause.with_suffix(".go").write_text("go")
        out = finish(paused)
    finally:
        cleanup(paused)
    assert out["problems"][0]["code"] == "STAGING_CHANGED", out
    assert knowledge_tree(env) == before and staging(env) == []
    assert PY


# DEC-I16 (independent review issue 2): a legitimate write by another command after the successful
# update_rule call is not a staging swap — success with a note, no WRITE_MISMATCH and no restore advice.
def test_concurrent_write_after_update_is_not_write_mismatch(env, monkeypatch):
    service = mod("drafting_service")
    real = service.service.update_rule

    def wrapped(*args, **kwargs):
        result = real(*args, **kwargs)
        assert result.ok, result.to_dict()
        text = env.rule_files()["example-python.md"].decode() + "# later legitimate human note\n"
        later = env.req(
            {"schema": "ai-secure-code-toolkit/knowledge-update/v1", "examples": {"python": text}}
        )
        other = real(str(env.project), R89, result.data["state_digest"], later, [], trust_paths=env.paths)
        assert other.ok, other.to_dict()
        return result

    monkeypatch.setattr(service.service, "update_rule", wrapped)
    result = env.checked_approve(*env.drafted())
    assert result.ok and codes(result) == [], result.to_dict()
    assert result.data["changed_after_approval"]["state_digest"] == env.state()
    assert "restore" not in (result.to_json() + result.to_text()).lower()
    text = env.rule_files()["example-python.md"]
    assert b"x-ipe-ai-supplement" in text and text.endswith(b"# later legitimate human note\n")
