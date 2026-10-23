"""Unit tests for the host entry fragment (AC-001A-04h, 04i)."""

from __future__ import annotations

from x_ipe_secure_code import host_fragment as hf

BODY = "## AI Secure Code Toolkit\nUse the skills.\n"


def test_create_file_when_absent():
    plan = hf.plan_upsert(None, BODY, recorded_sha=None, replace=False)
    assert plan.outcome == "create_file" and not plan.blocking
    assert plan.new_bytes.decode().count(hf.BEGIN) == 1


def test_append_preserves_prefix_bytes_lf():
    original = b"# My agents\n\nKeep this exactly.  \n"
    plan = hf.plan_upsert(original, BODY, recorded_sha=None, replace=False)
    assert plan.outcome == "append"
    assert plan.new_bytes.startswith(original)
    assert plan.new_bytes.count(hf.BEGIN.encode()) == 1


def test_append_without_trailing_newline_and_crlf():
    original = b"line one\r\nline two"
    plan = hf.plan_upsert(original, BODY, recorded_sha=None, replace=False)
    assert plan.new_bytes.startswith(original)
    tail = plan.new_bytes[len(original):]
    assert b"\r\n" in tail and b"\n" not in tail.replace(b"\r\n", b"")


def test_idempotent_when_unchanged():
    first = hf.plan_upsert(b"intro\n", BODY, recorded_sha=None, replace=False)
    second = hf.plan_upsert(first.new_bytes, BODY, recorded_sha=first.inner_sha, replace=False)
    assert second.outcome == "current" and second.new_bytes is None


def test_update_when_unedited_and_toolkit_text_changed():
    first = hf.plan_upsert(b"intro\n", BODY, recorded_sha=None, replace=False)
    second = hf.plan_upsert(first.new_bytes, BODY + "More.\n", recorded_sha=first.inner_sha,
                            replace=False)
    assert second.outcome == "update"
    assert second.new_bytes.startswith(b"intro\n")
    assert b"More." in second.new_bytes


def test_user_edited_fragment_kept_and_reported_then_replaced_on_choice():
    first = hf.plan_upsert(b"intro\n", BODY, recorded_sha=None, replace=False)
    edited = first.new_bytes.replace(b"Use the skills.", b"Use the skills carefully.")
    kept = hf.plan_upsert(edited, BODY, recorded_sha=first.inner_sha, replace=False)
    assert kept.outcome == "edited_kept" and kept.new_bytes is None
    assert kept.problem.code == "FRAGMENT_EDITED" and not kept.blocking
    replaced = hf.plan_upsert(edited, BODY, recorded_sha=first.inner_sha, replace=True)
    assert replaced.outcome == "replaced" and b"carefully" not in replaced.new_bytes
    assert replaced.new_bytes.startswith(b"intro\n")


def test_outside_bytes_identical_on_update():
    prefix, suffix = b"top \xc3\xa9\n", b"\nbottom\n"
    block = hf.plan_upsert(None, BODY, None, False).new_bytes
    data = prefix + block + suffix
    plan = hf.plan_upsert(data, BODY + "x\n", recorded_sha=hf.sha256_text(BODY), replace=False)
    assert plan.new_bytes.startswith(prefix) and plan.new_bytes.endswith(suffix)


def test_duplicate_and_malformed_are_blocking():
    block = hf.plan_upsert(None, BODY, None, False).new_bytes
    dup = hf.plan_upsert(block + block, BODY, None, False)
    assert dup.blocking and dup.problem.code == "FRAGMENT_DUPLICATE"
    unmatched = hf.plan_upsert(b"x\n" + hf.BEGIN.encode() + b"\n", BODY, None, False)
    assert unmatched.blocking and unmatched.problem.code == "FRAGMENT_MALFORMED"
    reversed_ = hf.plan_upsert((hf.END + "\n" + hf.BEGIN + "\n").encode(), BODY, None, False)
    assert reversed_.blocking and reversed_.problem.code == "FRAGMENT_MALFORMED"


def test_non_utf8_is_blocking():
    plan = hf.plan_upsert(b"\xff\xfe\x00bad", BODY, None, False)
    assert plan.blocking and plan.problem.code == "HOST_ENTRY_UNREADABLE"


def test_inspect_states():
    block = hf.plan_upsert(None, BODY, None, False)
    assert hf.inspect(None, block.inner_sha) == "absent_file"
    assert hf.inspect(b"nothing\n", block.inner_sha) == "absent"
    assert hf.inspect(block.new_bytes, block.inner_sha) == "present"
    assert hf.inspect(block.new_bytes.replace(b"skills", b"SKILLS"), block.inner_sha) == "modified"
