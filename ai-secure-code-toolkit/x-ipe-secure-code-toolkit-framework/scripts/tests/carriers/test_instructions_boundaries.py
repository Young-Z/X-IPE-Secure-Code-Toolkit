"""FEATURE-003-B unit tests: the instructions file's two managed boundaries (AC-003B-03b, 03g, 05c, 06d).

The toolkit owns exactly the front matter at file start and the marker-delimited body (BR-18).
"""

from __future__ import annotations

import pytest
from carhelp import BEGIN, END, FRONT_MATTER

from x_ipe_secure_code import host_fragment as hf

BLOCK = BEGIN + "\n## AI Secure Code Toolkit\nRoute.\n" + END + "\n"
CR = {"lf": "\n", "crlf": "\r\n"}


def _nl(text: str, nl: str) -> str:
    return text.replace("\n", nl)


def test_writer_contract_unchanged():
    assert hf.BEGIN == BEGIN and hf.END == END
    assert hf.FRONT_MATTER == FRONT_MATTER == '---\napplyTo: "**"\n---\n'


@pytest.mark.parametrize("style", CR)
def test_front_matter_ok_at_file_start(style):
    nl = CR[style]
    text = _nl(FRONT_MATTER + "\n" + BLOCK + "user tail\n", nl)
    state, _region = hf.front_matter_state(text)
    assert state == "ok"
    assert hf.restore_front_matter(text, state, _region) == text


@pytest.mark.parametrize("text", [
    BLOCK,
    "intro\n" + BLOCK,
    "---\nno closing line\n" + "x\n" * 60 + BLOCK,
    "intro\n" + FRONT_MATTER + "middle\n" + FRONT_MATTER + BLOCK,
], ids=["absent", "user-text-first", "unclosed-leading-dashes", "two-copies-away-from-start"])
def test_front_matter_missing(text):
    state, region = hf.front_matter_state(text)
    assert state == "missing"
    assert hf.restore_front_matter(text, state, region) == FRONT_MATTER + text


@pytest.mark.parametrize("block", [
    '---\napplyTo: "src/**"\n---\n',
    '---\napplyTo: "**"\nexcludeAgent: "code-review"\n---\n',
    "---\n---\n",
], ids=["applyTo-changed", "key-added", "emptied"])
@pytest.mark.parametrize("style", CR)
def test_front_matter_altered_replaces_only_the_leading_block(block, style):
    nl = CR[style]
    rest = "\nUser line ü\n" + BLOCK + "tail\n"
    text = _nl(block + rest, nl)
    state, region = hf.front_matter_state(text)
    assert state == "altered"
    restored = hf.restore_front_matter(text, state, region)
    assert restored == _nl(FRONT_MATTER, nl) + _nl(rest, nl)


@pytest.mark.parametrize("style", CR)
def test_front_matter_moved_is_relocated_as_one_block(style):
    nl = CR[style]
    head = _nl("User intro ü\n\n", nl)
    tail = _nl("\n" + BLOCK + "after\n", nl)
    fm = _nl(FRONT_MATTER, nl)
    text = head + fm + tail
    state, region = hf.front_matter_state(text)
    assert state == "moved"
    restored = hf.restore_front_matter(text, state, region)
    assert restored == fm + head + tail
    assert restored.count(fm) == 1 and restored.startswith(fm)


def test_state_order_ok_wins_over_a_later_copy():
    text = FRONT_MATTER + "\n" + BLOCK + FRONT_MATTER
    assert hf.front_matter_state(text)[0] == "ok"


def test_plan_upsert_still_the_only_body_writer_for_instructions():
    """The body boundary of the instructions file uses the FEATURE-001-A writer unchanged."""
    text = FRONT_MATTER + "\n" + BLOCK
    plan = hf.plan_upsert(text.encode(), "## AI Secure Code Toolkit\nRoute again.\n",
                          recorded_sha=hf.sha256_text("## AI Secure Code Toolkit\nRoute.\n"), replace=False)
    assert plan.outcome == "update"
    assert plan.new_bytes.startswith((FRONT_MATTER + "\n").encode())
