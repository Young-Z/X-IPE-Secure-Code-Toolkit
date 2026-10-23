"""Toolkit-owned fragment in a host entry file (e.g. AGENTS.md) and the other carriers.

The one writer of every toolkit carrier (FEATURE-001-A, extended by FEATURE-003-B). Works on decoded
UTF-8 text but never alters anything outside the managed boundaries, so the re-encoded bytes outside
them are identical. The GitHub instructions file has a second managed boundary: the exact front matter
at file start.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .environments import Profile
from .results import Problem

BEGIN = "<!-- BEGIN ai-secure-code-toolkit: managed fragment, edits are reported not overwritten -->"
END = "<!-- END ai-secure-code-toolkit -->"
FRONT_MATTER = '---\napplyTo: "**"\n---\n'
FRONT_MATTER_SCAN_LINES = 50


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def render_minimal_body(profile: Profile) -> str:
    """The FEATURE-001-A fragment text, used only for a payload without a routing definition."""
    skills = profile.skills_dir
    return (
        "## AI Secure Code Toolkit\n"
        "\n"
        f"This project uses the AI secure-code toolkit skills in `{skills}/`:\n"
        "\n"
        "- `x-ipe-secure-code-toolkit-copilot`: use during design, implementation, bug fix and "
        "refactor tasks for in-flow security suggestions and adoption review.\n"
        "- `x-ipe-secure-code-toolkit-guard`: use only for an explicit or authorized security "
        "verification request; it reports findings and does not fix.\n"
        "- `x-ipe-secure-code-toolkit-framework`: security knowledge, Policies, status and "
        "Maintainer authorization.\n"
        "\n"
        f"Check status: `uvx --from {skills}/x-ipe-secure-code-toolkit-framework/scripts "
        "secure-code status --project . --json`\n"
    )


@dataclass(frozen=True)
class FragmentPlan:
    outcome: str  # create_file|append|current|update|edited_kept|replaced|malformed|unreadable
    new_bytes: bytes | None
    inner_sha: str
    problem: Problem | None = None
    blocking: bool = False


def _newline(text: str) -> str:
    index = text.find("\n")
    return "\r\n" if index > 0 and text[index - 1] == "\r" else "\n"


def _markers(lines: list[str]) -> tuple[list[int], list[int]]:
    begins = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    return begins, ends


def _block(body: str, nl: str) -> str:
    return BEGIN + nl + body.replace("\n", nl) + END + nl


def _locate(text: str) -> tuple[str, list[str], int, int]:
    lines = text.splitlines(keepends=True)
    begins, ends = _markers(lines)
    if not begins and not ends:
        return "absent", lines, -1, -1
    if len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0]:
        return "present", lines, begins[0], ends[0]
    if len(begins) == len(ends) >= 2:
        return "duplicate", lines, -1, -1
    return "malformed", lines, -1, -1


def plan_upsert(data: bytes | None, body: str, recorded_sha: str | None,
                replace: bool) -> FragmentPlan:
    new_sha = sha256_text(body)
    if data is None:
        return FragmentPlan("create_file", _block(body, "\n").encode("utf-8"), new_sha)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return FragmentPlan("unreadable", None, new_sha,
                            Problem("HOST_ENTRY_UNREADABLE", "Host entry file is not UTF-8"), True)
    nl = _newline(text)
    kind, lines, begin, end = _locate(text)
    if kind == "duplicate":
        return FragmentPlan("malformed", None, new_sha, Problem(
            "FRAGMENT_DUPLICATE", "Host entry file contains more than one toolkit fragment"), True)
    if kind == "malformed":
        return FragmentPlan("malformed", None, new_sha, Problem(
            "FRAGMENT_MALFORMED", "Toolkit fragment markers are unmatched or out of order"), True)
    if kind == "absent":
        separator = "" if not text or text.endswith("\n") else nl
        lead = "" if not text else separator + nl
        return FragmentPlan("append", (text + lead + _block(body, nl)).encode("utf-8"), new_sha)
    inner_sha = sha256_text("".join(lines[begin + 1:end]))
    if inner_sha == new_sha:
        return FragmentPlan("current", None, new_sha)
    rebuilt = "".join(lines[:begin + 1]) + body.replace("\n", nl) + "".join(lines[end:])
    if recorded_sha is not None and inner_sha == recorded_sha:
        return FragmentPlan("update", rebuilt.encode("utf-8"), new_sha)
    if replace:
        return FragmentPlan("replaced", rebuilt.encode("utf-8"), new_sha)
    return FragmentPlan("edited_kept", None, new_sha, Problem(
        "FRAGMENT_EDITED", "The toolkit fragment was edited locally and was kept; "
        "re-run with --replace <host entry file> to take the toolkit version"))


def inspect(data: bytes | None, expected_sha: str | None) -> str:
    """absent_file | absent | present | modified | malformed | unreadable."""
    if data is None:
        return "absent_file"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "unreadable"
    kind, lines, begin, end = _locate(text)
    if kind in ("duplicate", "malformed"):
        return "malformed"
    if kind == "absent":
        return "absent"
    inner = sha256_text("".join(lines[begin + 1:end]))
    return "present" if expected_sha is None or inner == expected_sha else "modified"


def fragment_text(text: str) -> str | None:
    """The text between the markers of a single, well-formed fragment, else None."""
    kind, lines, begin, end = _locate(text)
    return "".join(lines[begin + 1:end]) if kind == "present" else None


def _front_matter(nl: str) -> str:
    return FRONT_MATTER.replace("\n", nl)


def front_matter_state(text: str) -> tuple[str, tuple[int, int] | None]:
    """ok | altered | moved | missing, with the (start, end) text region of the block where known."""
    if text.startswith(FRONT_MATTER) or text.startswith(_front_matter("\r\n")):
        nl = "\r\n" if text.startswith(_front_matter("\r\n")) else "\n"
        return "ok", (0, len(_front_matter(nl)))
    lines = text.splitlines(keepends=True)
    if lines and lines[0].strip() == "---":
        for index in range(1, min(len(lines), FRONT_MATTER_SCAN_LINES)):
            if lines[index].strip() == "---":
                return "altered", (0, len("".join(lines[:index + 1])))
    block = _front_matter(_newline(text))
    if text.count(block) == 1:
        start = text.index(block)
        if start == 0 or text[start - 1] == "\n":
            return "moved", (start, start + len(block))
    return "missing", None


def restore_front_matter(text: str, state: str, region: tuple[int, int] | None) -> str:
    """Put the exact front matter at file start; every other byte stays as it was."""
    block = _front_matter(_newline(text))
    if state == "ok":
        return text
    if state == "missing" or region is None:
        return block + text
    start, end = region
    if state == "altered":
        return block + text[end:]
    return block + text[:start] + text[end:]  # moved: relocate the single detected block


def user_content_outside(text: str) -> bool:
    """Non-whitespace text outside the leading front matter (ok/altered) and the fragment."""
    state, region = front_matter_state(text)
    rest = text[region[1]:] if state in ("ok", "altered") and region else text
    kind, lines, begin, end = _locate(rest)
    if kind == "present":
        rest = "".join(lines[:begin] + lines[end + 1:])
    return bool(rest.strip())
