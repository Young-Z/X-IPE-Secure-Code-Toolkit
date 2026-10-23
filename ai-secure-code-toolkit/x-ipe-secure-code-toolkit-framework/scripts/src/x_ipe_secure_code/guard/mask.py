"""Mask suspected credentials with the FEATURE-001-B pre-check patterns before anything is stored."""

from __future__ import annotations

import re

from ..knowledge.precheck import ASSIGNMENT, AWS_DOC_EXAMPLES, CREDENTIALS, is_placeholder

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.S,
)
# Guard-only additions to the FEATURE-001-B pre-check patterns (the knowledge pre-check is unchanged).
EXTRA_TOKENS = re.compile(r"\bsk-(?:proj|ant|svcacct|admin|None)-[A-Za-z0-9_-]{20,}")
# Name parts are bounded so a long identifier-like line cannot cause quadratic backtracking.
UNQUOTED_ASSIGNMENT = re.compile(
    r"(?im)^[ \t]*(?:export[ \t]+)?[A-Z0-9_.-]{0,64}(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_.-]{0,64}"
    r"[ \t]*[:=][ \t]*([^\s\"'#]{8,})"
)


def _marker(kind: str) -> str:
    return f"[masked:{kind}]"


def mask_text(text: str) -> tuple[str, list[str]]:
    """Return the text with suspected credential values replaced, and the masked types."""
    kinds: set[str] = set()

    def block(_match: re.Match) -> str:
        kinds.add("credential.private_key")
        return _marker("credential.private_key")

    text = PRIVATE_KEY_BLOCK.sub(block, text)

    def extra(_match: re.Match) -> str:
        kinds.add("credential.token")
        return _marker("credential.token")

    text = EXTRA_TOKENS.sub(extra, text)
    for kind, pattern in CREDENTIALS:

        def credential(match: re.Match, _kind: str = kind) -> str:
            value = match.group(0)
            if _kind == "credential.cloud_key" and value in AWS_DOC_EXAMPLES:
                return value
            kinds.add(_kind)
            return _marker(_kind)

        text = pattern.sub(credential, text)

    def assignment(match: re.Match) -> str:
        value = match.group(1)
        if value in AWS_DOC_EXAMPLES or is_placeholder(value) or value.startswith("[masked:"):
            return match.group(0)
        kinds.add("credential.assignment")
        whole = match.group(0)
        start, end = match.start(1) - match.start(0), match.end(1) - match.start(0)
        return whole[:start] + _marker("credential.assignment") + whole[end:]

    text = ASSIGNMENT.sub(assignment, text)
    text = UNQUOTED_ASSIGNMENT.sub(assignment, text)
    return text, sorted(kinds)
