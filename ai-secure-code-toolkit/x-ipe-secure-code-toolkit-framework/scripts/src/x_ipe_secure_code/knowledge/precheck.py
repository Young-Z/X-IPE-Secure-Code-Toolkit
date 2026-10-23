"""Lightweight pre-check for suspected credentials and embedded operating instructions.

Matched values are never returned or stored; findings carry a keyed fingerprint.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from ..atomic import atomic_write_bytes

KEY_REL = ".x-ipe/private/secure-code/precheck-key"
AWS_DOC_EXAMPLES = frozenset({"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
PLACEHOLDER_WORDS = frozenset(
    {
        "changeme",
        "example",
        "placeholder",
        "redacted",
        "dummy",
        "password",
        "secret",
        "your-password",
        "your-api-key",
    }
)

CREDENTIALS = [
    (
        "credential.private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    ("credential.cloud_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "credential.token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}"
            r"|sk-[A-Za-z0-9]{20,})"
        ),
    ),
]
ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)
INSTRUCTIONS = [
    (
        "instruction.agent",
        re.compile(
            r"(?i)\b(?:ignore (?:all )?(?:previous|prior|above) instructions"
            r"|disregard .{0,30}instructions|you are now |reveal (?:the )?system prompt)"
        ),
    ),
    (
        "instruction.shell",
        re.compile(r"rm -rf /|\bmkfs\b|\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b|:\(\)\s*\{"),
    ),
]


@dataclass(frozen=True)
class Finding:
    type: str
    file: str
    line: int
    fingerprint: str
    blocking: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "fingerprint": self.fingerprint,
            "blocking": self.blocking,
        }


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return (
        lowered in PLACEHOLDER_WORDS
        or re.fullmatch(r"<[^<>]+>", value) is not None
        or re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Z_][A-Z0-9_]*", value) is not None
        or re.fullmatch(r"[x*]+", lowered) is not None
    )


def read_key(root: Path) -> bytes | None:
    path = root / KEY_REL
    return path.read_bytes() if path.is_file() else None


def load_or_create_key(root: Path) -> bytes:
    """Caller holds the knowledge write lock; creation is atomic (temp file + replace)."""
    path = root / KEY_REL
    if path.is_file():
        key = path.read_bytes()
        if len(key) == 32:
            return key
    key = secrets.token_bytes(32)
    atomic_write_bytes(path, key, private=True)
    return key


def scan(files: dict[str, str], key: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for name, text in sorted(files.items()):
        seen: dict[tuple[str, str], int] = {}
        in_example = name != "content.md"

        def add(
            kind: str,
            value: str,
            offset: int,
            blocking: bool,
            _name: str = name,
            _text: str = text,
            _seen: dict = seen,
        ) -> None:
            _seen[(kind, value)] = _seen.get((kind, value), 0) + 1
            occurrence = _seen[(kind, value)]
            mac = hmac.new(key, f"{kind}\0{_name}\0{value}\0{occurrence}".encode(), hashlib.sha256)
            line = _text.count("\n", 0, offset) + 1
            findings.append(Finding(kind, _name, line, mac.hexdigest()[:16], blocking))

        for kind, pattern in CREDENTIALS:
            for match in pattern.finditer(text):
                value = match.group(0)
                documented = kind == "credential.cloud_key" and value in AWS_DOC_EXAMPLES
                add("note.placeholder" if documented else kind, value, match.start(), not documented)
        for match in ASSIGNMENT.finditer(text):
            value = match.group(1)
            if value in AWS_DOC_EXAMPLES or is_placeholder(value):
                add("note.placeholder", value, match.start(), False)
            else:
                add("credential.assignment", value, match.start(), True)
        for kind, pattern in INSTRUCTIONS:
            for match in pattern.finditer(text):
                if kind == "instruction.shell" and in_example:
                    add("note.example_command", match.group(0), match.start(), False)
                else:
                    add(kind, match.group(0), match.start(), True)
    return findings
