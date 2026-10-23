"""Streaming parser of the Trivy v0.76.1 stderr log (`--debug`) into bounded facts (FEATURE-002-D).

Record format `<RFC3339>\\t<LEVEL>\\t<message>[\\t<fields>]` (time in UTC `Z` or with a `±hh:mm` offset:
Trivy formats it in the process's local zone); other lines are continuations (stack traces), counted
and never kept, except the bounded message lines (`  - …`) of a field-less debug-format FATAL, which
are attached to it. Only bounded, masked facts leave the parser.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..guard.mask import mask_text

RECORD = re.compile(
    r"^(\d{4}-\d\d-\d\dT[0-9:.]+(?:Z|[+-]\d\d:\d\d))\t(DEBUG|INFO|WARN|ERROR|FATAL)\t([^\t]*)(?:\t(.*))?$"
)
FIELD = re.compile(r'([A-Za-z_][\w]*)=("(?:[^"\\]|\\.)*"|\S*)')
ANCHORS = {
    "[vuln] Vulnerability scanning is enabled": "vuln",
    "[misconfig] Misconfiguration scanning is enabled": "misconfig",
    "[secret] Secret scanning is enabled": "secret",
}
SKIPPED_PACKAGE = re.compile(
    r"^\[(\w[\w-]*)\] Skipping vulnerability scan as no version is detected for the package$"
)
BENIGN = ("Unable to get vulnerability details", "file too large", "scanned file is too large")
# Exact WARN messages observed on the real binary that do not reduce analysis coverage (Bug Fix TASK-059;
# acceptance/evidence-container-linux.jsonl F-2, tool-validation/results-linux-aarch64.jsonl): the pip
# license-detection skip (license scanning is out of scope) and the informational vendor-severity notice.
# Pinned per tool version: any other version, message or level stays analysis-degrading (fail-closed).
BENIGN_EXACT = {
    "0.76.1": frozenset(
        {
            "[pip] Unable to find python `site-packages` directory. License detection is skipped.",
            "Using severities from other vendors for some vulnerabilities. Read "
            "https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity-selection for details.",
        }
    ),
}
MAX_LINE = 64 * 1024
MAX_PATHS = 50_000
MAX_MESSAGES = 200
MAX_TEXT = 300
MAX_FATAL_LINES = 64
MAX_FATAL_TEXT = 4096


@dataclass
class LogFacts:
    recognized: bool = False
    anchors: set[str] = field(default_factory=set)
    secret_scanned: list[str] = field(default_factory=list)
    skipped_paths: dict[str, str] = field(default_factory=dict)
    skipped_packages: list[dict[str, str]] = field(default_factory=list)
    remote_pom_skipped: int = 0
    os_not_detected: bool = False
    embedded_fallback: bool = False
    config_scanned: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    messages: list[dict[str, str]] = field(default_factory=list)
    component_errors: dict[str, str] = field(default_factory=dict)
    timed_out: bool = False
    continuations: int = 0
    paths_truncated: bool = False
    messages_dropped: int = 0


def _fields(text: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, raw in FIELD.findall(text or ""):
        if raw.startswith('"'):
            try:
                out[key] = json.loads(raw)
            except ValueError:
                continue
        else:
            out[key] = raw
    return out


class LogParser:
    """Feed stderr chunks as they arrive; `finish()` returns the facts.

    `version` is the running binary's version; it selects the exact benign WARN list (none if unknown).
    """

    def __init__(self, version: str | None = None) -> None:
        self.facts = LogFacts()
        self._benign_exact = BENIGN_EXACT.get(version or "", frozenset())
        self._buffer = bytearray()
        self._overlong = False
        self._seen: dict[int, set[str]] = {}
        self._fatal: dict | None = None  # field-less FATAL awaiting its `  - %+v` continuation lines

    def feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        while True:
            end = self._buffer.find(b"\n")
            if end < 0:
                if len(self._buffer) > MAX_LINE:
                    if not self._overlong:
                        self._line(bytes(self._buffer[:MAX_LINE]))
                    self._overlong = True
                    del self._buffer[:]
                return
            line = bytes(self._buffer[:end])
            del self._buffer[: end + 1]
            if self._overlong:
                self._overlong = False
                continue
            self._line(line[:MAX_LINE])

    def finish(self) -> LogFacts:
        if self._buffer and not self._overlong:
            self._line(bytes(self._buffer[:MAX_LINE]))
        self._buffer.clear()
        self._close_fatal()
        return self.facts

    # ------------------------------------------------------------------ one line
    def _path(self, target: list[str], value: str | None) -> None:
        seen = self._seen.setdefault(id(target), set())
        if not value or value in seen:
            return
        if len(target) >= MAX_PATHS:
            self.facts.paths_truncated = True
            return
        target.append(value)
        seen.add(value)

    def _message(self, level: str, text: str, kind: str) -> None:
        if len(self.facts.messages) >= MAX_MESSAGES:
            self.facts.messages_dropped += 1
            return
        self.facts.messages.append({"level": level, "text": mask_text(text)[0][:MAX_TEXT], "kind": kind})

    def _line(self, raw: bytes) -> None:
        f = self.facts
        text = raw.decode("utf-8", "replace").rstrip("\r")
        match = RECORD.match(text)
        if match is None:
            f.continuations += 1
            self._continue_fatal(text)
            return
        self._close_fatal()
        f.recognized = True
        _, level, msg, rest = match.groups()
        fields = _fields(rest)
        if msg in ANCHORS:
            f.anchors.add(ANCHORS[msg])
        elif msg == "[secret] Using streaming scanner":
            self._path(f.secret_scanned, fields.get("file_path"))
        elif msg == "Skipping path" and fields.get("path"):
            if len(f.skipped_paths) < MAX_PATHS:
                f.skipped_paths[fields["path"]] = "skipped by the tool's built-in skip rules"
        elif SKIPPED_PACKAGE.match(msg):
            if len(f.skipped_packages) < MAX_PATHS:
                f.skipped_packages.append(
                    {
                        "analyzer": SKIPPED_PACKAGE.match(msg).group(1),
                        "name": fields.get("name", "?"),
                        "reason": "no version detected offline",
                    }
                )
        elif msg == "[pom] Fetching the remote pom.xml is skipped":
            f.remote_pom_skipped += 1
        elif msg == "OS is not detected.":
            f.os_not_detected = True
        elif msg == "Scanned config file":
            self._path(f.config_scanned, fields.get("file_path"))
        elif msg == "Number of language-specific files" and fields.get("num", "").isdigit():
            f.counts["language_files"] = int(fields["num"])
        elif msg == "Detected config files" and fields.get("num", "").isdigit():
            f.counts["config_files"] = int(fields["num"])
        if "Falling back to embedded checks" in msg:
            f.embedded_fallback = True
        if level == "FATAL" and rest is None:
            self._fatal = {"msg": msg, "parts": [], "size": 0, "lines": 0}
        elif level == "FATAL":
            self._fatal_detail(f"{msg}: {rest}")
        elif level in ("WARN", "ERROR"):
            benign = any(b in msg for b in BENIGN) or (level == "WARN" and msg in self._benign_exact)
            kind = "benign" if benign else "degrading"
            self._message(level, msg, kind)

    def _fatal_detail(self, detail: str) -> None:
        self._component(detail)
        if "context deadline exceeded" in detail:
            self.facts.timed_out = True
        self._message("FATAL", detail, "fatal")

    def _continue_fatal(self, text: str) -> None:
        """Debug handler format: the error follows as `  - %+v`; keep message lines, drop stack frames."""
        pending = self._fatal
        if pending is None or pending["lines"] >= MAX_FATAL_LINES or pending["size"] >= MAX_FATAL_TEXT:
            return
        indent = len(text) - len(text.lstrip(" \t"))
        stripped = text.strip()
        if indent >= 4 or not stripped:
            return  # stack frame (`    pkg.func`, `        /file.go:n`) or blank line
        part = stripped[2:] if stripped.startswith("- ") else stripped
        part = part[: MAX_FATAL_TEXT - pending["size"]]
        pending["parts"].append(part)
        pending["size"] += len(part) + 1
        pending["lines"] += 1

    def _close_fatal(self) -> None:
        pending, self._fatal = self._fatal, None
        if pending is not None:
            detail = " ".join(pending["parts"])
            self._fatal_detail(f"{pending['msg']}: {detail}" if detail else pending["msg"])

    def _component(self, text: str) -> None:
        errors = self.facts.component_errors
        if "failed to open db" in text or "invalid database" in text:
            errors["vulnerability_db"] = "unreadable"
        if re.search(r"--skip-db-update'? cannot be specified on the first run", text):
            errors["vulnerability_db"] = "missing"
        if re.search(r"--skip-java-db-update'? cannot be specified on the first run", text):
            errors["java_db"] = "missing"
