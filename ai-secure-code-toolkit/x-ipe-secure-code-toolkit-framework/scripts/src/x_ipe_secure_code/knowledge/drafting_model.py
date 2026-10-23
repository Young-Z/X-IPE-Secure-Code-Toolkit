"""Draft and review file formats v1 for AI-assisted example drafting (FEATURE-001-G, FR-001G-1).

A draft (`*.draft.json`, written by the host agent) proposes labelled unsafe/safe examples for one
stored rule; a review (`*.review.json`, written only by the Maintainer) records the per-example
decisions and the per-draft attestations. Both live directly in `x-ipe-docs/secure-code/drafts/`,
are at most 1 MiB, and are read without following links. Explanations are not part of v1.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import durable
from .batch import DIGEST, LANG
from .identity import IdentityError, RuleRef

DRAFT_SCHEMA = "ai-secure-code-toolkit/knowledge-draft/v1"
REVIEW_SCHEMA = "ai-secure-code-toolkit/knowledge-draft-review/v1"
DRAFTS_REL = "x-ipe-docs/secure-code/drafts"
MAX_FILE_BYTES = 1024 * 1024
MARKER_WORD = "x-ipe-ai-supplement"
HOST_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
UTC_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
DRAFT_KEYS = frozenset(
    {"schema", "rule", "base_state", "drafted_by", "created_at", "confidentiality", "sources", "examples"}
)
REQUIRED_KEYS = ("schema", "rule", "base_state", "drafted_by", "created_at", "sources", "examples")
FORBIDDEN = {
    "explanation": "explanations are not drafted in this version (deferred by a human decision); "
    "a draft carries examples only",
    **{
        name: "a draft only adds examples; it cannot change rule text, identity, name, source location, "
        "applicability or relations"
        for name in (
            "content",
            "name",
            "source_location",
            "applicability",
            "relations",
            "namespace",
            "version",
            "rule_id",
            "source_document_digest",
        )
    },
}
SOURCE_FIELDS = {
    "stored_rule_content": frozenset({"kind"}),
    "fetched": frozenset({"kind", "url", "fetched_at", "http_status", "body_sha256", "attribution"}),
    "not_retrieved": frozenset({"kind", "url", "reason"}),
}
ATTRIBUTION_FIELDS = frozenset({"title", "url", "licence"})
EXAMPLE_FIELDS = frozenset({"unsafe", "safe", "demonstrates"})
DECISION_ITEMS = ("unsafe_violates_rule", "safe_addresses_rule", "language_correct")
REVIEW_ITEMS = frozenset({*DECISION_ITEMS, "unchecked_syntax_understood", "example_commands_acknowledged"})
ATTESTATIONS = ("non_normative", "licence_and_original_wording")
LOCATION_STEP = (
    "Drafts and reviews live directly in x-ipe-docs/secure-code/drafts/ (*.draft.json, *.review.json)"
)
DRAFT_STEP = "Fix the draft file; a supplement only adds examples"
REVIEW_STEP = "The Maintainer corrects the review file"


class DraftError(Exception):
    """Refusal of a draft or review input (code, message, next step)."""

    def __init__(self, code: str, message: str, next_step: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_step = next_step


@dataclass(frozen=True)
class Example:
    unsafe: str
    safe: str
    demonstrates: tuple[str, ...]


@dataclass(frozen=True)
class Draft:
    ref: RuleRef
    base_state: str
    host: str
    model: str | None
    created_at: str
    confidentiality: str | None
    sources: tuple[dict[str, Any], ...]
    examples: dict[str, Example]
    digest: str


@dataclass(frozen=True)
class Review:
    draft_digest: str
    examples: dict[str, dict[str, bool]] = field(default_factory=dict)
    attestations: dict[str, bool] = field(default_factory=dict)
    digest: str = ""

    def recorded(self, lang: str) -> set[str]:
        """Items recorded with a literal `true` for one example."""
        return {k for k, v in self.examples.get(lang, {}).items() if v is True}

    def attested(self) -> set[str]:
        return {k for k, v in self.attestations.items() if v is True}


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def normalize_part(text: str) -> str:
    """CRLF/CR → LF and trailing newlines removed (the block adds its own line ends)."""
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")


def _fail(path: str, message: str, code: str = "DRAFT_INVALID") -> DraftError:
    step = REVIEW_STEP if code == "DRAFT_REVIEW_INVALID" else DRAFT_STEP
    return DraftError(code, f"{path}: {message}" if path else message, step)


def single_line(value: Any, path: str, limit: int = 200) -> str:
    """Notice-safe text: one line, bounded, no control/format characters, no marker word."""
    if not isinstance(value, str) or not value.strip():
        raise _fail(path, "must be a non-empty string")
    if len(value) > limit:
        raise _fail(path, f"must be at most {limit} characters")
    if any(unicodedata.category(c)[0] == "C" for c in value):
        raise _fail(path, "must be a single line without control or format characters")
    if MARKER_WORD in value.lower():
        raise _fail(path, f"must not contain '{MARKER_WORD}'")
    return value


def _load_object(data: bytes, code: str) -> dict[str, Any]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _fail("", f"not readable UTF-8 JSON ({type(exc).__name__})", code) from None
    if not isinstance(obj, dict):
        raise _fail("", "must be a JSON object", code)
    return obj


def parse_draft(data: bytes) -> Draft:
    obj = _load_object(data, "DRAFT_INVALID")
    for name, why in FORBIDDEN.items():
        if name in obj:
            raise _fail("", f"field '{name}' is not allowed: {why}")
    unknown = sorted(set(obj) - DRAFT_KEYS)
    if unknown:
        raise _fail(unknown[0], f"unknown field(s) {unknown}")
    for key in REQUIRED_KEYS:
        if key not in obj:
            raise _fail(key, "is required")
    if obj["schema"] != DRAFT_SCHEMA:
        raise _fail("schema", f"must be '{DRAFT_SCHEMA}'")
    try:
        ref = RuleRef.parse(obj["rule"])
    except IdentityError as exc:
        raise _fail("rule", exc.message) from None
    if not (isinstance(obj["base_state"], str) and DIGEST.fullmatch(obj["base_state"])):
        raise _fail("base_state", "must look like sha256:<64 hex> (the rule's state_digest)")
    host, model = _drafted_by(obj["drafted_by"])
    if not (isinstance(obj["created_at"], str) and UTC_TIME.fullmatch(obj["created_at"])):
        raise _fail("created_at", "must be UTC YYYY-MM-DDTHH:MM:SSZ")
    confidentiality = obj.get("confidentiality")
    if confidentiality is not None and confidentiality != "internal":
        if ref.kind == "custom":
            raise DraftError(
                "CLASSIFICATION_DOWNGRADE",
                f"{ref} is an @ rule: its drafts are internal and cannot be declared '{confidentiality}'",
                "Remove the confidentiality declaration",
            )
        raise _fail("confidentiality", "must be absent or 'internal'")
    return Draft(
        ref,
        obj["base_state"],
        host,
        model,
        obj["created_at"],
        confidentiality,
        _sources(obj["sources"]),
        _examples(obj["examples"]),
        sha256(data),
    )


def _drafted_by(value: Any) -> tuple[str, str | None]:
    if not isinstance(value, dict) or not set(value) <= {"host", "model"} or "host" not in value:
        raise _fail("drafted_by", "must be an object {host, model?}")
    host = value["host"]
    if not (isinstance(host, str) and HOST_LABEL.fullmatch(host)):
        raise _fail("drafted_by.host", "must match [a-z0-9][a-z0-9._-]{0,63} (self-reported label)")
    model = value.get("model")
    return host, None if model is None else single_line(model, "drafted_by.model", 100)


def _sources(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value:
        raise _fail("sources", "must be a non-empty list")
    result = []
    for index, source in enumerate(value):
        path = f"sources[{index}]"
        if not isinstance(source, dict) or source.get("kind") not in SOURCE_FIELDS:
            raise _fail(f"{path}.kind", f"must be one of {sorted(SOURCE_FIELDS)}")
        extra = sorted(set(source) - SOURCE_FIELDS[source["kind"]])
        if extra:
            raise _fail(path, f"fields {extra} are not allowed for kind '{source['kind']}'")
        for key in ("url", "fetched_at", "body_sha256", "reason"):
            if key in source:
                single_line(source[key], f"{path}.{key}")
        status = source.get("http_status")
        if "http_status" in source and (not isinstance(status, int) or isinstance(status, bool)):
            raise _fail(f"{path}.http_status", "must be an integer")
        if "attribution" in source:
            attribution = source["attribution"]
            if not isinstance(attribution, dict) or not set(attribution) <= ATTRIBUTION_FIELDS:
                raise _fail(f"{path}.attribution", "must be an object {title, url, licence}")
            for key, text in attribution.items():
                single_line(text, f"{path}.attribution.{key}")
        result.append(json.loads(json.dumps(source)))
    return tuple(result)


def _examples(value: Any) -> dict[str, Example]:
    if not isinstance(value, dict) or not value:
        raise _fail("examples", "must be a non-empty object of language -> {unsafe, safe, demonstrates}")
    result = {}
    for lang, example in value.items():
        if not (isinstance(lang, str) and LANG.fullmatch(lang)):
            raise _fail("examples", f"language key must be a lowercase language name: {lang!r}")
        path = f"examples.{lang}"
        if not isinstance(example, dict):
            raise _fail(path, "replacement text is not allowed; give {unsafe, safe, demonstrates}")
        extra = sorted(set(example) - EXAMPLE_FIELDS)
        if extra:
            raise _fail(path, f"unknown field(s) {extra}")
        parts = {}
        for part in ("unsafe", "safe"):
            text = example.get(part, "")
            if not isinstance(text, str):
                raise _fail(f"{path}.{part}", "must be a string")
            parts[part] = normalize_part(text)
        demonstrates = example.get("demonstrates", [])
        if not isinstance(demonstrates, list) or not all(isinstance(q, str) for q in demonstrates):
            raise _fail(f"{path}.demonstrates", "must be a list of strings")
        result[lang] = Example(parts["unsafe"], parts["safe"], tuple(demonstrates))
    return result


def parse_review(data: bytes) -> Review:
    code = "DRAFT_REVIEW_INVALID"
    obj = _load_object(data, code)
    unknown = sorted(set(obj) - {"schema", "draft_digest", "examples", "attestations"})
    if unknown:
        raise _fail(unknown[0], f"unknown field(s) {unknown}", code)
    if obj.get("schema") != REVIEW_SCHEMA:
        raise _fail("schema", f"must be '{REVIEW_SCHEMA}'", code)
    if not (isinstance(obj.get("draft_digest"), str) and DIGEST.fullmatch(obj["draft_digest"])):
        raise _fail("draft_digest", "must be the sha256:<64 hex> digest of the reviewed draft file", code)
    examples = obj.get("examples", {})
    if not isinstance(examples, dict):
        raise _fail("examples", "must be an object of language -> decisions", code)
    for lang, items in examples.items():
        if not isinstance(items, dict) or not set(items) <= REVIEW_ITEMS:
            raise _fail(f"examples.{lang}", f"decisions must be among {sorted(REVIEW_ITEMS)}", code)
        if not all(isinstance(v, bool) for v in items.values()):
            raise _fail(f"examples.{lang}", "decisions must be true or false", code)
    attestations = obj.get("attestations", {})
    if (
        not isinstance(attestations, dict)
        or not set(attestations) <= set(ATTESTATIONS)
        or not all(isinstance(v, bool) for v in attestations.values())
    ):
        raise _fail("attestations", f"must map {list(ATTESTATIONS)} to true or false", code)
    return Review(
        obj["draft_digest"], {k: dict(v) for k, v in examples.items()}, dict(attestations), sha256(data)
    )


# --------------------------------------------------------------------------- file location (DEC-9)
def read_input(root: Path, raw_path: str, kind: str) -> bytes:
    """Bytes of a draft or review file directly inside the drafts folder (no links, ≤ 1 MiB)."""
    code, suffix = (
        ("DRAFT_REVIEW_INVALID", ".review.json") if kind == "review" else ("DRAFT_INVALID", ".draft.json")
    )
    path = Path(os.path.abspath(raw_path))
    name = path.name
    if not name.endswith(suffix) or name == suffix or name.startswith("."):
        raise DraftError(code, f"{raw_path}: a {kind} file name must end in {suffix}", LOCATION_STEP)
    drafts = root / DRAFTS_REL
    if os.path.realpath(path.parent) != os.path.realpath(drafts):
        raise DraftError(code, f"{raw_path} is not directly inside {DRAFTS_REL}/", LOCATION_STEP)
    try:
        with durable.Tree(root) as tree:
            fd = tree.dir(DRAFTS_REL)
            try:
                return _read_regular(fd, name, code)
            finally:
                durable.close(fd)
    except FileNotFoundError:
        raise DraftError(
            code,
            f"{DRAFTS_REL}/ or {name} does not exist (never created by drafting commands)",
            LOCATION_STEP,
        ) from None
    except durable.StoreError as exc:
        raise DraftError(code, exc.message, LOCATION_STEP) from None
    except OSError as exc:
        raise DraftError(code, f"{name} cannot be read: {exc.strerror or exc}", LOCATION_STEP) from None


def _read_regular(dfd: int, name: str, code: str) -> bytes:
    found = durable.entry(dfd, name)
    if found is None:
        raise FileNotFoundError(errno.ENOENT, name)
    if not stat.S_ISREG(found.st_mode):
        raise DraftError(code, f"{name} is not a regular file (links are not followed)", LOCATION_STEP)
    data = read_nofollow(dfd, name, MAX_FILE_BYTES)
    if data is None:
        raise DraftError(code, f"{name} is larger than {MAX_FILE_BYTES} bytes", LOCATION_STEP)
    return data


def read_nofollow(dfd: int, name: str, limit: int) -> bytes | None:
    """Regular-file bytes through a held folder handle (O_NOFOLLOW); None when larger than `limit`."""
    if not durable.POSIX_FD:  # pragma: no cover - Windows only
        target = durable._WIN[dfd] / name
        if not stat.S_ISREG(os.lstat(target).st_mode):
            raise durable.unsafe(f"{name} is not a regular file")
        with open(target, "rb") as handle:
            data = handle.read(limit + 1)
        return None if len(data) > limit else data
    try:
        fd = os.open(name, os.O_RDONLY | durable.NOFOLLOW | durable.NONBLOCK, dir_fd=dfd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise durable.unsafe(f"{name} is a link") from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise durable.unsafe(f"{name} is not a regular file")
        chunks, size = [], 0
        while size <= limit and (chunk := os.read(fd, 1024 * 1024)):
            chunks.append(chunk)
            size += len(chunk)
        return None if size > limit else b"".join(chunks)
    finally:
        os.close(fd)
