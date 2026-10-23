"""Batch, check and update inputs; canonical items and digests."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .identity import IdentityError, RuleRef, make_ref

BATCH_SCHEMA = "ai-secure-code-toolkit/knowledge-batch/v1"
CHECK_SCHEMA = "ai-secure-code-toolkit/knowledge-check/v1"
UPDATE_SCHEMA = "ai-secure-code-toolkit/knowledge-update/v1"
MAX_ITEM_BYTES = 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
LANG = re.compile(r"[a-z0-9+#-]{1,20}")
ITEM_FIELDS = frozenset(
    {
        "namespace",
        "version",
        "rule_id",
        "name",
        "source_location",
        "source_document_digest",
        "content",
        "examples",
        "applicability",
        "relations",
    }
)
UPDATE_FIELDS = frozenset(
    {"schema", "name", "source_location", "content", "applicability", "relations", "examples"}
)


class BatchError(Exception):
    """The whole input file is unusable."""


class ItemError(Exception):
    def __init__(self, message: str, code: str = "ITEM_INVALID") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_text(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


@dataclass
class Item:
    ref: RuleRef
    name: str | None
    source_location: str | None
    content: str
    examples: dict[str, str] = field(default_factory=dict)
    applicability: list[str] | None = None
    relations: list[RuleRef] = field(default_factory=list)
    source_document_digest: str | None = None

    def canonical(self) -> dict[str, Any]:
        return {
            "namespace": self.ref.namespace,
            "version": self.ref.version,
            "rule_id": self.ref.rule_id,
            "name": self.name,
            "source_location": self.source_location,
            "content": self.content,
            "examples": dict(sorted(self.examples.items())),
            "applicability": self.applicability,
            "relations": [str(r) for r in self.relations],
        }

    def digest(self) -> str:
        data = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()

    def size(self) -> int:
        return len(self.content.encode("utf-8")) + sum(len(v.encode("utf-8")) for v in self.examples.values())


def _text(value: Any, field_name: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ItemError(f"{field_name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ItemError(f"{field_name} contains text that is not valid Unicode") from exc
    return value


def _examples(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ItemError("examples must be an object of language -> text")
    result = {}
    for key, text in value.items():
        if key != "general" and not (isinstance(key, str) and LANG.fullmatch(key)):
            raise ItemError(f"example key must be 'general' or a lowercase language name: {key!r}")
        result[key] = normalize_text(_text(text, f"examples.{key}", required=True))
    return result


def _applicability(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) and LANG.fullmatch(v) for v in value):
        raise ItemError("applicability must be a list of lowercase language names")
    return sorted(set(value)) or None


def _relations(value: Any) -> list[RuleRef]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ItemError("relations must be a list of NAMESPACE/VERSION/ID references")
    try:
        return sorted({RuleRef.parse(v) for v in value})
    except IdentityError as exc:
        raise ItemError(f"invalid relation: {exc.message}") from exc


def identity_label(obj: Any, index: int) -> str:
    if isinstance(obj, dict) and all(
        isinstance(obj.get(k), str) for k in ("namespace", "version", "rule_id")
    ):
        return f"{obj['namespace']}/{obj['version']}/{obj['rule_id']}"
    return f"#{index}"


def parse_item(obj: Any) -> Item:
    if not isinstance(obj, dict):
        raise ItemError("item must be an object")
    unknown = set(obj) - ITEM_FIELDS
    if unknown:
        raise ItemError(f"unknown fields: {sorted(unknown)}")
    if not all(k in obj for k in ("namespace", "version", "rule_id")):
        raise IdentityError("item needs exactly one primary identity: namespace, version and rule_id")
    ref = make_ref(obj["namespace"], obj["version"], obj["rule_id"])
    name = _text(obj.get("name"), "name")
    if ref.kind == "custom" and name is None:
        raise ItemError("custom-namespace rules need a name chosen or confirmed by the Maintainer")
    document = obj.get("source_document_digest")
    if document is not None and not (isinstance(document, str) and DIGEST.fullmatch(document)):
        raise ItemError("source_document_digest must look like sha256:<64 hex>")
    return Item(
        ref=ref,
        name=name,
        source_location=_text(obj.get("source_location"), "source_location"),
        content=normalize_text(_text(obj.get("content"), "content", required=True)),
        examples=_examples(obj.get("examples")),
        applicability=_applicability(obj.get("applicability")),
        relations=_relations(obj.get("relations")),
        source_document_digest=document,
    )


def _load_json(path: str | Path, schema: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BatchError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != schema:
        raise BatchError(f"{path} must be a JSON object with schema '{schema}'")
    return data


def load_batch(path: str | Path) -> tuple[int | None, list[Any]]:
    data = _load_json(path, BATCH_SCHEMA)
    if set(data) - {"schema", "items", "expected_count"}:
        raise BatchError(f"unknown batch fields: {sorted(set(data) - {'schema', 'items', 'expected_count'})}")
    items = data.get("items")
    expected = data.get("expected_count")
    if not isinstance(items, list):
        raise BatchError("items must be a list")
    if expected is not None and (not isinstance(expected, int) or isinstance(expected, bool) or expected < 0):
        raise BatchError("expected_count must be a non-negative integer")
    return expected, items


def load_check(path: str | Path) -> tuple[list[tuple[str, str]], list[str]]:
    data = _load_json(path, CHECK_SCHEMA)
    items, documents = data.get("items", []), data.get("source_documents", [])
    if not isinstance(items, list) or not isinstance(documents, list):
        raise BatchError("items and source_documents must be lists")
    pairs = []
    for entry in items:
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("rule"), str)
            and isinstance(entry.get("item_digest"), str)
            and DIGEST.fullmatch(entry["item_digest"])
        ):
            raise BatchError("check items need 'rule' and 'item_digest' (sha256:<64 hex>)")
        pairs.append((entry["rule"], entry["item_digest"]))
    if not all(isinstance(d, str) and DIGEST.fullmatch(d) for d in documents):
        raise BatchError("source_documents must be sha256:<64 hex> strings")
    return pairs, documents


def load_update(path: str | Path) -> dict[str, Any]:
    data = _load_json(path, UPDATE_SCHEMA)
    unknown = set(data) - UPDATE_FIELDS
    if unknown:
        raise ItemError(f"unknown or identity fields in update: {sorted(unknown)}")
    if len(data) == 1:
        raise ItemError("update contains no changes")
    return {k: v for k, v in data.items() if k != "schema"}


def apply_update(current: Item, changes: dict[str, Any]) -> Item:
    if "examples" in changes and not isinstance(changes["examples"], dict):
        raise ItemError("examples must be an object")
    examples = dict(current.examples)
    for key, text in (changes.get("examples") or {}).items():
        if text is None:
            if key not in examples:
                raise ItemError(f"cannot delete missing example '{key}'")
            del examples[key]
        else:
            examples.update(_examples({key: text}))
    name = _text(changes["name"], "name") if "name" in changes else current.name
    if current.ref.kind == "custom" and name is None:
        raise ItemError("custom-namespace rules need a name")
    return Item(
        ref=current.ref,
        name=name,
        source_location=(
            _text(changes["source_location"], "source_location")
            if "source_location" in changes
            else current.source_location
        ),
        content=(
            normalize_text(_text(changes["content"], "content", required=True))
            if "content" in changes
            else current.content
        ),
        examples=examples,
        applicability=(
            _applicability(changes["applicability"]) if "applicability" in changes else current.applicability
        ),
        relations=_relations(changes["relations"]) if "relations" in changes else current.relations,
    )
