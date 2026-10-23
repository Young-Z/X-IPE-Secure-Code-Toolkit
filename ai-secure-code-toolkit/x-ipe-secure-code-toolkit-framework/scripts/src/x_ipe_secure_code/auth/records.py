"""Trust-state and grant records: strict shapes and canonical signing bytes."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

STATE_SCHEMA = "ai-secure-code-toolkit/trust-state/v1"
GRANT_SCHEMA = "ai-secure-code-toolkit/maintainer-grant/v1"
STATE_FIELDS = frozenset({"schema", "key_id", "generation", "status", "current_grant_id",
                          "created_at", "created_by", "updated_at", "signature"})
GRANT_FIELDS = frozenset({"schema", "grant_id", "key_id", "generation", "qualification",
                          "issued_at", "issued_to", "signature"})
PERSON_FIELDS = frozenset({"os_user", "host"})
GRANT_ID = re.compile(r"[0-9a-f]{32}")


class RecordInvalid(Exception):
    pass


def canonical(kind: str, record: dict[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k != "signature"}
    prefix = f"ai-secure-code-toolkit:{kind}:v1\n".encode()
    return prefix + json.dumps(body, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise RecordInvalid("signature is not valid base64") from exc


def parse(data: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecordInvalid("record is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise RecordInvalid("record is not a JSON object")
    return obj


def _person(value: Any, name: str) -> None:
    if not isinstance(value, dict) or set(value) != PERSON_FIELDS:
        raise RecordInvalid(f"{name} must contain exactly os_user and host")
    if not all(isinstance(v, str) for v in value.values()):
        raise RecordInvalid(f"{name} values must be strings")


def _common(obj: dict[str, Any], fields: frozenset[str], schema: str) -> None:
    if set(obj) != fields:
        unknown = sorted(set(obj) - fields)
        missing = sorted(fields - set(obj))
        raise RecordInvalid(f"unexpected fields {unknown} / missing fields {missing}")
    if obj["schema"] != schema:
        raise RecordInvalid("unexpected schema")
    gen = obj["generation"]
    if not isinstance(gen, int) or isinstance(gen, bool) or gen < 1:
        raise RecordInvalid("generation must be a positive integer")
    for key in fields - {"generation", "created_by", "issued_to"}:
        if key in obj and not isinstance(obj[key], str):
            raise RecordInvalid(f"{key} must be a string")


def check_state(obj: dict[str, Any]) -> None:
    _common(obj, STATE_FIELDS, STATE_SCHEMA)
    if obj["status"] not in ("active", "revoked"):
        raise RecordInvalid("status must be active or revoked")
    _person(obj["created_by"], "created_by")
    if not GRANT_ID.fullmatch(obj["current_grant_id"]):
        raise RecordInvalid("current_grant_id has an invalid format")


def check_grant(obj: dict[str, Any]) -> None:
    _common(obj, GRANT_FIELDS, GRANT_SCHEMA)
    if obj["qualification"] != "maintainer":
        raise RecordInvalid("qualification must be maintainer")
    _person(obj["issued_to"], "issued_to")
    if not GRANT_ID.fullmatch(obj["grant_id"]):
        raise RecordInvalid("grant_id has an invalid format")
