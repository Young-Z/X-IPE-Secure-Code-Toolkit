"""Rule identity: namespace / source version / rule ID, with portable safe components."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

COMPONENT = re.compile(r"[A-Za-z0-9._-]{1,100}")
RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)


class IdentityError(Exception):
    def __init__(self, message: str, code: str = "IDENTITY_INVALID") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _check(value: object, field: str) -> str:
    if not isinstance(value, str) or not COMPONENT.fullmatch(value):
        raise IdentityError(f"{field} must be 1-100 characters from A-Z a-z 0-9 . _ -: {value!r}")
    if value in (".", "..") or value.startswith(".") or value.endswith("."):
        raise IdentityError(f"{field} must not start or end with a dot: {value!r}")
    if value.split(".", 1)[0].upper() in RESERVED:
        raise IdentityError(f"{field} is a reserved device name on Windows: {value!r}")
    return value


@dataclass(frozen=True, order=True)
class RuleRef:
    namespace: str
    version: str
    rule_id: str

    @property
    def kind(self) -> str:
        return "custom" if self.namespace.startswith("@") else "institutional"

    @property
    def rel(self) -> str:
        return f"{self.namespace}/{self.version}/{self.rule_id}"

    def __str__(self) -> str:
        return self.rel

    @classmethod
    def parse(cls, text: str) -> RuleRef:
        parts = text.split("/") if isinstance(text, str) else []
        if len(parts) != 3:
            raise IdentityError(f"Rule reference must be NAMESPACE/VERSION/ID: {text!r}")
        return make_ref(*parts)


def make_ref(namespace: object, version: object, rule_id: object) -> RuleRef:
    if isinstance(namespace, str) and namespace.startswith("@"):
        _check(namespace[1:], "namespace")
    else:
        _check(namespace, "namespace")
    return RuleRef(str(namespace), _check(version, "version"), _check(rule_id, "rule_id"))


def find_collision(local_root: Path, ref: RuleRef) -> str | None:
    """Return a message if an existing folder differs from `ref` only by letter case."""
    current = local_root
    for part in (ref.namespace, ref.version, ref.rule_id):
        if not current.is_dir():
            return None
        names = [entry.name for entry in os.scandir(current) if entry.is_dir(follow_symlinks=False)]
        if part in names:
            current = current / part
            continue
        clash = [name for name in names if name.lower() == part.lower()]
        if clash:
            return f"'{part}' collides with existing '{clash[0]}' (differs only by letter case)"
        return None
    return None
