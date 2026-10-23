"""Requested rule references: `NS/VER/ID` or version-less `NS/ID`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..knowledge.identity import IdentityError, RuleRef

_PROBE_VERSION = "0"


@dataclass(frozen=True)
class RequestedRef:
    """One reference as requested by the agent; `invalid` holds the reason when unusable."""

    text: str
    namespace: str | None = None
    version: str | None = None
    rule_id: str | None = None
    invalid: str | None = None

    def full(self) -> RuleRef | None:
        """Return the exact rule identity when a version was given."""
        if self.invalid or self.version is None:
            return None
        return RuleRef(self.namespace, self.version, self.rule_id)  # type: ignore[arg-type]


def is_utf8(value: Any) -> bool:
    """True when every string inside `value` can be encoded as UTF-8 (no lone surrogates)."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, dict):
        return all(is_utf8(k) and is_utf8(v) for k, v in value.items())
    if isinstance(value, list):
        return all(is_utf8(v) for v in value)
    return True


def parse_requested(text: str) -> RequestedRef:
    """Parse one requested reference; never raises for a bad reference.

    Args:
        text: `NAMESPACE/VERSION/RULE_ID` or `NAMESPACE/RULE_ID`.

    Returns:
        RequestedRef with components, or with `invalid` set.
    """
    if isinstance(text, str) and not is_utf8(text):
        safe = text.encode("utf-8", "backslashreplace").decode("utf-8")
        return RequestedRef(safe, invalid="reference is not valid UTF-8 text")
    parts = text.split("/") if isinstance(text, str) else []
    try:
        if len(parts) == 3:
            ref = RuleRef.parse(text)
            return RequestedRef(text, ref.namespace, ref.version, ref.rule_id)
        if len(parts) == 2:
            probe = RuleRef.parse(f"{parts[0]}/{_PROBE_VERSION}/{parts[1]}")
            return RequestedRef(text, probe.namespace, None, probe.rule_id)
    except IdentityError as exc:
        return RequestedRef(text, invalid=exc.message)
    return RequestedRef(text, invalid="expected NAMESPACE/VERSION/RULE_ID or NAMESPACE/RULE_ID")
