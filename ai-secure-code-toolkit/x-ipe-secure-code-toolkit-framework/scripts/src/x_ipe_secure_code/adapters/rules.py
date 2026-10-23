"""Opengrep rule files: restricted YAML loading and the validated search-mode capability allowlist."""

from __future__ import annotations

import re
from typing import Any

import yaml

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
MAX_RULES = 500
MAX_DEPTH = 32
MAX_NODES = 100_000
ALLOWED_KEYS = frozenset(
    {
        "id",
        "languages",
        "severity",
        "message",
        "metadata",
        "pattern",
        "patterns",
        "pattern-either",
        "pattern-regex",
        "pattern-not",
        "pattern-not-regex",
        "pattern-inside",
        "pattern-not-inside",
        "metavariable-regex",
        "metavariable-pattern",
        "metavariable-comparison",
        "focus-metavariable",
        "mode",
    }
)


class RuleError(Exception):
    pass


class _Loader(yaml.SafeLoader):
    """Safe loader without aliases or duplicate keys, with depth and node limits."""

    nodes = 0

    def compose_node(self, parent, index):  # noqa: D401 - PyYAML hook
        if self.check_event(yaml.AliasEvent):
            raise RuleError("YAML aliases are not allowed in rule files")
        event = self.peek_event()
        if getattr(event, "anchor", None):
            raise RuleError("YAML anchors/aliases are not allowed in rule files")
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise RuleError("rule file has too many YAML nodes")
        depth = getattr(self, "_depth", 0) + 1
        if depth > MAX_DEPTH:
            raise RuleError("rule file is nested too deeply")
        self._depth = depth
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth = depth - 1

    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in keys:
                raise RuleError(f"duplicate key {key!r} in rule file")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def load_rules(data: bytes) -> list[dict[str, Any]]:
    """Parse and validate a rule file; returns its rules."""
    try:
        doc = yaml.load(data.decode("utf-8"), Loader=_Loader)  # noqa: S506 - restricted SafeLoader subclass
    except RuleError:
        raise
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise RuleError(f"rule file is not valid YAML: {str(exc)[:200]}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list) or not doc["rules"]:
        raise RuleError("rule file must be a mapping with a non-empty 'rules' list")
    if set(doc) != {"rules"}:
        raise RuleError("rule file may only contain 'rules'")
    if len(doc["rules"]) > MAX_RULES:
        raise RuleError(f"rule file has more than {MAX_RULES} rules")
    for index, rule in enumerate(doc["rules"]):
        where = f"rules[{index}]"
        if not isinstance(rule, dict):
            raise RuleError(f"{where} must be a mapping")
        if not isinstance(rule.get("id"), str) or not NAME.fullmatch(rule["id"]):
            raise RuleError(f"{where} needs a valid id")
        langs = rule.get("languages")
        if not isinstance(langs, list) or not langs or not all(isinstance(x, str) and x for x in langs):
            raise RuleError(f"{where} ({rule['id']}) needs a non-empty languages list")
        extra = sorted(set(rule) - ALLOWED_KEYS)
        if extra or rule.get("mode", "search") != "search":
            what = ", ".join(extra) if extra else f"mode {rule['mode']}"
            raise RuleError(f"{where} ({rule['id']}) uses features not supported by this Adapter: {what}")
    return doc["rules"]


def check_set(rules: list[dict[str, Any]]) -> None:
    """Rule ids of one check must be unique and not suffixes of each other (unambiguous attribution)."""
    ids = [r["id"] for r in rules]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise RuleError(f"duplicate rule id(s): {', '.join(dup)}")
    for a in ids:
        for b in ids:
            if a != b and b.endswith("." + a):
                raise RuleError(f"rule ids {a} and {b} are ambiguous")


def dump_single(rule: dict[str, Any]) -> str:
    return yaml.safe_dump({"rules": [rule]}, sort_keys=True, allow_unicode=True)
