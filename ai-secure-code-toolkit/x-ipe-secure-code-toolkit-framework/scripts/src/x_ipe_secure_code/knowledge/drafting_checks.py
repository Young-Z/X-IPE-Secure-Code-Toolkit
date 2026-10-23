"""Deterministic draft checks V5, V6, V9, V10, V11, V12, V13 (FEATURE-001-G, FR-001G-2).

These are preconditions only: nothing is executed, imported or fetched. Python parts are parsed
with `ast.parse` (AST only); other languages are `not_syntax_validated`. Rule fit, licence and
original wording remain recorded Maintainer decisions.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from .batch import DIGEST
from .drafting_blocks import COMMENT, SUPPORTED
from .drafting_model import DECISION_ITEMS, UTC_TIME, Draft, Example
from .identity import RuleRef

MAX_PYTHON_PART = 200_000
MAX_NESTING = 100
MIN_QUOTE = 16
RULE_LINK_NOTE = (
    "verbatim rule quote present (precondition only; not evidence of rule fit — the "
    "Maintainer's per-example decision is the binding control)"
)
COMMAND_NOTE = (
    "001-G command validator finding; the delivered pre-check does not enforce example "
    "commands (it emits only note.example_command)"
)
PROVENANCE_NOTE = (
    "provenance is checked for field completeness only; licence and original wording are "
    "the Maintainer's attestation"
)
GENERAL_PAGES = (
    "https://cwe.mitre.org/top25/",
    "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html",
    "https://top10.owasp.org/2025/",
)
CWE_TOP25 = (
    79,
    89,
    352,
    862,
    787,
    22,
    416,
    125,
    78,
    94,
    120,
    434,
    476,
    121,
    502,
    122,
    863,
    20,
    284,
    200,
    306,
    918,
    77,
    639,
    770,
)
OWASP_PAGES = {
    "A01": "A01_2025-Broken_Access_Control",
    "A02": "A02_2025-Security_Misconfiguration",
    "A03": "A03_2025-Software_Supply_Chain_Failures",
    "A04": "A04_2025-Cryptographic_Failures",
    "A05": "A05_2025-Injection",
    "A06": "A06_2025-Insecure_Design",
    "A07": "A07_2025-Authentication_Failures",
    "A08": "A08_2025-Software_or_Data_Integrity_Failures",
    "A09": "A09_2025-Security_Logging_and_Alerting_Failures",
    "A10": "A10_2025-Mishandling_of_Exceptional_Conditions",
}
COMMANDS = (
    ("rm_recursive", re.compile(r"\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+", re.I)),
    ("mkfs", re.compile(r"\bmkfs(?:\.\w+)?\b", re.I)),
    ("dd_of", re.compile(r"\bdd\b[^\n]*\bof=", re.I)),
    ("pipe_to_shell", re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I)),
    ("format_volume", re.compile(r"\bformat-volume\b", re.I)),
    ("del_recursive", re.compile(r"\bdel\s+(?:/[a-z]\s+)*/s\b", re.I)),
    ("shutdown", re.compile(r"\bshutdown\b", re.I)),
    ("remove_item_recurse", re.compile(r"\bremove-item\b[^\n]*-recurse", re.I)),
    ("fork_bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
)


def _cwe_url(n: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{n}.html"


def _owasp_url(rule: str) -> str:
    return f"https://top10.owasp.org/2025/{OWASP_PAGES[rule]}/"


def allowed_urls() -> list[str]:
    return [*GENERAL_PAGES, *(_cwe_url(n) for n in CWE_TOP25), *(_owasp_url(r) for r in OWASP_PAGES)]


def url_allowed(ref: RuleRef, url: Any, *, internal: bool) -> bool:
    """Exact membership (no normalisation); rule-specific pages only for their own rule."""
    if internal or not isinstance(url, str):
        return False
    if url in GENERAL_PAGES:
        return True
    if any(url == _cwe_url(n) for n in CWE_TOP25):
        return (
            ref.namespace == "CWE"
            and url == f"https://cwe.mitre.org/data/definitions/{ref.rule_id[4:]}.html"
            and ref.rule_id.startswith("CWE-")
        )
    return (
        ref.namespace == "OWASP"
        and ref.version == "Top10-2025"
        and ref.rule_id in OWASP_PAGES
        and url == _owasp_url(ref.rule_id)
    )


def provenance(ref: RuleRef, source: dict[str, Any], *, internal: bool) -> dict[str, Any]:
    """V10 for one source: field completeness and the page allowlist (never a verification)."""
    kind = source["kind"]
    entry: dict[str, Any] = {"kind": kind}
    if kind == "stored_rule_content":
        return {**entry, "result": "stored_rule_content"}
    entry["url"] = source.get("url")
    if not url_allowed(ref, source.get("url"), internal=internal):
        return {**entry, "result": "source_not_allowed"}
    if kind == "not_retrieved":
        return {**entry, "result": "not_retrieved" if source.get("reason") else "provenance_incomplete"}
    status = source.get("http_status")
    complete = (
        isinstance(source.get("fetched_at"), str)
        and UTC_TIME.fullmatch(source["fetched_at"])
        and isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status <= 599
        and isinstance(source.get("body_sha256"), str)
        and DIGEST.fullmatch(source["body_sha256"])
    )
    if not complete:
        return {**entry, "result": "provenance_incomplete"}
    attribution = source.get("attribution") or {}
    if not all(attribution.get(k) for k in ("title", "url", "licence")):
        return {**entry, "result": "attribution_missing"}
    if (
        source["url"].startswith("https://cwe.mitre.org/")
        and "cwe terms of use" not in attribution["licence"].casefold()
    ):
        return {**entry, "result": "attribution_missing"}
    return {**entry, "result": "provenance_complete"}


def structure(lang: str, example: Example) -> list[str]:
    """V5 (and the comment-syntax part of V2): failure results, empty when well-formed."""
    results = []
    if lang not in COMMENT:
        results.append("language_unsupported")
    if not example.unsafe.strip() or not example.safe.strip():
        results.append("example_incomplete")
    return results


def unsupported_message(lang: str) -> str:
    return f"language '{lang}' has no comment syntax for AI blocks; supported: {', '.join(SUPPORTED)}"


def corpus(texts: list[str]) -> str:
    return " ".join(" ".join(t.split()) for t in texts)


def rule_link(example: Example, rule_corpus: str) -> str:
    """V6 (DEC-7): some `demonstrates` entry of ≥ 16 chars occurs verbatim (whitespace-collapsed)."""
    for quote in example.demonstrates:
        collapsed = " ".join(quote.split())
        if len(collapsed) >= MIN_QUOTE and collapsed in rule_corpus:
            return "quote_present"
    return "no_rule_link"


def _too_deep(text: str) -> bool:
    depth = 0
    for char in text:
        if char in "([{":
            depth += 1
            if depth > MAX_NESTING:
                return True
        elif char in ")]}":
            depth = max(0, depth - 1)
    return False


def python_syntax(example: Example, lang: str = "python") -> tuple[str, list[dict[str, Any]]]:
    """V9: Python AST-only parse of both parts; never compiles to a code object or executes."""
    if lang != "python":
        return "not_syntax_validated", []
    results = []
    for part in ("unsafe", "safe"):
        text = getattr(example, part)
        failure: dict[str, Any] | None = None
        if len(text.encode("utf-8")) > MAX_PYTHON_PART:
            failure = {"line": None, "offset": None, "message": f"part too large (> {MAX_PYTHON_PART} bytes)"}
        elif _too_deep(text):
            failure = {"line": None, "offset": None, "message": f"nesting too deep (> {MAX_NESTING})"}
        else:
            try:
                ast.parse(text, filename=f"<{part}>", mode="exec")
            except SyntaxError as exc:
                failure = {"line": exc.lineno, "offset": exc.offset, "message": str(exc.msg or exc)}
            except (ValueError, RecursionError, MemoryError, OverflowError) as exc:
                failure = {"line": None, "offset": None, "message": f"{type(exc).__name__}: {exc}"}
        if failure:
            failure["message"] = failure["message"][:120]
            results.append({"result": "invalid_syntax", "part": part, **failure})
    return ("invalid_syntax" if results else "syntax_checked"), results


def commands(lang: str, example: Example) -> list[dict[str, Any]]:
    """V11: shell/destructive commands per occurrence (001-G's own validator)."""
    found = []
    for part in ("unsafe", "safe"):
        for number, line in enumerate(getattr(example, part).split("\n"), 1):
            for name, pattern in COMMANDS:
                found += [
                    {
                        "result": "example_command",
                        "language": lang,
                        "part": part,
                        "line": number,
                        "pattern": name,
                    }
                    for _ in pattern.finditer(line)
                ]
    return found


def applicability_warning(lang: str, applicability: Any) -> bool:
    return isinstance(applicability, list) and lang not in applicability


def classification(draft: Draft) -> str | None:
    """V13: `@` rules are internal by default; a draft may declare `internal` for any rule."""
    return "internal" if draft.ref.kind == "custom" or draft.confidentiality == "internal" else None


def required_items(lang: str, *, has_commands: bool) -> list[str]:
    items = list(DECISION_ITEMS)
    if lang != "python":
        items.append("unchecked_syntax_understood")
    if has_commands:
        items.append("example_commands_acknowledged")
    return items


def required_attestations(draft: Draft) -> list[str]:
    attestations = ["non_normative"]
    if any(s["kind"] == "fetched" for s in draft.sources):
        attestations.append("licence_and_original_wording")
    return attestations
