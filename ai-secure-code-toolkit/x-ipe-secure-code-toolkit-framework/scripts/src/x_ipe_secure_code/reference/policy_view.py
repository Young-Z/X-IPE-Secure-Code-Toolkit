"""Reference Policies and `missing` entries for the single 001-C resolution entry point (FEATURE-001-E, P1).

Called only from `policy.resolve` when a Reference rule (or its tombstone) exists for the identity and no
formal Local record or exit memory does (X-02, read literally). Never fetches and never writes: the cache
states were attached read-only when the Library snapshot was taken.
"""

from __future__ import annotations

from typing import Any

from ..knowledge.identity import RuleRef
from .registry import Bad

CONTENT_LABEL = "untrusted_external"
PENDING_NOTE = "Reference used; pending Local candidate exists"
LOCAL_NOTE = "Reference with the same identity exists and was not accessed (Local first, X-02)"
LOCAL_BROKEN = "A Reference with the same identity exists but was not substituted (Local first, X-02)"
PREFIX_NOTE = "reference: prefix does not override Local first (X-02); Local used"
FETCH_STEP = (
    "Open a Guard verification on an available scope, ask the User to grant reference_fetch "
    "(secure-code guard allow-egress --purpose reference_fetch --recipient ORIGIN --data public_query "
    "--scope URL), then run secure-code knowledge reference fetch --run ID --rule REF [--refresh]"
)
CLEAN_STEP = "Run secure-code knowledge reference cache-clean, then fetch again inside a verification"


def _missing(reason: str, **extra: Any) -> dict[str, Any]:
    return {"availability": "missing", "reason": reason, "knowledge_kind": "reference", **extra}


def _registration(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": record["title"],
        "entry_url": record["entry_url"],
        "applicability": record["applicability"],
    }


def _policy(lib: Any, ref: RuleRef, entry: dict[str, Any], languages: list[str]) -> dict[str, Any]:
    from ..policy.resolve import language_note

    evidence = {
        "source_location": entry["canonical_url"],
        "source_documents": [],
        "state_digest": entry["policy_state_digest"],
        "last_changed_at": entry["fetched_at"],
        "entry_url": entry["canonical_url"],
        "fetched_at": entry["fetched_at"],
        "expires_at": entry["expires_at"],
        "response_digest": entry["response_digest"],
        "policy_state_digest": entry["policy_state_digest"],
        "registration_digest": entry["registration_digest"],
        "parser_version": entry["parser_version"],
        "cache_state": "valid",
    }
    return {
        "rule": ref.rel,
        "availability": "available",
        "name": entry["title"],
        "kind": ref.kind,
        "knowledge_kind": "reference",
        "requirement": entry["text"],
        "content_label": CONTENT_LABEL,
        "applicability": entry["applicability"],
        "language_note": language_note(entry["applicability"], languages),
        "examples": [],
        "relations": [],
        "source_evidence": evidence,
        "masking": entry["masking"],
        "other_versions": [r.rel for r in lib.versions(ref.namespace, ref.rule_id) if r != ref],
        "retrieval_status": "cached",
        "unresolved": [],
    }


def evaluate(lib: Any, ref: RuleRef, languages: list[str]) -> dict[str, Any]:
    """Reference Policy (valid entry) or a `missing` entry with the Reference reason."""
    refs = lib.refs
    if refs.is_removed(ref):
        stone = refs.removed[ref.rel]
        return _missing("deleted", detail="Reference rule removed", removed_at=stone["removed_at"])
    usable = refs.usable(ref)
    if isinstance(usable, Bad):
        found = _missing("unreadable", detail=usable.detail)
    else:
        record = usable[0]
        state = refs.states.get(ref.rel)
        if state is None or state.state == "not_cached":
            found = _missing(
                "not_cached",
                registration=_registration(record),
                detail="content not obtained (no cache entry for the current registration)",
            )
        elif state.state == "invalid":
            found = _missing("cache_invalid", detail=state.detail)
        elif state.state == "expired":
            found = _missing(
                "cache_expired", fetched_at=state.entry["fetched_at"], expires_at=state.entry["expires_at"]
            )
        else:
            found = _policy(lib, ref, state.entry, languages)
    if ref.rel in lib.pending:
        found["notes"] = [PENDING_NOTE]
    return found


def local_first(lib: Any, ref: RuleRef, found: dict[str, Any]) -> dict[str, Any]:
    """A formal Local record (or exit memory) wins; say that a Reference exists and was not accessed."""
    if not lib.refs.has(ref):
        return found
    if found["availability"] == "available":
        return {**found, "notes": [LOCAL_NOTE]}
    return {**found, "unresolved": [*found.get("unresolved", []), LOCAL_BROKEN]}


def kind_of(lib: Any, ref: RuleRef) -> str:
    return "local" if ref in lib.rules or ref.rel in lib.exited or not lib.refs.has(ref) else "reference"


def counts_by_kind(entries: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out = {kind: dict.fromkeys(("available", "missing", "unclear"), 0) for kind in ("local", "reference")}
    for e in entries:
        kind = "reference" if e.get("knowledge_kind") == "reference" else "local"
        out[kind][e["availability"]] += 1
    return out


def next_steps(entries: list[dict[str, Any]]) -> list[str]:
    reasons = {e.get("reason") for e in entries if e.get("knowledge_kind") == "reference"}
    steps = []
    if reasons & {"not_cached", "cache_expired"}:
        steps.append(FETCH_STEP)
    if "cache_invalid" in reasons:
        steps.append(CLEAN_STEP)
    return steps
