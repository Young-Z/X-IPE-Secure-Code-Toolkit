"""Deterministic Policy resolution over formal Local knowledge (no AI, read-only)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..knowledge import durable, lifecycle, store
from ..knowledge.identity import RuleRef
from ..reference import cache as reference_cache
from ..reference import clock as reference_clock
from ..reference import policy_view, registry
from .refs import RequestedRef, is_utf8, parse_requested

COMPLETE = "complete"
PARTIAL = "partial"
MAINTENANCE_NEEDED = "maintenance_needed"
DEFAULT_PRESET_REL = "x-ipe-docs/secure-code/presets/default.json"
IMPORT_STEP = "Ask a Maintainer to import Local knowledge (secure-code knowledge import), then resolve again"
REACTIVATE_STEP = "All Local rules are deactivated: ask a Maintainer to reactivate or import rules"
APPLY_ALL_MESSAGE = (
    "No clues and no default Preset — Apply All proposed: every formal Local Policy. "
    "This is the Policy scope only; the artifact scope is decided separately."
)


@dataclass(frozen=True)
class Unreadable:
    """A rule folder whose files could not be read safely."""

    detail: str


def safe_read(tree: durable.Tree, ref: RuleRef) -> store.StoredRule | Unreadable | None:
    """Read one rule through the command's Tree; I/O, decoding and path errors become `Unreadable`."""
    try:
        return store.read_rule_at(tree, ref)
    except store.StoreError as exc:
        return Unreadable(exc.code)
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        # A hand-edited record (e.g. not a JSON object) is unreadable, never a traceback.
        return Unreadable(type(exc).__name__)


def deactivated(stored: store.StoredRule | Unreadable) -> bool:
    """A consistent rule whose lifecycle marker says deactivated."""
    return (
        isinstance(stored, store.StoredRule)
        and stored.consistent
        and store.lifecycle_state(stored.record)[0] == "deactivated"
    )


@dataclass
class Library:
    """Snapshot of formal rules, pending and exited identities taken under the knowledge lock.

    `overrides` (scope-save exception only) maps an identity to its pre-action view from one
    integrity-checked transition; it reconstructs proposal identity/state, never Policy content.
    """

    rules: dict[RuleRef, store.StoredRule | Unreadable]
    pending: set[str]
    exited: dict[str, dict[str, Any]] = field(default_factory=dict)
    notices: list[str] = field(default_factory=list)
    overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    # FEATURE-001-E (P1): registered Reference rules with their read-only cache states; empty → Local only.
    refs: registry.RegistryView = field(default_factory=registry.RegistryView.empty)
    now: datetime | None = None

    @property
    def size(self) -> int:
        return len(self.rules)

    def _present(self) -> set[RuleRef]:
        refs = set(self.rules)
        for rel, view in self.overrides.items():
            ref = RuleRef.parse(rel)
            if view["present"]:
                refs.add(ref)
            else:
                refs.discard(ref)
        return refs

    def versions(self, namespace: str, rule_id: str) -> list[RuleRef]:
        found = {r for r in self._present() if r.namespace == namespace and r.rule_id == rule_id}
        if self.refs.present:
            found.update(self.refs.versions(namespace, rule_id))
        return sorted(found)

    def active(self) -> list[RuleRef]:
        """The "all" set: stored rules except consistent deactivated ones (overrides applied)."""
        refs = {r for r in self.rules if not deactivated(self.rules[r])}
        for rel, view in self.overrides.items():
            ref = RuleRef.parse(rel)
            if view["active"]:
                refs.add(ref)
            else:
                refs.discard(ref)
        return sorted(refs)

    def exited_like(self, namespace: str, rule_id: str) -> list[dict[str, Any]]:
        """Exited identities NS/*/ID, as information (sorted by rule)."""
        found = []
        for rel, entry in sorted(self.exited.items()):
            ns, _, rid = rel.split("/")
            if (ns, rid) == (namespace, rule_id):
                found.append({"rule": rel, "reason": entry["action"], "renamed_to": entry.get("renamed_to")})
        return found


def snapshot(tree: durable.Tree) -> Library:
    """Read every stored rule, pending and exited identity through the command's Tree
    (call under the knowledge lock)."""
    rules: dict[RuleRef, store.StoredRule | Unreadable] = {}
    for ref in store.iter_refs_at(tree):
        stored = safe_read(tree, ref)
        if stored is not None:
            rules[ref] = stored
    return _library(tree, rules, _pending(tree))


def _pending(tree: durable.Tree) -> set[str]:
    found = store.list_pending_at(tree)
    return {p["rule"] for p in found if isinstance(p, dict) and isinstance(p.get("rule"), str)}


def partial(tree: durable.Tree, texts: list[str]) -> Library:
    """Library of only the named identities (plus pending and exited ones), e.g. relation targets."""
    rules: dict[RuleRef, store.StoredRule | Unreadable] = {}
    for text in texts:
        ref = parse_requested(text).full()
        if ref is not None and ref not in rules:
            stored = safe_read(tree, ref)
            if stored is not None:
                rules[ref] = stored
    return _library(tree, rules, _pending(tree))


def _library(tree: durable.Tree, rules: dict[RuleRef, Any], pending: set[str]) -> Library:
    formal = {r.rel for r in rules}
    memory, notice = lifecycle.memory_or_empty(tree)
    lib = Library(rules, pending - formal, latest_exits(memory, formal), [notice] if notice else [])
    _attach_references(tree, lib)
    return lib


def _attach_references(tree: durable.Tree, lib: Library) -> None:
    """FEATURE-001-E (P1): registry view and current-key cache states, read-only through the same Tree."""
    try:
        refs = registry.view_at(tree)
    except (store.StoreError, OSError, ValueError, UnicodeError) as exc:
        refs = registry.RegistryView(notice=f"REFERENCE_REGISTRY_UNREADABLE: {getattr(exc, 'message', exc)}")
    if refs.present:
        lib.now = reference_clock.utc_now()
        reference_cache.attach(tree, refs, lib.now)
    lib.refs = refs


def latest_exits(memory: list[dict[str, Any]], formal: set[str] | None = None) -> dict[str, dict[str, Any]]:
    """Latest exit-memory entry per identity (identities stored again are skipped)."""
    exited: dict[str, dict[str, Any]] = {}
    for entry in sorted(memory, key=lambda e: (e.get("at") or "", e["exit_id"])):
        if formal is None or entry["rule"] not in formal:
            exited[entry["rule"]] = entry
    return exited


def view_of(lib: Library, ref: RuleRef) -> dict[str, Any]:
    """Transition view of one identity: presence, "all" membership and what `evaluate` shows."""
    found = evaluate(lib, ref, [])
    stored = lib.rules.get(ref)
    digest = (found.get("source_evidence") or {}).get("state_digest")
    if digest is None and isinstance(stored, store.StoredRule) and stored.consistent:
        digest = store.state_digest(stored)
    return {
        "present": ref in lib._present(),
        "active": ref in lib.active(),
        "availability": found["availability"],
        "reason": found.get("reason"),
        "state_digest": digest,
    }


def language_note(applicability: Any, languages: list[str]) -> str:
    """Advisory comparison of rule applicability with the artifact languages; never filters."""
    if not languages:
        return "no_context"
    if not isinstance(applicability, list) or not applicability:
        return "unknown"
    wanted = {lang.lower() for lang in languages}
    return "matches" if wanted & {a.lower() for a in applicability} else "does_not_match"


def _strings(value: Any) -> list[str]:
    """Fields outside the item digest may be hand-edited; keep only a list of strings."""
    return [v for v in value if isinstance(v, str) and is_utf8(v)] if isinstance(value, list) else []


def _policy(lib: Library, ref: RuleRef, stored: store.StoredRule, languages: list[str]) -> dict[str, Any]:
    record = stored.record
    applicability = record.get("applicability", "unknown")
    location = record.get("source_location")
    return {
        "rule": ref.rel,
        "availability": "available",
        "name": record.get("name"),
        "kind": ref.kind,
        "requirement": stored.files.get("content.md", ""),
        "applicability": applicability,
        "language_note": language_note(applicability, languages),
        "examples": sorted(stored.item.examples) if stored.item else [],
        "relations": list(record.get("relations", [])),
        "source_evidence": {
            "source_location": location or "not recorded",
            "source_documents": _strings(record.get("source_documents")),
            "state_digest": store.state_digest(stored),
            "last_changed_at": updated if _strings([updated := record.get("updated_at")]) else None,
        },
        "other_versions": [r.rel for r in lib.versions(ref.namespace, ref.rule_id) if r != ref],
        "retrieval_status": "retrieved",
        "unresolved": [] if location else ["source location not recorded"],
    }


def evaluate(lib: Library, ref: RuleRef, languages: list[str]) -> dict[str, Any]:
    """Availability of one exact rule identity: a Policy entry or a `missing` entry with reason.

    FEATURE-001-E (P1, X-02 literal): a formal Local record or exit memory wins; otherwise a registered
    (or removed) Reference rule is evaluated from its cache; otherwise the delivered result."""
    found = _evaluate_local(lib, ref, languages)
    if not lib.refs.present or ref.rel in lib.overrides:
        return found
    if ref in lib.rules or ref.rel in lib.exited:
        return policy_view.local_first(lib, ref, found)
    if lib.refs.has(ref) or lib.refs.is_removed(ref):
        return policy_view.evaluate(lib, ref, languages)
    return found


def _evaluate_local(lib: Library, ref: RuleRef, languages: list[str]) -> dict[str, Any]:
    """The delivered FEATURE-001-C/001-D evaluation of formal Local knowledge (unchanged)."""
    if ref.rel in lib.overrides:
        return _projected(ref, lib.overrides[ref.rel])
    stored = lib.rules.get(ref)
    if stored is None:
        exited = lib.exited.get(ref.rel)
        if exited:
            result = {"availability": "missing", "reason": exited["action"]}
            if exited.get("renamed_to"):
                result["renamed_to"] = exited["renamed_to"]
            return result
        reason = "pending_decision" if ref.rel in lib.pending else "not_found"
        return {"availability": "missing", "reason": reason}
    if isinstance(stored, Unreadable):
        return {"availability": "missing", "reason": "unreadable", "detail": stored.detail}
    if stored.item is None:
        return {
            "availability": "missing",
            "reason": "unreadable",
            "detail": "record or content not parseable",
        }
    if not stored.consistent:
        return {
            "availability": "missing",
            "reason": "inconsistent",
            "detail": "stored state does not match its record",
        }
    if deactivated(stored):
        return {"availability": "missing", "reason": "deactivated"}
    return _policy(lib, ref, stored, languages)


def _projected(ref: RuleRef, view: dict[str, Any]) -> dict[str, Any]:
    """Pre-action proposal projection of one identity (no requirement, no Policy content)."""
    if view["availability"] == "available":
        return {
            "rule": ref.rel,
            "availability": "available",
            "source_evidence": {"state_digest": view["state_digest"]},
            "retrieval_status": "reconstructed",
        }
    return {"availability": view["availability"], "reason": view["reason"]}


def entry_for(lib: Library, req: RequestedRef, languages: list[str]) -> dict[str, Any]:
    """Resolve one requested reference (full or version-less)."""
    if lib.refs.present and req.text.lower().startswith("reference:"):
        return _prefixed(lib, req.text, languages)
    base: dict[str, Any] = {"requested": req.text}
    if req.invalid:
        return {**base, "availability": "missing", "reason": "invalid_reference", "detail": req.invalid}
    full = req.full()
    if full is not None:
        return {**base, **evaluate(lib, full, languages)}
    versions = lib.versions(req.namespace, req.rule_id)  # type: ignore[arg-type]
    exited = lib.exited_like(req.namespace, req.rule_id)  # type: ignore[arg-type]
    info = {"exited": exited} if exited else {}
    if not versions:
        if exited:
            latest = lib.exited[max(exited, key=lambda e: _exit_order(lib, e["rule"]))["rule"]]
            found = {"availability": "missing", "reason": latest["action"]}
            if latest.get("renamed_to"):
                found["renamed_to"] = latest["renamed_to"]
            return {**base, **found, **info}
        held = any(p.split("/")[0] == req.namespace and p.split("/")[-1] == req.rule_id for p in lib.pending)
        return {**base, "availability": "missing", "reason": "pending_decision" if held else "not_found"}
    if len(versions) == 1:
        return {**base, **evaluate(lib, versions[0], languages), **info}
    candidates = []
    for ref in versions:
        found = evaluate(lib, ref, languages)
        candidate = {"rule": ref.rel, "availability": found["availability"]}
        if "reason" in found:
            candidate["reason"] = found["reason"]
        else:
            candidate["state_digest"] = found["source_evidence"]["state_digest"]
        candidates.append(candidate)
    kinds = [policy_view.kind_of(lib, ref) for ref in versions] if lib.refs.present else []
    if "reference" in kinds:
        for candidate, kind in zip(candidates, kinds, strict=True):
            candidate["knowledge_kind"] = kind
    return {
        **base, "availability": "unclear", "reason": "multiple_versions", "candidates": candidates, **info,
    }


def _prefixed(lib: Library, text: str, languages: list[str]) -> dict[str, Any]:
    """`reference:NS/VER/ID` (FEATURE-001-E, 02e): the prefix never overrides Local first."""
    req = parse_requested(text[len("reference:"):])
    full = None if req.invalid else req.full()
    if full is None or not (lib.refs.has(full) or lib.refs.is_removed(full)):
        return {"requested": text, "availability": "missing", "reason": "invalid_reference",
                "detail": "not a registered Reference rule", "requested_kind": "reference"}
    found = {"requested": text, **evaluate(lib, full, languages), "requested_kind": "reference"}
    if full in lib.rules or full.rel in lib.exited:
        found["notes"] = [*found.get("notes", []), policy_view.PREFIX_NOTE]
    return found


def _exit_order(lib: Library, rel: str) -> tuple[str, str]:
    entry = lib.exited[rel]
    return entry.get("at") or "", entry["exit_id"]


def overall_status(entries: list[dict[str, Any]]) -> str:
    """BR-11: complete = all usable; partial = some usable; maintenance_needed = none usable."""
    usable = sum(1 for e in entries if e["availability"] == "available")
    if usable == 0:
        return MAINTENANCE_NEEDED
    return COMPLETE if usable == len(entries) else PARTIAL


def proposal_digest(mode: str, entries: list[dict[str, Any]]) -> str:
    """Digest of what the user is shown: references, availability and rule state digests."""
    considered = sorted(
        (
            {
                "requested": e["requested"],
                "availability": e["availability"],
                "reason": e.get("reason"),
                "rule": e.get("rule"),
                "state_digest": (e.get("source_evidence") or {}).get("state_digest"),
                "candidates": e.get("candidates"),
            }
            for e in entries
        ),
        key=lambda item: item["requested"],
    )
    data = json.dumps(
        {"mode": mode, "considered": considered}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def build(
    lib: Library,
    texts: list[str],
    apply_all: bool,
    languages: list[str],
    *,
    default_preset_exists: bool = False,
) -> dict[str, Any]:
    """Resolve references (or every library rule) into the proposal data."""
    mode = "apply_all" if apply_all else "clues"
    requested = [r.rel for r in lib.active()] if apply_all else texts
    if apply_all and lib.refs.present:  # FEATURE-001-E (DEC-14): Reference rules without Local or exit memory
        extra_refs = [r.rel for r in lib.refs.identities() if r not in lib.rules and r.rel not in lib.exited]
        requested = sorted({*requested, *extra_refs})
    entries: list[dict[str, Any]] = []
    seen: dict[str, dict[str, Any]] = {}
    for text in requested:
        if text in seen:
            seen[text]["duplicates"] = seen[text].get("duplicates", 0) + 1
            continue
        seen[text] = entry_for(lib, parse_requested(text), languages)
        entries.append(seen[text])
    counts = {"requested": len(entries)}
    for state in ("available", "missing", "unclear"):
        counts[state] = sum(1 for e in entries if e["availability"] == state)
    extra: dict[str, Any] = {}
    if apply_all:
        extra["inactive"] = inactive_counts(lib)
    if lib.refs.present:  # FEATURE-001-E (02f/02g): only with Reference rules; Local-only output unchanged
        extra["library_sizes"] = {"local": lib.size, "reference": lib.refs.count}
        extra["counts_by_kind"] = policy_view.counts_by_kind(entries)
    return {
        "notices": _notices(lib, entries, apply_all, default_preset_exists),
        "status": overall_status(entries),
        "mode": mode,
        "library_size": lib.size,
        "pending_count": len(lib.pending),
        "counts": counts,
        "adopted": [],
        "adoption": "nothing adopted yet — the user must confirm, then: secure-code scope save --confirmed",
        "proposal_digest": proposal_digest(mode, entries),
        "entries": entries,
        **extra,
    }


def inactive_counts(lib: Library) -> dict[str, int]:
    """Informational counts of the "all" exclusions; never part of status, counts or digest."""
    deactivated_count = sum(1 for r in lib.rules if deactivated(lib.rules[r]))
    actions = [e["action"] for e in lib.exited.values()]
    return {
        "deactivated": deactivated_count,
        "deleted": actions.count("deleted"),
        "renamed": actions.count("renamed"),
    }


def _notices(
    lib: Library, entries: list[dict[str, Any]], apply_all: bool, default_preset_exists: bool
) -> list[dict[str, Any]]:
    notices: list[dict[str, Any]] = [
        {"code": code, "message": "Exit memory is unreadable; exited identities are reported as not found"}
        for code in lib.notices
    ]
    if lib.refs.notice:
        code, _, detail = lib.refs.notice.partition(": ")
        notices.append({"code": code, "message": "The Reference registry is partly unreadable" +
                        (f": {detail}" if detail else "")})
    exited = sorted({x["rule"] for e in entries for x in e.get("exited", [])})
    if exited:
        notices.append(
            {
                "code": "EXITED_IDENTITIES",
                "message": "Exited identities (information only, not substituted): " + ", ".join(exited),
            }
        )
    if apply_all:
        notices.append(
            {
                "code": "APPLY_ALL_PROPOSED",
                "message": APPLY_ALL_MESSAGE,
                "default_preset_exists": default_preset_exists,
            }
        )
        if lib.pending:
            notices.append(
                {
                    "code": "PENDING_EXCLUDED",
                    "count": len(lib.pending),
                    "message": f"{len(lib.pending)} item(s) waiting for a Maintainer decision are excluded",
                }
            )
    multi: dict[str, list[str]] = {}
    for e in entries:
        rule = e.get("rule")
        if not rule:
            continue
        ns, _, rid = rule.split("/")
        versions = lib.versions(ns, rid)
        if len(versions) > 1:
            multi[f"{ns}/{rid}"] = [r.version for r in versions]
    if multi:
        notices.append(
            {
                "code": "MULTI_VERSION",
                "rules": multi,
                "message": "Rules present in several source versions: confirm which versions apply",
            }
        )
    return notices


def next_steps(data: dict[str, Any]) -> list[str]:
    """One next step per non-complete situation, plus the confirmation step (and, FEATURE-001-E, one
    step per Reference reason present)."""
    return _next_steps(data) + policy_view.next_steps(data["entries"])


def _next_steps(data: dict[str, Any]) -> list[str]:
    status = data["status"]
    if status == MAINTENANCE_NEEDED:
        if data["library_size"] == 0:
            return [IMPORT_STEP]
        if data["mode"] == "apply_all" and not data["entries"]:
            return [REACTIVATE_STEP]
        gaps = ", ".join(e["requested"] for e in data["entries"])
        return [f"Revise the references or ask a Maintainer to import them: {gaps}"]
    steps = []
    if status == PARTIAL:
        gaps = ", ".join(e["requested"] for e in data["entries"] if e["availability"] != "available")
        steps.append(
            f"Show the missing/unclear references to the user and record each as not_adopted: {gaps}"
        )
    steps.append(
        "Ask the user to confirm the scope, then run: secure-code scope save --decisions FILE --confirmed"
    )
    return steps
