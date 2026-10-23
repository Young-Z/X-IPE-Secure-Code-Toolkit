"""Adopted-scope records: decisions validation, digest identity, publication and load."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..atomic import atomic_write_bytes, dumps_json
from ..knowledge import durable, lifecycle, store
from ..knowledge.identity import IdentityError, RuleRef
from . import resolve
from .refs import is_utf8, parse_requested

DECISIONS_SCHEMA = "ai-secure-code-toolkit/scope-decisions/v1"
RECORD_SCHEMA = "ai-secure-code-toolkit/scope-record/v1"
ARTIFACT_SCOPE = "not determined by the Policy scope"
SCOPES_REL = "x-ipe-docs/secure-code/scopes"
SCOPE_LOCK_REL = f"{store.PRIVATE_REL}/locks/scopes.lock"
MAX_DECISIONS_BYTES = 1024 * 1024
MAX_TEXT = 4096
MODES = ("clues", "apply_all")
_HEX = re.compile(r"[0-9a-f]{64}")
_DECISION_KEYS = {
    "schema",
    "mode",
    "considered",
    "proposal_digest",
    "clues",
    "language_context",
    "decisions",
    "confirmation_note",
}


class ScopeError(Exception):
    """A refused scope operation with a problem code and optional next step."""

    def __init__(self, code: str, message: str, next_step: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_step = next_step


@dataclass
class Decisions:
    mode: str
    considered: list[str] | None
    proposal_digest: str
    clues: str
    language_context: list[str]
    decisions: list[dict[str, Any]]
    confirmation_note: str


def _invalid(message: str) -> ScopeError:
    return ScopeError(
        "DECISIONS_INVALID", message, "Fix the decisions file (see references/policy-selection.md)"
    )


def _text(value: Any, field: str, *, required: bool) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise _invalid(f"{field} must be a non-empty string" if required else f"{field} must be a string")
    if len(value) > MAX_TEXT:
        raise _invalid(f"{field} is longer than {MAX_TEXT} characters")
    return value


def _decision(raw: Any, index: int) -> dict[str, Any]:
    where = f"decisions[{index}]"
    if not isinstance(raw, dict) or not isinstance(raw.get("ref"), str) or not raw["ref"]:
        raise _invalid(f"{where} must be an object with a 'ref'")
    kind = raw.get("decision")
    if kind == "adopted":
        if set(raw) - {"ref", "decision", "state_digest", "note"}:
            raise _invalid(f"{where} has unknown fields")
        digest = raw.get("state_digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise _invalid(f"{where}.state_digest must be the state digest shown by policy resolve")
        note = _text(raw.get("note"), f"{where}.note", required=False)
        return {"ref": raw["ref"], "decision": kind, "state_digest": digest, "note": note or None}
    if kind == "not_adopted":
        if set(raw) - {"ref", "decision", "reason"}:
            raise _invalid(f"{where} has unknown fields")
        return {
            "ref": raw["ref"],
            "decision": kind,
            "reason": _text(raw.get("reason"), f"{where}.reason", required=True),
        }
    raise _invalid(f"{where}.decision must be 'adopted' or 'not_adopted'")


def load_decisions(path: str) -> Decisions:
    """Load and validate a decisions file written by the agent after the user confirmed."""
    file = Path(path)
    try:
        if not file.is_file() or file.is_symlink():
            raise _invalid(f"{path} is not a regular file")
        if file.stat().st_size > MAX_DECISIONS_BYTES:
            raise _invalid(f"{path} is larger than {MAX_DECISIONS_BYTES} bytes")
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise _invalid(f"{path} is not readable JSON: {exc}") from None
    if not isinstance(data, dict) or data.get("schema") != DECISIONS_SCHEMA:
        raise _invalid(f"decisions must be a JSON object with schema '{DECISIONS_SCHEMA}'")
    if not is_utf8(data):
        raise _invalid("decisions contain text that is not valid UTF-8")
    if set(data) - _DECISION_KEYS:
        raise _invalid(f"unknown fields: {sorted(set(data) - _DECISION_KEYS)}")
    mode = data.get("mode")
    if mode not in MODES:
        raise _invalid("mode must be 'clues' or 'apply_all'")
    considered = data.get("considered")
    if mode == "clues":
        if (
            not isinstance(considered, list)
            or not considered
            or not all(isinstance(c, str) for c in considered)
        ):
            raise _invalid("considered must list the references given to policy resolve")
    elif considered is not None:
        raise _invalid("considered is not used with mode 'apply_all'")
    digest = data.get("proposal_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise _invalid("proposal_digest must be the digest shown by policy resolve")
    languages = data.get("language_context") or []
    if not isinstance(languages, list) or not all(isinstance(lang, str) for lang in languages):
        raise _invalid("language_context must be a list of language names")
    raw = data.get("decisions")
    if not isinstance(raw, list) or not raw:
        raise _invalid("decisions must be a non-empty list")
    decisions = [_decision(d, i) for i, d in enumerate(raw)]
    refs = [d["ref"] for d in decisions]
    if len(set(refs)) != len(refs):
        raise _invalid("each reference may have only one decision")
    return Decisions(
        mode,
        considered,
        digest,
        _text(data.get("clues"), "clues", required=False),
        languages,
        decisions,
        _text(data.get("confirmation_note"), "confirmation_note", required=True),
    )


def _drift(dec: Decisions, entries: dict[str, dict[str, Any]]) -> list[str]:
    names = []
    for d in dec.decisions:
        e = entries.get(d["ref"])
        if e is None:
            names.append(f"{d['ref']} (no longer in the library)")
        elif d["decision"] == "adopted" and (
            e["availability"] != "available" or e["source_evidence"]["state_digest"] != d["state_digest"]
        ):
            names.append(f"{d['ref']} (changed)")
    if dec.mode == "apply_all":
        decided = {d["ref"] for d in dec.decisions}
        names += [f"{ref} (new)" for ref in entries if ref not in decided]
    return names or ["the proposal changed since it was shown"]


def check_decisions(
    dec: Decisions,
    data: dict[str, Any],
    lib: resolve.Library | None = None,
    tree: durable.Tree | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Verify the confirmed proposal is current and every considered reference has a valid decision.

    Returns (adopted, not_adopted, references outside the confirmed scope). A changed proposal is
    accepted only through the single-transition not-adopted exception (AC-001D-02f).
    """
    entries = {e["requested"]: e for e in data["entries"]}
    outside: list[str] = []
    if data["proposal_digest"] != dec.proposal_digest:
        explained = _exception(dec, data, lib, tree) if lib is not None and tree is not None else None
        if explained is None:
            raise ScopeError(
                "STALE_CONFIRMATION",
                "Knowledge changed after the user saw the proposal: " + ", ".join(_drift(dec, entries)),
                "Resolve again, show the new proposal to the user and confirm again",
            )
        entries, outside = explained
    adopted, not_adopted = _decide(dec, entries)
    return adopted, not_adopted, outside


def _decide(
    dec: Decisions, entries: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_ref = {d["ref"]: d for d in dec.decisions}
    unknown = sorted(set(by_ref) - set(entries))
    if unknown:
        raise _invalid(f"decisions name references that were not considered: {', '.join(unknown)}")
    undecided = sorted(set(entries) - set(by_ref))
    if undecided:
        raise ScopeError(
            "DECISION_MISSING",
            f"No decision for: {', '.join(undecided)}",
            "Record each missing or unclear reference as not_adopted with the user's reason",
        )
    adopted, not_adopted, refused = [], [], []
    for ref, d in sorted(by_ref.items()):
        e = entries[ref]
        if d["decision"] == "not_adopted":
            not_adopted.append({"requested": ref, "availability": e["availability"], "reason": d["reason"]})
        elif e["availability"] != "available" or e["source_evidence"]["state_digest"] != d["state_digest"]:
            refused.append(ref)
        else:
            adopted.append(
                {"rule": e["rule"], "requested": ref, "state_digest": d["state_digest"], "note": d["note"]}
            )
    if refused:
        raise ScopeError(
            "NOT_ADOPTABLE",
            f"Only available Policies with their shown state can be adopted: {', '.join(refused)}",
            "Record them as not_adopted or resolve again",
        )
    if not adopted:
        raise ScopeError(
            "NOTHING_ADOPTED",
            "A scope needs at least one adopted Policy",
            "Adopt at least one available Policy, or ask a Maintainer to import knowledge",
        )
    return sorted(adopted, key=lambda a: a["rule"]), not_adopted


TRANSITION_STEP = (
    "Ask a Maintainer to inspect the exit transition and its changelog or memory binding; "
    "do not publish a scope"
)


def _transition_invalid(message: str) -> ScopeError:
    return ScopeError("EXIT_TRANSITION_INVALID", f"exit transition is invalid: {message}", TRANSITION_STEP)


def _verified_transition(tree: durable.Tree) -> dict[str, Any] | None:
    """The latest committed transition, integrity-checked against its changelog/memory binding."""
    try:
        entries = lifecycle.transition_entries(
            lifecycle.read_at(tree, lifecycle.EXITS_REL, lifecycle.TRANSITIONS_NAME)
        )
    except (ValueError, OSError):
        raise _transition_invalid("the transition log is unreadable") from None
    if not entries:
        return None
    entry = entries[-1]
    try:
        digest = entry["digest"]
        if lifecycle.transition_digest(entry) != digest:
            raise _transition_invalid("its content does not match its digest")
        action, rule, target = entry["action"], entry["rule"], entry.get("target")
        identities = entry["identities"]
        if not isinstance(identities, dict) or rule not in identities:
            raise _transition_invalid("it does not describe its rule")
        if action in ("deactivate", "reactivate", "rename"):
            folder = target if action == "rename" else rule
            log = lifecycle.read_at(tree, f"{store.LOCAL_REL}/{folder}", "changelog.md") or b""
            if f"- transition: {digest}\n".encode() not in log:
                raise _transition_invalid("the rule's changelog does not bind it")
        if action in ("delete", "rename"):
            memory = lifecycle.read_memory(tree)
            if not any(m["exit_id"] == entry["exit_id"] and m.get("transition") == digest for m in memory):
                raise _transition_invalid("the exit memory does not bind it")
    except (KeyError, TypeError, AttributeError, ValueError, store.StoreError) as exc:
        raise _transition_invalid(f"it is malformed ({exc})") from None
    return entry


def _projection(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (
        entry["availability"], entry.get("reason"), entry.get("rule"),
        (entry.get("source_evidence") or {}).get("state_digest"), entry.get("candidates"),
    )


def _exception(
    dec: Decisions, data: dict[str, Any], lib: resolve.Library, tree: durable.Tree
) -> tuple[dict[str, dict[str, Any]], list[str]] | None:
    """Explain a changed proposal by exactly one exit whose affected references were explicitly
    decided not_adopted; returns (current entries of the originally considered references,
    references outside the confirmed scope) or None (stale)."""
    entry = _verified_transition(tree)
    if entry is None:
        return None
    identities = entry["identities"]
    try:
        for rel, views in identities.items():
            if resolve.view_of(lib, RuleRef.parse(rel)) != views["after"]:
                return None  # a later content edit or another action is not explained
        before = {rel: dict(views["before"]) for rel, views in identities.items()}
    except (IdentityError, KeyError, TypeError):
        raise _transition_invalid("its identity views are malformed") from None
    pre = resolve.Library(lib.rules, lib.pending, lib.exited, lib.notices, before)
    apply_all = dec.mode == "apply_all"
    original = resolve.build(pre, dec.considered or [], apply_all, dec.language_context)
    if original["proposal_digest"] != dec.proposal_digest:
        return None
    current = {e["requested"]: e for e in data["entries"]}
    decided = {d["ref"]: d["decision"] for d in dec.decisions}
    now: dict[str, dict[str, Any]] = {}
    for e in original["entries"]:
        ref = e["requested"]
        found = current.get(ref) or resolve.entry_for(lib, parse_requested(ref), dec.language_context)
        if _projection(found) != _projection(e) and decided.get(ref) != "not_adopted":
            return None
        now[ref] = found
    outside = sorted(set(current) - set(now))
    if outside and not (entry["action"] == "rename" and outside == [entry.get("target")]):
        return None
    return now, outside


def _canonical(record: dict[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k not in ("scope_id", "created_at")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def with_id(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with `scope_id` = SHA-256 of the canonical record without id and creation time."""
    return {**record, "scope_id": "sha256:" + hashlib.sha256(_canonical(record)).hexdigest()}


def build_record(
    dec: Decisions, adopted: list[dict[str, Any]], not_adopted: list[dict[str, Any]], created_at: str
) -> dict[str, Any]:
    return with_id(
        {
            "schema": RECORD_SCHEMA,
            "mode": dec.mode,
            "clues": dec.clues,
            "language_context": dec.language_context,
            "adopted": adopted,
            "not_adopted": not_adopted,
            "artifact_scope": ARTIFACT_SCOPE,
            "confirmation_note": dec.confirmation_note,
            "created_at": created_at,
        }
    )


def _bad(message: str) -> ScopeError:
    return ScopeError(
        "SCOPE_INVALID",
        message,
        "Do not use this scope; remove the damaged file, then select and confirm the scope again",
    )


def verify_record(record: Any, hex_id: str) -> dict[str, Any]:
    """Check schema, structure and that the content matches its identifier and file name."""
    if not isinstance(record, dict) or record.get("schema") != RECORD_SCHEMA:
        raise _bad("not a scope record")
    if not is_utf8(record):
        raise _bad("scope record contains text that is not valid UTF-8")
    if (
        record.get("mode") not in MODES
        or not isinstance(record.get("adopted"), list)
        or not record["adopted"]
    ):
        raise _bad("scope record is malformed")
    if not isinstance(record.get("not_adopted"), list):
        raise _bad("scope record is malformed")
    if not isinstance(record.get("created_at"), str):
        raise _bad("scope record is malformed")
    languages = record.get("language_context", [])
    if not isinstance(languages, list) or not all(isinstance(lang, str) for lang in languages):
        raise _bad("scope record is malformed")
    for a in record["adopted"]:
        if not isinstance(a, dict) or not isinstance(a.get("state_digest"), str):
            raise _bad("scope record is malformed")
        try:
            RuleRef.parse(a.get("rule"))
        except IdentityError:
            raise _bad("scope record names an invalid rule") from None
    expected = with_id(record)["scope_id"]
    if record.get("scope_id") != expected or expected != f"sha256:{hex_id}":
        raise _bad("scope record content does not match its identifier")
    return record


def parse_scope_id(text: str) -> str:
    value = text[len("sha256:") :] if isinstance(text, str) and text.startswith("sha256:") else text
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ScopeError(
            "SCOPE_NOT_FOUND",
            f"Not a scope identifier: {text!r}",
            "Pass the scope_id returned by secure-code scope save",
        )
    return value


def read_record(root: Path, scope_text: str) -> dict[str, Any]:
    """Load and verify one stored scope record."""
    hex_id = parse_scope_id(scope_text)
    rel = f"{SCOPES_REL}/{hex_id}.json"
    store.ensure_safe(root, rel, expect_dir=False)
    path = root / rel
    if not path.is_file():
        raise ScopeError(
            "SCOPE_NOT_FOUND",
            f"No scope record {hex_id}",
            "Pass the scope_id returned by secure-code scope save",
        )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise _bad("scope record is not readable JSON") from None
    return verify_record(record, hex_id)


def publish(root: Path, record: dict[str, Any], tree: durable.Tree) -> tuple[str, bool, dict[str, Any]]:
    """Write the record once under the scope lock (taken via the caller's Tree while it holds the
    knowledge lock); an identical existing record is returned unchanged."""
    hex_id = record["scope_id"].split(":", 1)[1]
    rel = f"{SCOPES_REL}/{hex_id}.json"
    store.ensure_safe(root, SCOPES_REL, expect_dir=True)
    store.ensure_safe(root, rel, expect_dir=False)
    with durable.DirLock(tree, SCOPE_LOCK_REL, create=True):
        if (root / rel).exists():
            return rel, False, read_record(root, hex_id)
        atomic_write_bytes(root / rel, dumps_json(record))
    return rel, True, record


def load_scope(lib: resolve.Library, record: dict[str, Any]) -> dict[str, Any]:
    """Compare each adopted Policy with its confirmed state; only unchanged ones stay adopted."""
    languages = record.get("language_context") or []
    entries, adopted_rules = [], []
    for a in record["adopted"]:
        found = resolve.evaluate(lib, RuleRef.parse(a["rule"]), languages)
        base = {
            "rule": a["rule"],
            "requested": a.get("requested"),
            "note": a.get("note"),
            "confirmed_state_digest": a["state_digest"],
        }
        if found["availability"] != "available":
            missing = {**base, "adoption": "missing", "reason": found["reason"]}
            if found.get("renamed_to"):
                missing["renamed_to"] = found["renamed_to"]
            entries.append(missing)
            continue
        current = found["source_evidence"]["state_digest"]
        if current == a["state_digest"]:
            entries.append({**base, "adoption": "adopted", "policy": found})
            adopted_rules.append(a["rule"])
        else:
            entries.append(
                {
                    **base,
                    "adoption": "needs_reconfirmation",
                    "changed_since_confirmation": True,
                    "current_state_digest": current,
                    "for_review": found,
                }
            )
    if not adopted_rules:
        status = resolve.MAINTENANCE_NEEDED
    else:
        status = resolve.COMPLETE if len(adopted_rules) == len(record["adopted"]) else resolve.PARTIAL
    return {
        "status": status,
        "scope_id": record["scope_id"],
        "mode": record["mode"],
        "artifact_scope": record.get("artifact_scope"),
        "adopted_rules": adopted_rules,
        "counts": {
            s: sum(1 for e in entries if e["adoption"] == s)
            for s in ("adopted", "needs_reconfirmation", "missing")
        },
        "entries": entries,
        "not_adopted": record["not_adopted"],
        "clues": record.get("clues"),
        "confirmation_note": record.get("confirmation_note"),
        "created_at": record.get("created_at"),
    }
