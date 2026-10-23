"""Knowledge operations: check, import, update, list, show (FEATURE-001-B)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..auth.service import require_maintainer
from ..auth.trust_store import TrustPaths
from ..projects import knowledge_root
from ..results import Problem, Result
from . import changelog, exit_journal, lifecycle, precheck, store
from .batch import (
    DIGEST,
    MAX_ITEM_BYTES,
    BatchError,
    Item,
    ItemError,
    apply_update,
    identity_label,
    load_batch,
    load_check,
    load_update,
    parse_item,
)
from .identity import IdentityError, RuleRef, find_collision
from .views import list_rules, show_rule

__all__ = ["check", "import_batch", "list_rules", "show_rule", "update_rule"]

FAILURE_OUTCOMES = ("refused", "not_processed")
REACTIVATE_FIRST = "Reactivate {rule} first with secure-code knowledge exit-preview --action reactivate"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root(project: str | None, command: str) -> Path | Result:
    return knowledge_root(project, command)


def _recover(root: Path, command: str) -> dict[str, Any] | None | Result:
    """FR-001D-6: complete or roll back an interrupted exit before this command's own checks."""
    try:
        return exit_journal.ensure_recovered(root)
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(command, exc)


def _authorize(command: str, trust_paths: TrustPaths | None) -> Result | None:
    decision = require_maintainer(f"knowledge.{command.split()[-1]}", paths=trust_paths)
    return None if decision.allowed else decision.to_result()


def _parse_accepts(values: list[str]) -> dict[RuleRef, str]:
    result = {}
    for value in values:
        rule, sep, digest = value.partition("@sha256:")
        if not sep:
            raise ItemError(f"--accept-update must be RULE@sha256:<digest>: {value}", "ARGUMENT_INVALID")
        result[RuleRef.parse(rule)] = "sha256:" + digest
    return result


def _parse_false_positives(values: list[str]) -> dict[RuleRef, set[str]]:
    result: dict[RuleRef, set[str]] = {}
    for value in values:
        rule, sep, fingerprint = value.rpartition(":")
        if not sep or not rule:
            raise ItemError(f"--false-positive must be RULE:FINGERPRINT: {value}", "ARGUMENT_INVALID")
        result.setdefault(RuleRef.parse(rule), set()).add(fingerprint)
    return result


def _files_for(item: Item) -> dict[str, str]:
    return store.item_files(item)


def _write_rule(
    root: Path,
    item: Item,
    stored: store.StoredRule | None,
    operation: str,
    declared: list[precheck.Finding],
    source_documents: list[str],
    source_document: str | None,
) -> None:
    now = _now()
    old_files = dict(stored.files) if stored else {}
    old_record = stored.record_raw if stored else None
    old_log = old_files.pop("changelog.md", changelog.header(item.ref.rel))
    new_files = _files_for(item)
    record = store.record_text(
        item,
        created_at=stored.record["created_at"] if stored else now,
        updated_at=now,
        source_documents=source_documents,
        lifecycle=store.lifecycle_of(stored.record) if stored else None,
    )
    names = sorted(set(old_files) | set(new_files))
    changes = [("record.json", old_record, record)] + [(n, old_files.get(n), new_files.get(n)) for n in names]
    log = old_log + changelog.entry(
        time=now,
        operation=operation,
        item_digest=item.digest(),
        base_digest=stored.digest if stored else None,
        source_document=source_document,
        declared=declared,
        changes=changes,
    )
    writes = {"record.json": record, "changelog.md": log}
    writes.update({n: t for n, t in new_files.items() if old_files.get(n) != t})
    deletes = [n for n in old_files if n not in new_files]
    store.commit(
        root,
        item.ref,
        writes,
        deletes,
        base_digest=stored.digest if stored else None,
        new_digest=item.digest(),
    )


def _findings(item: Item, key: bytes) -> list[precheck.Finding]:
    return precheck.scan(_files_for(item), key)


# --------------------------------------------------------------------------- check
def check(project: str | None, input_path: str) -> Result:
    root = _root(project, "knowledge check")
    if isinstance(root, Result):
        return root
    try:
        pairs, documents = load_check(input_path)
    except BatchError as exc:
        return Result.refused("knowledge check", "BATCH_INVALID", str(exc))

    def safe_read(text: str) -> store.StoredRule | None:
        try:
            return store.read_rule(root, RuleRef.parse(text))
        except (IdentityError, store.StoreError):
            return None

    try:
        session = exit_journal.session(root, write=False)
        recovered = session.__enter__().recovered
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal("knowledge check", exc)
    try:
        items: dict[str, str] = {}
        for rule, digest in pairs:
            stored = safe_read(rule)
            if stored is None or stored.digest is None:
                items[rule] = "new"
            else:
                items[rule] = "stored_unchanged" if stored.digest == digest else "stored_changed"
        index = store.load_index(root)
        docs = {}
        for digest in documents:
            entry = index.get(digest)
            full = bool(entry and entry.get("complete"))
            for edge in (entry or {}).get("items", []):
                stored = safe_read(edge["rule"])
                full &= bool(
                    stored
                    and stored.consistent
                    and stored.digest == edge["item_digest"]
                    and store.lifecycle_state(stored.record)[0] == "active"
                )
            docs[digest] = "fully_stored" if full else "not_fully_stored"
    finally:
        session.__exit__(None, None, None)
    return exit_journal.with_recovered(
        Result("knowledge check", True, {"items": items, "source_documents": docs}), recovered
    )


# --------------------------------------------------------------------------- import
def import_batch(
    project: str | None,
    batch_path: str,
    accept_updates: list[str],
    false_positives: list[str],
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    command = "knowledge import"
    root = _root(project, command)
    if isinstance(root, Result):
        return root
    recovered = _recover(root, command)
    if isinstance(recovered, Result):
        return recovered
    result = _import_batch(root, command, batch_path, accept_updates, false_positives, trust_paths)
    return exit_journal.with_recovered(result, recovered)


def _import_batch(
    root: Path,
    command: str,
    batch_path: str,
    accept_updates: list[str],
    false_positives: list[str],
    trust_paths: TrustPaths | None,
) -> Result:
    denied = _authorize(command, trust_paths)
    if denied:
        return denied
    try:
        accepts = _parse_accepts(accept_updates)
        declared_fps = _parse_false_positives(false_positives)
        expected, raw_items = load_batch(batch_path)
    except (ItemError, IdentityError) as exc:
        return Result.refused(command, exc.code, exc.message)
    except BatchError as exc:
        return Result.refused(command, "BATCH_INVALID", str(exc))

    problems: list[Problem] = []
    if expected is not None and expected != len(raw_items):
        problems.append(
            Problem(
                "EXPECTED_COUNT_MISMATCH", f"batch declares {expected} items but contains {len(raw_items)}"
            )
        )
    parsed: list[tuple[str, Item | None, dict[str, Any] | None]] = []
    for index, raw in enumerate(raw_items):
        label = identity_label(raw, index)
        try:
            parsed.append((label, parse_item(raw), None))
        except (ItemError, IdentityError) as exc:
            parsed.append((label, None, {"code": exc.code, "reason": exc.message}))
    counts: dict[str, int] = {}
    for _, item, _ in parsed:
        if item:
            counts[item.ref.rel.lower()] = counts.get(item.ref.rel.lower(), 0) + 1
    for target in set(accepts) | set(declared_fps):
        if not any(item and item.ref == target for _, item, _ in parsed):
            problems.append(Problem("UNKNOWN_ACCEPT", f"{target} is not in this batch; no effect"))

    try:
        with exit_journal.session(root, write=True):
            store.ensure_safe(root, precheck.KEY_REL, expect_dir=False)
            key = precheck.load_or_create_key(root)
    except LockHeld as exc:
        return Result.refused(command, "LOCKED", str(exc), "Retry when the other operation finished")
    except store.StoreError as exc:
        return Result.refused(command, exc.code, exc.message)
    except OSError as exc:
        return Result.refused(command, "IO_ERROR", str(exc.strerror or exc))
    results: list[dict[str, Any]] = []
    touched_documents: dict[str, list[tuple[RuleRef, str, str]]] = {}
    halted = False
    for label, item, error in parsed:
        entry: dict[str, Any] = {"rule": label}
        if halted:
            entry.update(outcome="not_processed", code="IO_ERROR", reason="stopped after an I/O failure")
        elif error:
            entry.update(outcome="refused", **error)
        elif counts[item.ref.rel.lower()] > 1:
            entry.update(
                outcome="refused",
                code="DUPLICATE_IN_BATCH",
                reason="the same identity appears more than once in this batch",
            )
        elif item.size() > MAX_ITEM_BYTES:
            entry.update(
                outcome="refused",
                code="ITEM_TOO_LARGE",
                reason=f"item is {item.size()} bytes; maximum is {MAX_ITEM_BYTES}",
            )
        else:
            try:
                entry.update(
                    _import_one(
                        root, item, key, accepts.get(item.ref), declared_fps.get(item.ref, set()), trust_paths
                    )
                )
            except LockHeld as exc:
                entry.update(outcome="not_processed", code="LOCKED", reason=str(exc))
            except store.StoreError as exc:
                entry.update(outcome="refused", code=exc.code, reason=exc.message)
            except OSError as exc:
                entry.update(outcome="not_processed", code="IO_ERROR", reason=str(exc.strerror or exc))
                halted = True
            except ValueError as exc:
                entry.update(outcome="refused", code="ITEM_INVALID", reason=str(exc))
        document = _raw_document(raw_items, len(results))
        if document:
            touched_documents.setdefault(document, []).append(
                (label, entry["outcome"], entry.get("item_digest") if item else None)
            )
        results.append(entry)

    if touched_documents:
        try:
            with exit_journal.session(root, write=True):
                _update_index(root, touched_documents)
        except (LockHeld, OSError, store.StoreError) as exc:
            problems.append(Problem("INDEX_NOT_UPDATED", f"document index not updated: {exc}"))
    tally: dict[str, int] = {}
    for entry in results:
        tally[entry["outcome"]] = tally.get(entry["outcome"], 0) + 1
    ok = not any(e["outcome"] in FAILURE_OUTCOMES for e in results)
    next_steps = []
    if tally.get("update_candidate"):
        next_steps.append("Review update candidates; re-run with --accept-update RULE@<stored_digest>")
    for entry in results:
        if entry.get("code") == "RULE_DEACTIVATED":
            next_steps.append(REACTIVATE_FIRST.format(rule=entry["rule"]))
    if tally.get("needs_decision"):
        next_steps.append(
            "Remove genuine secrets/instructions, or declare false positives with "
            "--false-positive RULE:FINGERPRINT"
        )
    return Result(command, ok, {"items": results, "counts": tally}, problems, next_steps)


def _import_one(
    root: Path,
    item: Item,
    key: bytes,
    accept_digest: str | None,
    declared: set[str],
    trust_paths: TrustPaths | None,
) -> dict[str, Any]:
    with exit_journal.session(root, write=True) as session:
        exited = lifecycle.reserved(lifecycle.read_memory(session.tree), item.ref)
        if exited:
            how = f"renamed to {exited['renamed_to']}" if exited.get("renamed_to") else "deleted"
            return {
                "outcome": "refused",
                "code": "IDENTITY_RESERVED",
                "reason": f"{exited['rule']} is a reserved exited identity ({how} at {exited.get('at')})",
            }
        store.recover(root, item.ref)
        collision = find_collision(store.local_root(root), item.ref)
        if collision:
            return {"outcome": "refused", "code": "IDENTITY_COLLISION", "reason": collision}
        stored = store.read_rule(root, item.ref)
        inactive = stored is not None and stored.consistent and store.lifecycle_state(stored.record)[0]
        if inactive == "deactivated":
            return {
                "outcome": "refused",
                "code": "RULE_DEACTIVATED",
                "reason": f"{item.ref} is deactivated; reactivate it before importing",
            }
        if stored is not None and not stored.consistent:
            return {
                "outcome": "refused",
                "code": "RULE_INCONSISTENT",
                "reason": "stored rule does not match its record; resolve before writing",
            }
        digest = item.digest()
        documents = list(stored.record.get("source_documents", [])) if stored else []
        new_document = item.source_document_digest
        if stored and stored.digest == digest:
            store.remove_pending(root, item.ref)
            if not new_document or new_document in documents:
                return {"outcome": "current", "item_digest": digest}
            operation, base_documents = "provenance_added", documents + [new_document]
            findings: list[precheck.Finding] = []
        else:
            if stored and accept_digest is None:
                return {
                    "outcome": "update_candidate",
                    "stored_digest": stored.digest,
                    "item_digest": digest,
                    "reason": "same identity, different input; accept explicitly to update",
                }
            if stored and accept_digest != stored.digest:
                return {
                    "outcome": "refused",
                    "code": "STATE_CONFLICT",
                    "stored_digest": stored.digest,
                    "reason": "accepted digest does not match the stored rule",
                }
            findings = _findings(item, key)
            blocking = [f for f in findings if f.blocking]
            undeclared = [f for f in blocking if f.fingerprint not in declared]
            if undeclared:
                store.write_pending(root, item.ref, digest, [f.to_dict() for f in blocking], _now())
                return {
                    "outcome": "needs_decision",
                    "item_digest": digest,
                    "findings": [f.to_dict() for f in blocking],
                    "reason": "suspected credential or embedded instruction",
                }
            operation = "accepted_update" if stored else "created"
            if blocking:
                operation = "accepted_update+flagged" if stored else "accepted_flagged"
            base_documents = [new_document] if new_document else []
        if _authorize("knowledge import", trust_paths):
            return {
                "outcome": "refused",
                "code": "NOT_AUTHORIZED",
                "reason": "Maintainer qualification no longer valid",
            }
        declared_findings = [f for f in findings if f.blocking]
        _write_rule(root, item, stored, operation, declared_findings, base_documents, new_document)
        store.remove_pending(root, item.ref)
        notes = [f.to_dict() for f in findings if not f.blocking]
        result: dict[str, Any] = {"outcome": "stored", "operation": operation, "item_digest": digest}
        if notes:
            result["notes"] = notes
        return result


def _raw_document(raw_items: list[Any], index: int) -> str | None:
    raw = raw_items[index] if index < len(raw_items) else None
    value = raw.get("source_document_digest") if isinstance(raw, dict) else None
    return value if isinstance(value, str) and DIGEST.fullmatch(value) else None


def _update_index(root: Path, touched: dict[str, list[tuple[str, str, str | None]]]) -> None:
    """Merge this batch into each document entry.

    Identified failures clear only when that same rule later succeeds. Failures of items
    without a usable identity (`#N`) are counted; the count resets only when a later batch
    for the document has no failures and at least as many items as its largest batch.
    """
    index = store.load_index(root)
    before = json.dumps(index, sort_keys=True)
    for document, entries in touched.items():
        old = index.get(document, {})
        edges = {e["rule"]: e["item_digest"] for e in old.get("items", [])}
        failed = {label for label in old.get("failed", []) if not label.startswith("#")}
        if "unidentified_failures" in old:
            unidentified = int(old["unidentified_failures"])
        else:  # entry written before the counter existed: keep its failures conservatively
            unidentified = sum(1 for label in old.get("failed", []) if label.startswith("#"))
            if old and old.get("complete") is False and not failed and unidentified == 0:
                unidentified = 1
        # Entries written before `largest_batch` existed: use the document's known size.
        largest = int(old.get("largest_batch", len(old.get("items", [])) + len(old.get("failed", []))))
        batch_failures = batch_unidentified = 0
        for label, outcome, digest in entries:
            if outcome in ("stored", "current") and digest:
                edges[label] = digest
                failed.discard(label)
            elif label.startswith("#"):
                batch_unidentified += 1
            else:
                failed.add(label)
                batch_failures += 1
        if batch_unidentified:
            unidentified = batch_unidentified
        elif batch_failures == 0 and len(entries) >= largest:
            unidentified = 0
        largest = max(largest, len(entries))
        entry = {
            "items": [{"rule": r, "item_digest": d} for r, d in sorted(edges.items())],
            "failed": sorted(failed),
            "unidentified_failures": unidentified,
            "largest_batch": largest,
            "complete": not failed and unidentified == 0,
            "updated_at": old.get("updated_at") or _now(),
        }
        if json.dumps(entry, sort_keys=True) != json.dumps(old, sort_keys=True):
            entry["updated_at"] = _now()
        index[document] = entry
    if json.dumps(index, sort_keys=True) != before:
        store.save_index(root, index)


# --------------------------------------------------------------------------- update
def update_rule(
    project: str | None,
    rule: str,
    base_state: str,
    input_path: str,
    false_positives: list[str],
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    command = "knowledge update"
    root = _root(project, command)
    if isinstance(root, Result):
        return root
    recovered = _recover(root, command)
    if isinstance(recovered, Result):
        return recovered
    result = _update_rule(root, command, rule, base_state, input_path, false_positives, trust_paths)
    return exit_journal.with_recovered(result, recovered)


def _update_rule(
    root: Path,
    command: str,
    rule: str,
    base_state: str,
    input_path: str,
    false_positives: list[str],
    trust_paths: TrustPaths | None,
) -> Result:
    denied = _authorize(command, trust_paths)
    if denied:
        return denied
    try:
        ref = RuleRef.parse(rule)
        declared = _parse_false_positives(false_positives).get(ref, set())
        changes = load_update(input_path)
    except (ItemError, IdentityError) as exc:
        return Result.refused(command, exc.code, exc.message)
    except BatchError as exc:
        return Result.refused(command, "BATCH_INVALID", str(exc))
    try:
        with exit_journal.session(root, write=True):
            store.recover(root, ref)
            stored = store.read_rule(root, ref)
            if stored is None:
                return Result.refused(command, "RULE_NOT_FOUND", f"{ref} is not stored")
            if not stored.consistent:
                return Result.refused(
                    command, "RULE_INCONSISTENT", f"{ref} does not match its record; resolve before updating"
                )
            current_state = store.state_digest(stored)
            if current_state != base_state:
                return Result.refused(
                    command,
                    "STATE_CONFLICT",
                    f"{ref} changed since {base_state}",
                    "Show the rule again and base the change on its current state_digest",
                    {"item_digest": stored.digest, "state_digest": current_state},
                )
            try:
                item = apply_update(stored.item, changes)
            except ItemError as exc:
                return Result.refused(command, exc.code, exc.message)
            if item.digest() == stored.digest:
                return Result(
                    command, True, {"rule": ref.rel, "outcome": "unchanged", "item_digest": stored.digest}
                )
            if item.size() > MAX_ITEM_BYTES:
                return Result.refused(command, "ITEM_TOO_LARGE", f"maximum is {MAX_ITEM_BYTES} bytes")
            store.ensure_safe(root, precheck.KEY_REL, expect_dir=False)
            findings = _findings(item, precheck.load_or_create_key(root))
            blocking = [f for f in findings if f.blocking]
            if [f for f in blocking if f.fingerprint not in declared]:
                return Result.refused(
                    command,
                    "NEEDS_DECISION",
                    "suspected credential or embedded instruction",
                    "Remove it, or declare false positives with --false-positive",
                    {"findings": [f.to_dict() for f in blocking]},
                )
            if _authorize(command, trust_paths):
                return Result.refused(command, "NOT_AUTHORIZED", "Maintainer qualification no longer valid")
            _write_rule(root, item, stored, "updated", blocking, [], None)
    except LockHeld as exc:
        return Result.refused(command, "LOCKED", str(exc), "Retry when the other operation finished")
    except store.StoreError as exc:
        return Result.refused(command, exc.code, exc.message, exc.next_step)
    except OSError as exc:
        return Result.refused(
            command,
            "IO_ERROR",
            str(exc.strerror or exc),
            "Re-run; a committed change is completed by the next write",
        )
    return Result(
        command,
        True,
        {
            "rule": ref.rel,
            "outcome": "updated",
            "item_digest": item.digest(),
            "state_digest": store.revision_digest(item.digest(), store.lifecycle_state(stored.record)[1]),
            "notes": [f.to_dict() for f in findings if not f.blocking],
        },
    )


