"""`preset list/show/save/update/delete/recompute/recompute-confirm` (FEATURE-001-F).

Preset maintenance needs no Maintainer authorization, grants none and never writes knowledge or
pending files. Writes take the existing knowledge lock, carry the current file digest and are
atomic. The query intent is stored and shown as text; the CLI never runs it: recompute only
validates candidate references the agent derived through the existing read operations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..policy import resolve
from ..projects import knowledge_root
from ..results import Result
from . import catalog, exit_journal, lifecycle
from .catalog import PRESET, CatalogError

PRESET_REQUEST = "ai-secure-code-toolkit/preset-request/v1"
RECOMPUTE_REQUEST = "ai-secure-code-toolkit/preset-recompute/v1"
RECOMPUTE_SCHEMA = "ai-secure-code-toolkit/preset-recompute-digest/v1"
SAVE_KEYS = frozenset({"schema", "name", "rules", "query_intent", "applicability_summary"})
UPDATE_KEYS = SAVE_KEYS | {"keep_summary"}
RECOMPUTE_KEYS = frozenset(
    {
        "schema",
        "candidates",
        "recompute_digest",
        "accept_add",
        "accept_remove",
        "applicability_summary",
        "keep_summary",
        "reconfirm",
    }
)
SUMMARY_STEP = "Provide a new applicability summary or explicitly keep the current one (keep_summary: true)"
INTENT_STEP = "Add a query intent (secure-code preset update) or edit the list directly"
RECOMPUTE_STALE_STEP = "Show the new diff to the user and ask for confirmation again"
DEFAULT_STEP = (
    "It is now the default Preset: proposed when no clues are given (secure-code preset resolve --default)"
)


def _now() -> str:
    """Confirmation time with its timezone offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _finish(command: str, data: dict[str, Any], steps: list[str], recovered: dict[str, Any] | None) -> Result:
    return exit_journal.with_recovered(Result(command, True, data, [], steps), recovered)


def _summary_decision(data: dict[str, Any]) -> tuple[bool, bool]:
    """(keep, replace) for a membership change; exactly one is required (BR-13)."""
    keep = data.get("keep_summary")
    if keep is not None and keep is not True:
        raise catalog.request_error("keep_summary must be true when given")
    summary = catalog.text_field(data, "applicability_summary")
    replace = "applicability_summary" in data
    if keep and replace:
        raise catalog.request_error("Give either a new applicability_summary or keep_summary, not both")
    return bool(keep), replace and bool(summary and summary.strip())


def _require_summary(keep: bool, replace: bool) -> None:
    if not keep and not replace:
        raise CatalogError(
            "SUMMARY_DECISION_REQUIRED",
            "A membership change needs a new applicability summary or an explicit "
            "decision to keep the current one",
            SUMMARY_STEP,
        )


def _show_data(entry: catalog.Entry, lib: resolve.Library) -> dict[str, Any]:
    rows = catalog.availability(lib, entry.rels)
    doc = entry.data
    return {
        "name": entry.name,
        "default": entry.name == "default",
        "file_digest": entry.digest,
        "snapshot_at": doc["snapshot_at"],
        "snapshot_note": catalog.SNAPSHOT_NOTE,
        "query_intent": doc["query_intent"],
        "query_intent_note": catalog.QUERY_NOTE,
        "applicability_summary": doc["applicability_summary"],
        "status": resolve.overall_status(rows),
        "counts": catalog.counts(rows),
        "rules": rows,
        "broken": catalog.broken_refs(lib, "preset", entry.name, entry.rels),
        "history_note": catalog.HISTORY_NOTE,
    }


def list_presets(project: str | None) -> Result:
    """All valid Presets in fixed name order (no ranking) plus invalid/ignored files; read-only."""
    command = "preset list"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    taken = catalog.in_session(
        command, root, lambda s: (catalog.scan(s.tree, PRESET), resolve.snapshot(s.tree))
    )
    if isinstance(taken, Result):
        return taken
    (found, lib), recovered = taken
    presets = []
    for entry in found.entries:
        rows = catalog.availability(lib, entry.rels)
        presets.append(
            {
                "name": entry.name,
                "default": entry.name == "default",
                "snapshot_at": entry.data["snapshot_at"],
                "applicability_summary": entry.data["applicability_summary"],
                "rule_count": len(rows),
                "status": resolve.overall_status(rows),
                "file_digest": entry.digest,
            }
        )
    data = {
        "presets": presets,
        "invalid": catalog.listed_invalid(found),
        "ignored": found.ignored,
        "history_note": catalog.HISTORY_NOTE,
    }
    steps = [
        "Offer matching Presets in this name order (no ranking) with their applicability summary; "
        "the user picks"
    ]
    if found.invalid:
        steps.append("Invalid Preset files are never used: restore them from version control or re-save them")
    return _finish(command, data, steps, recovered)


def show_preset(project: str | None, name: str) -> Result:
    """Membership with current availability, snapshot meaning, intent (not run); read-only."""
    command = "preset show"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    taken = catalog.in_session(
        command, root, lambda s: _show_data(catalog.read_one(s.tree, PRESET, name), resolve.snapshot(s.tree))
    )
    if isinstance(taken, Result):
        return taken
    data, recovered = taken
    steps = []
    if data["broken"]:
        steps.append(
            "Broken references are reported, never substituted; update the Preset only on the "
            "user's explicit request"
        )
    return _finish(command, data, steps, recovered)


def save_preset(project: str | None, request: str, confirmed: bool) -> Result:
    """Create one Preset from concrete, available references (explicit confirmation required)."""
    command = "preset save"
    try:
        catalog.confirmed_or_refuse(confirmed)
        data = catalog.load_request(request, PRESET_REQUEST, SAVE_KEYS)
        name = data.get("name")
        becomes_default = catalog.check_slug(name, "preset")
        rules = catalog.ref_list(data, "rules")
        intent = catalog.text_field(data, "query_intent")
        summary = catalog.text_field(data, "applicability_summary")
    except CatalogError as exc:
        return exc.result(command)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    info: dict[str, Any] = {}

    def build(_current: catalog.Entry | None, lib: resolve.Library) -> bytes:
        valid, duplicates = catalog.validated_members(lib, rules)
        info.update(rule_count=len(valid), duplicates=duplicates, snapshot_at=_now())
        return catalog.serialize(catalog.preset_doc(name, valid, intent, summary, info["snapshot_at"]))

    write = catalog.Write(PRESET, name, create=True, build=build)
    taken = catalog.in_session(command, root, lambda s: catalog.guarded_write(s, write), write=True)
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    out: dict[str, Any] = {
        "name": name,
        "path": written.path,
        "file_digest": catalog.file_digest(written.data or b""),
        "snapshot_at": info["snapshot_at"],
        "rule_count": info["rule_count"],
    }
    steps = ["Reuse it with: secure-code preset resolve " + name]
    if becomes_default:
        out["becomes_default"] = True
        steps.insert(0, DEFAULT_STEP)
    if info["duplicates"]:
        out["duplicates_ignored"] = info["duplicates"]
    return _finish(command, out, steps, recovered)


def _write_result(
    command: str, written: catalog.Written, info: dict[str, Any], recovered: dict[str, Any] | None
) -> Result:
    data = {
        "name": info["name"],
        "path": written.path,
        "previous_digest": written.previous_digest,
        "file_digest": catalog.file_digest(written.data)
        if written.data is not None
        else written.previous_digest,
        "membership_changed": info.get("membership_changed", False),
        "snapshot_at": info.get("snapshot_at"),
        "summary": info.get("summary", "unchanged"),
        "changed": written.data is not None,
    }
    if "applied" in info:
        data["applied"] = info["applied"]
    steps = [] if data["changed"] else ["Nothing was written: the list is unchanged"]
    if data["summary"] == "kept":
        steps.append("The applicability summary was kept unchanged")
    return _finish(command, data, steps, recovered)


def update_preset(
    project: str | None, name: str, request: str, digest: str | None, confirmed: bool
) -> Result:
    """Change membership (new snapshot_at, summary decision) or only intent/summary; no rename."""
    command = "preset update"
    try:
        catalog.confirmed_or_refuse(confirmed)
        data = catalog.load_request(request, PRESET_REQUEST, UPDATE_KEYS)
        catalog.check_slug(name, "preset")
        if "name" in data and data["name"] != name:
            raise catalog.request_error(
                "A Preset cannot be renamed (no rename): delete it and create a new one"
            )
        membership = "rules" in data
        rules = catalog.ref_list(data, "rules") if membership else []
        keep, replace = _summary_decision(data)
        intent = catalog.text_field(data, "query_intent")
        if membership:
            _require_summary(keep, replace)
        elif keep:
            raise catalog.request_error("keep_summary is only used with a membership change")
        elif "query_intent" not in data and "applicability_summary" not in data:
            raise catalog.request_error(
                "Nothing to update: give rules, query_intent or applicability_summary"
            )
    except CatalogError as exc:
        return exc.result(command)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    info: dict[str, Any] = {"name": name}

    def build(current: catalog.Entry | None, lib: resolve.Library) -> bytes:
        assert current is not None
        old = current.data
        valid, snapshot = current.rels, old["snapshot_at"]
        if membership:
            valid, _ = catalog.validated_members(lib, rules)
            snapshot = _now()
        summary = (
            data["applicability_summary"] if "applicability_summary" in data else old["applicability_summary"]
        )
        info.update(
            membership_changed=valid != current.rels,
            snapshot_at=snapshot,
            summary="kept" if keep else "replaced" if "applicability_summary" in data else "unchanged",
        )
        new_intent = intent if "query_intent" in data else old["query_intent"]
        return catalog.serialize(catalog.preset_doc(name, valid, new_intent, summary, snapshot))

    write = catalog.Write(PRESET, name, expected=digest, build=build)
    taken = catalog.in_session(command, root, lambda s: catalog.guarded_write(s, write), write=True)
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    return _write_result(command, written, info, recovered)


def delete_preset(project: str | None, name: str, digest: str | None, confirmed: bool) -> Result:
    """Remove only the Preset file; scope records saved from it are untouched."""
    command = "preset delete"
    try:
        catalog.confirmed_or_refuse(confirmed)
        catalog.check_slug(name, "preset")
    except CatalogError as exc:
        return exc.result(command)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    write = catalog.Write(PRESET, name, delete=True, expected=digest)
    taken = catalog.in_session(command, root, lambda s: catalog.guarded_write(s, write), write=True)
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    data = {
        "name": name,
        "path": written.path,
        "removed": True,
        "note": "scope records saved from this Preset are unchanged",
    }
    return _finish(command, data, [], recovered)


# --------------------------------------------------------------------------- recompute (A6)
def _diff(entry: catalog.Entry, lib: resolve.Library, candidates: list[Any]) -> dict[str, Any]:
    intent = entry.data["query_intent"]
    if not intent or not intent.strip():
        raise CatalogError("QUERY_INTENT_MISSING", f"Preset {entry.name!r} has no query intent", INTENT_STEP)
    valid, invalid, _ = catalog.check_references(lib, candidates)
    stored = entry.rels
    stored_rows = [
        {k: v for k, v in row.items() if k != "source"} for row in catalog.availability(lib, stored)
    ]
    valid_rows = {r["rule"]: r for r in catalog.availability(lib, valid)}
    add = [
        {
            "rule": r,
            "availability": valid_rows[r]["availability"],
            "state_digest": valid_rows[r].get("state_digest"),  # FEATURE-001-E: uncached Reference
            **({"reason": valid_rows[r]["reason"]} if "reason" in valid_rows[r] else {}),
        }
        for r in valid
        if r not in stored
    ]
    remove = [
        {k: v for k, v in row.items() if k != "state_digest"}
        for row in stored_rows
        if row["rule"] not in valid
    ]
    unchanged_count = len(set(stored) & set(valid))
    invalid_view = [{k: i[k] for k in ("requested", "reason") if k in i} for i in invalid]
    digest = lifecycle.sha(
        lifecycle.canonical(
            {
                "schema": RECOMPUTE_SCHEMA,
                "name": entry.name,
                "file_digest": entry.digest,
                "valid": [{"rule": r, "state_digest": valid_rows[r].get("state_digest")} for r in valid],
                "stored": stored_rows,
                "invalid": sorted(invalid_view, key=lambda i: (i["requested"], i["reason"])),
                "add": [a["rule"] for a in add],
                "remove": [r["rule"] for r in remove],
                "unchanged_count": unchanged_count,
            }
        )
    )
    lines = [f"+ {a['rule']}" for a in add] + [f"- {r['rule']}" for r in remove]
    return {
        "name": entry.name,
        "file_digest": entry.digest,
        "query_intent": intent,
        "query_intent_note": catalog.QUERY_NOTE,
        "stored_count": len(stored),
        "add": add,
        "remove": remove,
        "unchanged_count": unchanged_count,
        "invalid": invalid,
        "unchanged": not add and not remove,
        "diff": [*lines, f"+{len(add)} -{len(remove)} ={unchanged_count}"],
        "recompute_digest": digest,
    }


def recompute(project: str | None, name: str, request: str) -> Result:
    """Read-only diff of agent-produced candidates against the stored list (never runs the query)."""
    command = "preset recompute"
    try:
        data = catalog.load_request(request, RECOMPUTE_REQUEST, RECOMPUTE_KEYS)
        candidates = catalog.ref_list(data, "candidates")
        catalog.check_slug(name, "preset")
    except CatalogError as exc:
        return exc.result(command)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    taken = catalog.in_session(
        command,
        root,
        lambda s: _diff(catalog.read_one(s.tree, PRESET, name), resolve.snapshot(s.tree), candidates),
    )
    if isinstance(taken, Result):
        return taken
    diff, recovered = taken
    if diff["unchanged"]:
        steps = ["The list is unchanged; nothing to confirm (re-confirm only if the user explicitly asks)"]
    else:
        steps = [
            "Show the diff to the user; after explicit confirmation run secure-code preset "
            f"recompute-confirm {name} with this recompute_digest and a summary decision"
        ]
    return _finish(command, diff, steps, recovered)


def _accepted(data: dict[str, Any], key: str, offered: list[str]) -> list[str]:
    value = data.get(key, "all")
    if value == "all":
        return offered
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise catalog.request_error(f"{key} must be 'all' or a list of references from the recompute result")
    outside = sorted(set(value) - set(offered))
    if outside:
        raise catalog.request_error(f"{key} names references that are not confirmable: {', '.join(outside)}")
    by_text = {str(o): o for o in offered}  # FEATURE-001-E: keep the offered member (and its source)
    return sorted({by_text[v] for v in value})


def recompute_confirm(project: str | None, name: str, request: str, confirmed: bool) -> Result:
    """Apply only the confirmed additions/removals if the recompute digest still matches."""
    command = "preset recompute-confirm"
    try:
        catalog.confirmed_or_refuse(confirmed)
        data = catalog.load_request(request, RECOMPUTE_REQUEST, RECOMPUTE_KEYS)
        candidates = catalog.ref_list(data, "candidates")
        catalog.check_slug(name, "preset")
        expected = data.get("recompute_digest")
        if not isinstance(expected, str) or not expected.startswith("sha256:"):
            raise catalog.request_error("recompute_digest must be the digest shown by preset recompute")
        reconfirm = data.get("reconfirm", False)
        if not isinstance(reconfirm, bool):
            raise catalog.request_error("reconfirm must be true or false")
        keep, replace = _summary_decision(data)
    except CatalogError as exc:
        return exc.result(command)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    info: dict[str, Any] = {"name": name}

    def build(current: catalog.Entry | None, lib: resolve.Library) -> bytes | None:
        assert current is not None
        diff = _diff(current, lib, candidates)
        if diff["recompute_digest"] != expected:
            raise CatalogError(
                "STALE_RECOMPUTE",
                "The Preset or a rule changed since the recompute was shown",
                RECOMPUTE_STALE_STEP,
                diff,
            )
        added = _accepted(data, "accept_add", [a["rule"] for a in diff["add"]])
        removed = _accepted(data, "accept_remove", [r["rule"] for r in diff["remove"]])
        new = sorted((set(current.rels) - set(removed)) | set(added))
        if not new:
            raise CatalogError(
                "MEMBERSHIP_EMPTY",
                "The confirmed list would be empty",
                "Keep at least one rule, or delete the Preset",
            )
        old = current.data
        info.update(
            applied={"added": added, "removed": removed},
            snapshot_at=old["snapshot_at"],
            membership_changed=new != current.rels,
        )
        summary = old["applicability_summary"]
        if new == current.rels:
            if not reconfirm:
                return None
        else:
            _require_summary(keep, replace)
            if replace:
                summary = data["applicability_summary"]
            info["summary"] = "kept" if keep else "replaced"
        info["snapshot_at"] = _now()
        return catalog.serialize(
            catalog.preset_doc(name, new, old["query_intent"], summary, info["snapshot_at"])
        )

    write = catalog.Write(PRESET, name, check_digest=False, build=build)
    taken = catalog.in_session(command, root, lambda s: catalog.guarded_write(s, write), write=True)
    if isinstance(taken, Result):
        return taken
    written, recovered = taken
    return _write_result(command, written, info, recovered)
