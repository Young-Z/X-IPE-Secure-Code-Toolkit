"""`secure-code copilot` commands (FEATURE-003-A): open, artifacts, suggest, review, report, show, close.

The agent suggests and reviews; these commands record, bind digests, compute adoption states and
publish immutable numbered report rounds. Copilot writes only its private collaboration folder,
its lock file and its report files - never business artifacts.

Publication Protocol: a round's structured result and Markdown are both created exclusively; the
round is published only when it is appended to `state.rounds` (the commit point). Files of an
uncommitted round are residue, reconciled under the lock before any change.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..atomic import LockHeld, ProcessLock, dumps_json
from ..guard.model import load_request
from ..guard.runs import fsync_dir
from ..knowledge import store
from ..policy import resolve
from ..policy.service import adoption_now, load_adopted
from ..projects import knowledge_root
from ..results import Result
from . import engine, manifest, records
from . import report as md_report
from .model import (
    COLLAB_ID,
    LOCK_REL,
    NEW_COLLAB,
    SCHEMA_ARTIFACTS,
    SCHEMA_OPEN,
    SCHEMA_RESULT,
    SCHEMA_REVIEW,
    SCHEMA_STATE,
    SCHEMA_SUGGEST,
    GuardError,
    allocate,
    check_id,
    collab_rel,
    read_state,
    report_path,
    report_rel,
    report_rounds,
    utc_now,
    write_state,
)

__all__ = [
    "COLLAB_ID",
    "open_collaboration",
    "update_artifacts",
    "suggest",
    "review",
    "report",
    "show",
    "close",
]
LOCK_TIMEOUT = 10.0
RETRY = "Retry when the other Copilot operation finished"
POLICY_STEP_CODES = ("EXIT_JOURNAL_INVALID", "PATH_UNSAFE", "LOCKED", "IO_ERROR")


def _policy_step(refused: Result, default: str) -> str:
    """Keep the Policy refusal's own next step for knowledge-integrity and retry codes."""
    if refused.problems[0].code in POLICY_STEP_CODES and refused.next_steps:
        return refused.next_steps[0]
    return default
REQUEST_STEP = manifest.REQUEST_STEP
MAINTAIN_STEP = (
    "Knowledge maintenance is needed: an authorized Maintainer imports or fixes Local rules with the "
    "Framework skill, then a scope is confirmed"
)
PARTIAL_STEP = "Re-propose and confirm a new scope (secure-code policy resolve, scope save), then open again"
HANDOVER = (
    "Hand the attention list and gaps to the upstream caller; Copilot does not pause the work and the "
    "caller decides whether to continue"
)


@contextmanager
def _locked(root: Path):
    store.ensure_safe(root, LOCK_REL, expect_dir=False)
    with ProcessLock(root / LOCK_REL, timeout=LOCK_TIMEOUT, create=True):
        yield


def _call(command: str, project: str | None, body: Callable[[Path], Result]) -> Result:
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        return body(root)
    except GuardError as exc:
        return Result.refused(command, exc.code, exc.message, exc.next_step, exc.data)
    except LockHeld as exc:
        return Result.refused(command, "LOCKED", str(exc), RETRY)
    except store.StoreError as exc:
        return Result.refused(
            command, exc.code, exc.message, "Replace the symbolic link with a real folder or file"
        )
    except (TypeError, ValueError, KeyError) as exc:
        return Result.refused(
            command, "REQUEST_INVALID", f"Request content has an unexpected shape: {exc}", REQUEST_STEP
        )
    except OSError as exc:
        return Result.refused(
            command,
            "IO_ERROR",
            f"Copilot files could not be read or written: {exc}",
            "Check the permissions of the project's .x-ipe/private and x-ipe-docs folders",
        )


def _policy_now(root: Path, state: dict[str, Any], command: str) -> dict[str, str]:
    now = adoption_now(root, state["scope"]["scope_id"], state["scope"]["adopted"], command)
    if isinstance(now, Result):
        raise GuardError(now.problems[0].code, now.problems[0].message, _policy_step(now, RETRY))
    return now


def _require(root: Path, cid: str) -> dict[str, Any]:
    state = read_state(root, cid)
    if state is None:
        raise GuardError(
            "COLLAB_NOT_FOUND",
            f"No collaboration {cid} (unknown, or its private data was removed)",
            NEW_COLLAB,
        )
    return state


def _closed(state: dict[str, Any]) -> GuardError:
    cid = state["collaboration_id"]
    latest = state["rounds"][-1]["n"] if state["rounds"] else None
    return GuardError(
        "COLLAB_CLOSED",
        f"Collaboration {cid} is closed; nothing more can be recorded",
        NEW_COLLAB,
        {
            "collaboration_id": cid,
            "latest_round": latest,
            "report": report_rel(cid, latest, "md") if latest else None,
        },
    )


def _persist_invalidated(root: Path, state: dict[str, Any], command: str) -> dict[str, str]:
    """Record newly changed or missing adopted rules (monotonic: never removed)."""
    now = _policy_now(root, state, command)
    found = engine.invalidated(state, now)
    new = {rule: info for rule, info in found.items() if rule not in state["invalidated_rules"]}
    if new:
        stamp = utc_now()
        for info in new.values():
            info["detected_at"] = stamp
        state["invalidated_rules"].update(new)
        write_state(root, state)
    return now


# --------------------------------------------------------------------------- publication protocol
def _create_new(path: Path, data: bytes) -> None:
    """Create `path` exclusively (temp file in the checked folder + hard link); never replaces."""
    tmp = path.parent / f".{path.name}.{secrets.token_hex(6)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _commit_round(root: Path, state: dict[str, Any]) -> None:
    write_state(root, state)


def _conflict(cid: str, n: int, why: str) -> GuardError:
    return GuardError(
        "REPORT_CONFLICT",
        f"Report files of round {n} are not a valid uncommitted round: {why}",
        f"Move {report_rel(cid, n, 'json')} and {report_rel(cid, n, 'md')} out of the reports folder "
        "manually (nothing is overwritten), then retry",
    )


def _publish(root: Path, state: dict[str, Any], content: dict[str, Any], sig: str) -> int:
    cid = state["collaboration_id"]
    n = len(state["rounds"]) + 1
    result = {
        **content,
        "round": n,
        "supersedes": f"{cid}-r{n - 1}" if n > 1 else None,
        "published_at": utc_now(),
        "private_data_present_as_of_publication": True,
        "state_signature": sig,
    }
    js, md = report_path(root, cid, n, "json"), report_path(root, cid, n, "md")
    if os.path.lexists(js) or os.path.lexists(md):
        raise _conflict(cid, n, "a file of this round already exists")
    js.parent.mkdir(parents=True, exist_ok=True)
    try:
        _create_new(js, dumps_json(result))
        _create_new(md, md_report.render(result).encode("utf-8"))
    except FileExistsError:
        raise _conflict(cid, n, "a file of this round appeared meanwhile") from None
    fsync_dir(js.parent)
    state["rounds"].append({"n": n, "signature": sig, "published_at": result["published_at"]})
    _commit_round(root, state)
    return n


def _reconcile(root: Path, state: dict[str, Any]) -> None:
    """Commit a complete, valid uncommitted round (creating its Markdown if missing) or refuse."""
    cid = state["collaboration_id"]
    k = len(state["rounds"]) + 1
    js, md = report_path(root, cid, k, "json"), report_path(root, cid, k, "md")
    has_json, has_md = os.path.lexists(js), os.path.lexists(md)
    if not has_json and not has_md:
        return
    if not has_json:
        raise _conflict(cid, k, "Markdown without a structured result")
    raw = js.read_bytes()
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise _conflict(cid, k, "the structured result is not readable JSON") from None
    expected = {
        "schema": SCHEMA_RESULT,
        "collaboration_id": cid,
        "round": k,
        "supersedes": f"{cid}-r{k - 1}" if k > 1 else None,
    }
    if (
        not isinstance(result, dict)
        or any(result.get(key) != value for key, value in expected.items())
        or raw != dumps_json(result)
        or result.get("state_signature") != engine.signature(engine.content_of(result))
    ):
        raise _conflict(cid, k, "the structured result does not belong to this round or was changed")
    text = md_report.render(result)
    if not has_md:
        _create_new(md, text.encode("utf-8"))
        fsync_dir(md.parent)
    elif md.read_bytes() != text.encode("utf-8"):
        raise _conflict(cid, k, "the Markdown does not match the structured result")
    state["rounds"].append(
        {"n": k, "signature": result["state_signature"], "published_at": result["published_at"]}
    )
    _commit_round(root, state)


def _repair_markdown(root: Path, cid: str, n: int, signature: str) -> None:
    """Re-create a removed Markdown of the latest committed round from its unchanged structured result."""
    js, md = report_path(root, cid, n, "json"), report_path(root, cid, n, "md")
    if os.path.lexists(md) or not js.is_file():
        return
    try:
        result = json.loads(js.read_bytes().decode("utf-8"))
    except (UnicodeError, ValueError):
        return
    if (
        isinstance(result, dict)
        and result.get("collaboration_id") == cid
        and result.get("round") == n
        and result.get("state_signature") == signature == engine.signature(engine.content_of(result))
    ):
        _create_new(md, md_report.render(result).encode("utf-8"))


def _round_step(root: Path, state: dict[str, Any], command: str) -> dict[str, Any]:
    """Publish a new round when the state signature changed; else return the latest round."""
    now = _persist_invalidated(root, state, command)
    content = engine.evaluate(state, manifest.current(root, state["manifest"]), now)
    sig = engine.signature(content)
    if state["rounds"] and state["rounds"][-1]["signature"] == sig:
        n, published = state["rounds"][-1]["n"], False
        _repair_markdown(root, state["collaboration_id"], n, sig)
    else:
        n, published = _publish(root, state, content, sig), True
    cid = state["collaboration_id"]
    return {
        "collaboration_id": cid,
        "round": n,
        "published": published,
        "report": report_rel(cid, n, "md"),
        "result": report_rel(cid, n, "json"),
        "report_exists": report_path(root, cid, n, "md").is_file(),
        "result_exists": report_path(root, cid, n, "json").is_file(),
        "supersedes": f"{cid}-r{n - 1}" if n > 1 else None,
        "counts": content["counts"],
        "attention": [{k: a[k] for k in ("id", "severity", "state", "reason")} for a in content["attention"]],
        "gaps": [{k: g[k] for k in ("id", "severity", "state", "reason")} for g in content["gaps"]],
        "re_review": content["re_review"],
        "snapshot_before_review": content["snapshot_before_review"],
        "policy_next_step": content["policy_next_step"],
    }


def _round_steps(out: dict[str, Any]) -> list[str]:
    steps = [HANDOVER]
    if out["policy_next_step"]:
        steps.append(out["policy_next_step"])
    if out["re_review"]:
        steps.append(
            "After relevant changes, re-review only the stale and new suggestions: "
            + ", ".join(out["re_review"])
        )
    return steps


# --------------------------------------------------------------------------- commands
def open_collaboration(project: str | None, request: str) -> Result:
    """Open a collaboration on explicit artifacts against a complete adopted scope.

    Args:
        project: Explicit project root.
        request: Open request file (`copilot-open/v1`).

    Returns:
        Result with the collaboration id, artifacts, per-file manifest and adopted rules; refusals
        (scope, artifacts) create nothing.
    """
    command = "copilot open"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_OPEN, "REQUEST_INVALID", records.OPEN_STEP)
        parsed = records.validate_open(root, doc)
        with _locked(root):
            loaded = load_adopted(root, parsed["scope_id"], command)
            if isinstance(loaded, Result):
                problem = loaded.problems[0]
                retry = problem.code in ("LOCKED", "IO_ERROR")
                step = _policy_step(loaded, RETRY if retry else records.SELECT_STEP)
                raise GuardError(problem.code, problem.message, step)
            groups = {
                s: [e["rule"] for e in loaded["entries"] if e["adoption"] == s]
                for s in ("adopted", "needs_reconfirmation", "missing")
            }
            if loaded["status"] == resolve.MAINTENANCE_NEEDED:
                raise GuardError(
                    "MAINTENANCE_NEEDED",
                    "No Policy of this adopted scope is usable; nothing is invented",
                    MAINTAIN_STEP,
                    groups,
                )
            if loaded["status"] != resolve.COMPLETE:
                raise GuardError(
                    "SCOPE_PARTIAL",
                    "Some adopted Policies changed or are missing; "
                    "Copilot uses only a complete adopted scope",
                    PARTIAL_STEP,
                    groups,
                )
            opened_at = utc_now()
            found, not_bindable = manifest.expand(root, parsed["entries"], opened_at)
            state = {
                "schema": SCHEMA_STATE,
                "collaboration_id": None,
                "status": "open",
                "opened_at": opened_at,
                "closed_at": None,
                "revision": 0,
                "stage": parsed["stage"],
                "task": parsed["task"],
                "masked": parsed["masked"],
                "scope": {
                    "scope_id": loaded["scope_id"],
                    "mode": loaded["mode"],
                    "adopted": [
                        {"rule": e["rule"], "state_digest": e["confirmed_state_digest"]}
                        for e in loaded["entries"]
                        if e["adoption"] == "adopted"
                    ],
                },
                "artifacts": [{**e, "recorded_at": opened_at} for e in parsed["entries"]],
                "manifest": found,
                "context": parsed["context"],
                "suggestions": [],
                "reviews": [],
                "invalidated_rules": {},
                "rounds": [],
            }
            dumps_json(state)  # refuse unserializable input before anything is written
            cid = allocate(root, opened_at)
            state["collaboration_id"] = cid
            try:
                write_state(root, state)
            except BaseException:
                shutil.rmtree(root / collab_rel(cid), ignore_errors=True)
                raise
        data = {
            "collaboration_id": cid,
            "opened_at": opened_at,
            "stage": state["stage"],
            "scope_id": state["scope"]["scope_id"],
            "adopted_rules": [a["rule"] for a in state["scope"]["adopted"]],
            "artifacts": [
                {k: a[k] for k in ("path", "kind", "change", "old_path")} for a in state["artifacts"]
            ],
            "manifest": {p: m["digest"] for p, m in sorted(found.items())},
            "not_bindable": not_bindable,
            "context": [c["path"] for c in state["context"]],
        }
        return Result(
            command,
            True,
            data,
            [],
            [
                "Give concrete suggestions tied to an artifact location and an adopted Policy, then record "
                f"them: secure-code copilot suggest --id {cid} "
                "--request .x-ipe/private/secure-code/tmp/suggest.json"
            ],
        )

    return _call(command, project, body)


def _mutate(
    root: Path, collab: str, command: str, change: Callable[[dict[str, Any]], dict[str, Any]]
) -> dict:
    cid = check_id(collab)
    with _locked(root):
        state = _require(root, cid)
        _reconcile(root, state)
        if state["status"] != "open":
            raise _closed(state)
        _persist_invalidated(root, state, command)
        data = change(state)
        write_state(root, state)
    return data


def update_artifacts(project: str | None, collab: str, request: str) -> Result:
    """Record added, modified, deleted or renamed artifact files (and folder trees) in the manifest."""
    command = "copilot artifacts"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_ARTIFACTS, "REQUEST_INVALID", REQUEST_STEP)

        def change(state: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(doc, dict) or set(doc) - {"schema", "artifacts"}:
                raise GuardError("REQUEST_INVALID", "request has unknown fields", REQUEST_STEP)
            entries = manifest.parse_entries(root, doc.get("artifacts"), "artifacts", state=state)
            context = {c["path"] for c in state["context"]}
            for e in entries:
                if e["path"] in context:
                    raise GuardError(
                        "ROLE_CONFLICT",
                        f"{e['path']} is read-only context of this collaboration",
                        "Give each path one role: artifact or read-only context",
                    )
            now = utc_now()
            found, not_bindable = manifest.expand(root, entries, now)
            manifest.check_size(set(state["manifest"]) | set(found))
            state["manifest"].update(found)
            state["artifacts"] += [{**e, "recorded_at": now} for e in entries]
            return {
                "collaboration_id": state["collaboration_id"],
                "recorded": [e["path"] for e in entries],
                "manifest": {p: m["digest"] for p, m in sorted(found.items())},
                "not_bindable": not_bindable,
            }

        data = _mutate(root, collab, command, change)
        return Result(
            command,
            True,
            data,
            [],
            [
                "Added and renamed files are now bindable; suggestion states change only through reviewed "
                "digests (check stale suggestions with secure-code copilot show --id "
                f"{data['collaboration_id']})"
            ],
        )

    return _call(command, project, body)


def suggest(project: str | None, collab: str, request: str) -> Result:
    """Record one batch of concrete suggestions (all or nothing; free text masked)."""
    command = "copilot suggest"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_SUGGEST, "SUGGESTION_INVALID", records.SUGGEST_STEP)

        def change(state: dict[str, Any]) -> dict[str, Any]:
            batch = records.validate_suggest(state, doc)
            now = utc_now()
            for s in batch:
                s["recorded_at"] = now
            state["suggestions"] += batch
            return {
                "collaboration_id": state["collaboration_id"],
                "recorded": [s["id"] for s in batch],
                "batch": batch[0]["batch"],
                "masked": {s["id"]: s["masked"] for s in batch if s["masked"]},
            }

        data = _mutate(root, collab, command, change)
        return Result(
            command,
            True,
            data,
            [],
            [
                "Leave all edits to the current executor; once the artifact is formed, ask one independent "
                "read-only Reviewer and record its result with secure-code copilot review"
            ],
        )

    return _call(command, project, body)


def review(project: str | None, collab: str, request: str) -> Result:
    """Record one Reviewer record (shared envelope, `adoption` subjects) bound to reviewed digests."""
    command = "copilot review"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_REVIEW, "REVIEW_INVALID", records.REVIEW_STEP)

        def change(state: dict[str, Any]) -> dict[str, Any]:
            record = records.validate_review(root, state, doc)
            record["seq"] = len(state["reviews"]) + 1
            record["recorded_at"] = utc_now()
            state["reviews"].append(record)
            return {
                "collaboration_id": state["collaboration_id"],
                "seq": record["seq"],
                "covers": [s["id"] for s in record["subjects"]],
                "completeness": record["completeness"],
                "wrong_version": record["wrong_version"],
                "valid": not record["completeness"] and not record["wrong_version"],
                "masked": record["masked"],
            }

        data = _mutate(root, collab, command, change)
        steps = [f"Produce the round: secure-code copilot report --id {data['collaboration_id']}"]
        if data["wrong_version"]:
            steps.insert(
                0,
                "The reviewed digests of " + ", ".join(data["wrong_version"]) + " differ from the "
                "files now (wrong version): this record does not count for suggestions bound to them",
            )
        if data["completeness"]:
            steps.insert(0, "This record is incomplete and will not count as a valid review")
        return Result(command, True, data, [], steps)

    return _call(command, project, body)


def report(project: str | None, collab: str) -> Result:
    """Publish round n+1 when the collaboration state changed since the latest round, else return it."""
    command = "copilot report"

    def body(root: Path) -> Result:
        cid = check_id(collab)
        with _locked(root):
            state = _require(root, cid)
            _reconcile(root, state)
            out = _round_step(root, state, command)
        return Result(command, True, out, [], _round_steps(out))

    return _call(command, project, body)


def close(project: str | None, collab: str) -> Result:
    """Publish a final round if the state changed, then close; later recordings are refused."""
    command = "copilot close"

    def body(root: Path) -> Result:
        cid = check_id(collab)
        with _locked(root):
            state = _require(root, cid)
            _reconcile(root, state)
            if state["status"] != "open":
                raise _closed(state)
            out = _round_step(root, state, command)
            state["status"], state["closed_at"] = "closed", utc_now()
            write_state(root, state)
        out.update(status="closed", closed_at=state["closed_at"])
        return Result(
            command,
            True,
            out,
            [],
            [
                *_round_steps(out),
                "Reports and the private collaboration data stay until the user removes them",
            ],
        )

    return _call(command, project, body)


def _report_list(root: Path, cid: str, rounds: list[int]) -> list[dict[str, Any]]:
    out = []
    for n in rounds:
        js, md = report_path(root, cid, n, "json"), report_path(root, cid, n, "md")
        out.append(
            {
                "round": n,
                "json": report_rel(cid, n, "json"),
                "json_exists": js.is_file(),
                "md": report_rel(cid, n, "md"),
                "md_exists": md.is_file(),
            }
        )
    return out


def show(project: str | None, collab: str) -> Result:
    """Current collaboration state without writing anything (uncommitted report files are ignored)."""
    command = "copilot show"

    def body(root: Path) -> Result:
        cid = check_id(collab)
        state = read_state(root, cid)
        if state is None:
            return _show_without_state(root, cid, command)
        now = _policy_now(root, state, command)
        current = manifest.current(root, state["manifest"])
        content = engine.evaluate(state, current, now)
        committed = [r["n"] for r in state["rounds"]]
        latest = committed[-1] if committed else None
        data = {
            "collaboration_id": cid,
            "status": state["status"],
            "stage": state["stage"],
            "task": state["task"],
            "opened_at": state["opened_at"],
            "closed_at": state["closed_at"],
            "private_data_present": True,
            "latest_round": latest,
            "latest_report": report_rel(cid, latest, "md") if latest else None,
            "report_current": bool(latest) and state["rounds"][-1]["signature"] == engine.signature(content),
            "reports": _report_list(root, cid, committed),
            "manifest": [
                {k: m[k] for k in ("path", "change", "recorded_digest", "current_digest")}
                for m in content["manifest"]
            ],
            "suggestions": [
                {k: s[k] for k in ("id", "state", "severity", "rule", "files", "changed")}
                for s in content["suggestions"]
            ],
            "re_review": content["re_review"],
            "attention": [a["id"] for a in content["attention"]],
            "gaps": [g["id"] for g in content["gaps"]],
        }
        steps = []
        if content["re_review"]:
            steps.append(
                "Send only these stale and new suggestions to one read-only Reviewer: "
                + ", ".join(content["re_review"])
            )
        if not data["report_current"]:
            steps.append(f"Publish the current state: secure-code copilot report --id {cid}")
        return Result(command, True, data, [], steps)

    return _call(command, project, body)


def _show_without_state(root: Path, cid: str, command: str) -> Result:
    rounds = report_rounds(root, cid)
    if not rounds:
        raise GuardError("COLLAB_NOT_FOUND", f"No collaboration {cid}", NEW_COLLAB)
    latest = rounds[-1]
    data = {
        "collaboration_id": cid,
        "private_data_present": False,
        "latest_round": latest,
        "latest_report": report_rel(cid, latest, "md"),
        "reports": _report_list(root, cid, rounds),
        "note": "The private collaboration data was removed; only the reports remain (history only)",
    }
    return Result(command, True, data, [], [NEW_COLLAB + " to continue collaborating"])
