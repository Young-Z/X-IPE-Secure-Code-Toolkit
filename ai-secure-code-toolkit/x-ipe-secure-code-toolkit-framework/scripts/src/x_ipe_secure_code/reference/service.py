"""`knowledge reference …` commands (FEATURE-001-E) → `Result`.

Reads (list, show) are open to everyone and never write. Registry writes are in `registry_ops`; fetching
(`fetch`, `explore`) is in `fetch` and happens only inside an open Guard verification.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..knowledge import durable, exit_journal
from ..knowledge.identity import IdentityError, RuleRef
from ..projects import knowledge_root
from ..results import Result
from . import (
    CACHE_CAPACITY,
    MAX_BYTES,
    MAX_FETCHES,
    MAX_TEXT,
    MIN_CACHE_CAPACITY,
    TIMEOUT,
    cache,
    cli_parser,
    clock,
    registry,
    registry_ops,
)
from .registry import Bad

NOT_OBTAINED = "content not obtained"
DEFAULTS = {
    "max_bytes": MAX_BYTES,
    "max_text": MAX_TEXT,
    "timeout": TIMEOUT,
    "max_fetches": MAX_FETCHES,
    "cache_capacity": CACHE_CAPACITY,
}
FETCH_STEP = (
    "Open a Guard verification on an available scope, ask the User to grant reference_fetch "
    "(secure-code guard allow-egress --purpose reference_fetch --recipient ORIGIN --data public_query "
    "--scope URL), then run secure-code knowledge reference fetch --run ID --rule REF [--refresh]"
)


class LimitInvalid(Exception):
    pass


def check_limits(**given: Any) -> dict[str, Any]:
    """Defaults, overridable downward only (DEC-10); anything else is LIMIT_INVALID."""
    out = dict(DEFAULTS)
    for name, value in given.items():
        if name not in DEFAULTS or value is None:
            if name not in DEFAULTS:
                raise LimitInvalid(f"unknown limit {name}")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise LimitInvalid(f"{name} must be a number")
        if name != "timeout" and not isinstance(value, int):
            raise LimitInvalid(f"{name} must be an integer")
        low = MIN_CACHE_CAPACITY if name == "cache_capacity" else (0 if name == "timeout" else 1)
        if not (value > low if name == "timeout" else value >= low) or value > DEFAULTS[name]:
            raise LimitInvalid(
                f"{name} must be within ({low}, {DEFAULTS[name]}]"
                if name == "timeout"
                else f"{name} must be within [{low}, {DEFAULTS[name]}]"
            )
        out[name] = value
    return out


def limit_refusal(command: str, exc: LimitInvalid) -> Result:
    return Result.refused(command, "LIMIT_INVALID", str(exc), "Use a value at or below the default")


def label(state: cache.CacheState | None) -> str:
    return "cached" if state is not None and state.state == "valid" else NOT_OBTAINED


def cache_summary(state: cache.CacheState | None) -> dict[str, Any]:
    if state is None:
        return {"state": "not_cached"}
    out: dict[str, Any] = {"state": state.state if state.state != "invalid" else "cache_invalid"}
    if state.entry is not None:
        out.update(
            {
                k: state.entry[k]
                for k in ("fetched_at", "expires_at", "response_digest", "policy_state_digest", "generation")
            }
        )
    if state.detail:
        out["detail"] = state.detail
    return out


def source_summary(record: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "namespace",
        "version",
        "display_name",
        "scheme",
        "domains",
        "port",
        "path_prefix",
        "revision",
        "registered_at",
        "updated_at",
    )
    return {k: record[k] for k in keys}


def _read(command: str, project: str | None, fn: Any) -> Result:
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    return registry_ops.run_locked(command, root, lambda s: fn(s.tree), write=False)


def list_references(project: str | None) -> Result:
    """Sources and rules with their cache state; read-only, open to everyone."""
    command = "knowledge reference list"

    def read(tree: durable.Tree) -> Result:
        view = cache.attach(tree, registry.view_at(tree), clock.utc_now())
        sources = [
            {"source": k, "state": "unusable", "detail": v.detail}
            if isinstance(v, Bad)
            else source_summary(v)
            for k, v in sorted(view.sources.items())
        ]
        rules = []
        for rel, record in sorted(view.rules.items()):
            if isinstance(record, Bad):
                rules.append(
                    {"rule": rel, "state": "unusable", "detail": record.detail, "cache_state": NOT_OBTAINED}
                )
                continue
            state = view.states.get(rel)
            rules.append(
                {**registry.rule_summary(record), "cache_state": label(state), "cache": cache_summary(state)}
            )
        out = {
            "sources": sources,
            "rules": rules,
            "removed": sorted(view.removed.values(), key=lambda e: e["rule"]),
        }
        if view.notice:
            out["notices"] = [view.notice]
        return Result(command, True, out, [], [])

    return _read(command, project, read)


def show(project: str | None, *, rule: str | None = None, source: str | None = None) -> Result:
    """One registration (identity, title, entry URL, registered domains), digests and cache state."""
    command = "knowledge reference show"

    def read(tree: durable.Tree) -> Result:
        view = registry.view_at(tree)
        if source is not None:
            ns_ver = "/".join(registry_ops._source_id(source))
            record = registry_ops._usable_source(view, ns_ver)
            out = {
                "source": source_summary(record),
                "registration_digest": registry.source_digest(record),
                "rules": sorted(r for r in view.rules if r.startswith(ns_ver + "/")),
            }
            return Result(command, True, out, [], [])
        try:
            ref = RuleRef.parse(rule)
        except IdentityError as exc:
            raise registry_ops.RefError(exc.code, exc.message, registry_ops.REQUEST_STEP) from None
        usable = view.usable(ref)
        if isinstance(usable, Bad):
            data = {"removed": view.removed[ref.rel]} if view.is_removed(ref) else None
            code = "RULE_NOT_REGISTERED" if ref.rel not in view.rules else "REGISTRY_INVALID"
            raise registry_ops.RefError(
                code,
                f"{ref.rel}: {usable.detail}",
                "List the registered rules (secure-code knowledge reference list)",
                data,
            )
        record, src = usable
        state = cache.read_state(tree, cache.rule_key(record, src), clock.utc_now())
        out = {
            "rule": ref.rel,
            "registration": {
                **registry.rule_summary(record),
                **{k: record[k] for k in ("revision", "registered_at", "updated_at")},
            },
            "source": source_summary(src),
            "registration_digest": registry.registration_digest(record, src),
            "source_digest": registry.source_digest(src),
            "cache": cache_summary(state),
            "label": label(state),
        }
        return Result(command, True, out, [], [] if state.state == "valid" else [FETCH_STEP])

    return _read(command, project, read)


def cache_clean(project: str | None, **limits: Any) -> Result:
    """Remove expired, invalid and orphaned entries and stale temporaries; open to everyone."""
    command = "knowledge reference cache-clean"
    try:
        capacity = check_limits(**limits)["cache_capacity"]
    except LimitInvalid as exc:
        return limit_refusal(command, exc)
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        out = cache.clean(Path(root), capacity)
    except (LockHeld, durable.StoreError, exit_journal.JournalInvalid) as exc:
        return exit_journal.refusal(command, exc)
    except OSError as exc:
        return Result.refused(command, "IO_ERROR", f"{exc.strerror or exc}", registry_ops.IO_STEP)
    return Result(command, True, out, [], [])


def fetch(
    project: str | None, run_id: str | None, rule: str, *, refresh: bool = False, **limits: Any
) -> Result:
    from . import fetch as fetching

    return fetching.fetch_command(project, run_id, rule, refresh=refresh, **limits)


def explore(
    project: str | None, run_id: str | None, source: str, url: str, *, refresh: bool = False, **limits: Any
) -> Result:
    from . import fetch as fetching

    return fetching.explore_command(project, run_id, source, url, refresh=refresh, **limits)


def run(args: argparse.Namespace) -> Result:
    """Dispatch of `secure-code knowledge reference <command>`."""
    cmd, project = args.reference_command, args.project
    if cmd == "register":
        return registry_ops.register_batch(project, args.batch)
    if cmd == "update":
        return registry_ops.update(
            project,
            rule=args.rule,
            source=args.source,
            registration_digest=args.registration_digest,
            changes=cli_parser.changes(args),
        )
    if cmd == "remove-preview":
        return registry_ops.remove_preview(project, args.rule, args.reason)
    if cmd == "remove-confirm":
        return registry_ops.remove_confirm(
            project, args.rule, args.reason, args.impact_digest, args.registration_digest
        )
    if cmd == "remove-source":
        return registry_ops.remove_source(project, args.source, args.registration_digest)
    if cmd == "list":
        return list_references(project)
    if cmd == "show":
        return show(project, rule=args.rule, source=args.source)
    if cmd == "fetch":
        return fetch(project, args.run, args.rule, refresh=args.refresh, **cli_parser.limits(args))
    if cmd == "explore":
        return explore(
            project, args.run, args.source, args.url, refresh=args.refresh, **cli_parser.limits(args)
        )
    return cache_clean(project, **cli_parser.limits(args))
