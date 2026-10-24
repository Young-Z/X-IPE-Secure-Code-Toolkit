"""Maintainer writes of Reference knowledge (FEATURE-001-E, FR-001E-2): register (batch), update,
two-step rule removal and source removal.

Every write checks the Maintainer qualification before the knowledge lock and again under it, completes
an interrupted exit first (`exit_journal.session`) and then the light registry recovery (a tombstoned rule
whose files still exist is removed; a missing changelog entry is appended). Files are written atomically
through the command's no-follow `durable.Tree`; a link anywhere on the registry path is `PATH_UNSAFE`.
Registration changes invalidate the affected cache entries before the record changes (safe direction).
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..auth.service import require_maintainer
from ..auth.trust_store import TrustPaths
from ..guard.mask import mask_text
from ..knowledge import changelog, durable, exit_journal, lifecycle
from ..knowledge.catalog import CatalogError, load_request
from ..knowledge.identity import IdentityError, RuleRef, make_ref
from ..projects import knowledge_root
from ..results import Problem, Result
from . import REGISTRY_REL, cache, clock, registry, urls
from .registry import CHANGELOG, REMOVED_FILE, REMOVED_SCHEMA, RULE_FILE, SOURCE_FILE, Bad

BATCH_SCHEMA = "ai-secure-code-toolkit/reference-batch/v1"
REMOVAL_SCHEMA = "ai-secure-code-toolkit/reference-removal-impact/v1"
SOURCE_ITEM = frozenset(
    {"type", "namespace", "version", "domains", "scheme", "port", "path_prefix", "display_name"}
)
RULE_ITEM = frozenset({"type", "rule", "title", "entry_url", "applicability"})
SOURCE_CHANGES = frozenset({"domains", "scheme", "port", "path_prefix", "display_name"})
RULE_CHANGES = frozenset({"title", "entry_url", "applicability"})
MAX_ITEMS, MAX_DOMAINS, MAX_DISPLAY = 500, 20, 200
ASK_STEP = "Ask a Maintainer to change Reference registrations (secure-code knowledge reference ...)"
REQUEST_STEP = "Fix the request (see references/reference-knowledge.md)"
SHOW_STEP = (
    "Show the registration again (secure-code knowledge reference show) and retry with the current digest"
)
IO_STEP = "Check folder permissions and retry"


class RefError(Exception):
    """A refused Reference operation (nothing written by the refused step)."""

    def __init__(
        self,
        code: str,
        message: str,
        next_step: str | None = None,
        data: dict[str, Any] | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code, self.message, self.next_step, self.data, self.reason = (
            code,
            message,
            next_step,
            data,
            reason,
        )

    def result(self, command: str) -> Result:
        data = dict(self.data or {})
        if self.reason:
            data.setdefault("reason", self.reason)
        return Result.refused(command, self.code, self.message, self.next_step, data)


def invalid(reason: str, message: str) -> RefError:
    return RefError("REGISTRATION_INVALID", f"{reason}: {message}", REQUEST_STEP, reason=reason)


def request_error(message: str) -> RefError:
    return RefError("REQUEST_INVALID", message, REQUEST_STEP)


# --------------------------------------------------------------------------- sessions and authorization
def _authorizer(op: str, trust_paths: TrustPaths | None) -> Callable[[str], Result | None]:
    def check(command: str) -> Result | None:
        decision = require_maintainer(f"reference.{op}", paths=trust_paths)
        if decision.allowed:
            return None
        denied = decision.to_result()
        step = denied.next_steps[0] if denied.next_steps else ASK_STEP
        return Result.refused(command, "NOT_AUTHORIZED", denied.problems[0].message, step, denied.data)

    return check


class _Denied(Exception):
    def __init__(self, result: Result) -> None:
        super().__init__(result.problems[0].message)
        self.result = result


def run_locked(
    command: str, root: Path, fn: Callable[[exit_journal.Session], Result], *, write: bool
) -> Result:
    """Run `fn` in the knowledge session; refusals carry any recovered exit."""
    recovered: dict[str, Any] | None = None
    try:
        with exit_journal.session(root, write=write) as session:
            recovered = session.recovered
            result = fn(session)
    except RefError as exc:
        result = exc.result(command)
    except _Denied as exc:
        result = exc.result
    except (LockHeld, durable.StoreError, exit_journal.JournalInvalid) as exc:
        result = exit_journal.refusal(command, exc)
    except OSError as exc:
        result = Result.refused(command, "IO_ERROR", f"{exc.strerror or exc}", IO_STEP)
    return exit_journal.with_recovered(result, recovered)


def _write(
    command: str,
    op: str,
    project: str | None,
    trust_paths: TrustPaths | None,
    fn: Callable[[durable.Tree], Result],
) -> Result:
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    authorize = _authorizer(op, trust_paths)
    denied = authorize(command)
    if denied is not None:
        return denied

    def locked(session: exit_journal.Session) -> Result:
        again = authorize(command)
        if again is not None:
            raise _Denied(again)
        recover(session.tree)
        return fn(session.tree)

    return run_locked(command, root, locked, write=True)


# --------------------------------------------------------------------------- files
def _now() -> str:
    return clock.iso(clock.utc_now())


def _tmp(name: str) -> str:
    return f".{name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"


def record_text(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _write_file(tree: durable.Tree, rel: str, name: str, data: bytes) -> None:
    fd = tree.dir(rel, create=True, mode=0o755)
    try:
        durable.write(fd, name, data, _tmp(name), mode=0o644 if durable.entry(fd, name) is None else None)
    finally:
        durable.close(fd)


def _log(
    tree: durable.Tree,
    ns_ver: str,
    operation: str,
    identity: str,
    revision: int | None,
    name: str,
    old: str | None,
    new: str | None,
    removal_id: str | None = None,
) -> None:
    """Append one entry to `<NS>/<VER>/.changelog.md` (same locked operation as the record write)."""
    rel = f"{REGISTRY_REL}/{ns_ver}"
    raw = lifecycle.read_at(tree, rel, CHANGELOG)
    text = raw.decode("utf-8") if raw is not None else f"# Reference changelog — {ns_ver}\n\n"
    detail = ", ".join(
        x
        for x in (
            f"revision {revision}" if revision else "",
            f"removal_id {removal_id}" if removal_id else "",
        )
        if x
    )
    text += (
        f"## {_now()} {operation} {identity}" + (f" ({detail})" if detail else "") + " (role: maintainer)\n\n"
    )
    text += changelog._diff(name, old, new) + "\n"
    _write_file(tree, rel, CHANGELOG, text.encode("utf-8"))


def _tombstones(tree: durable.Tree) -> list[dict[str, Any]]:
    try:
        return registry.removed_entries(lifecycle.read_at(tree, REGISTRY_REL, REMOVED_FILE))
    except (ValueError, UnicodeError) as exc:
        raise RefError(
            "REFERENCE_TOMBSTONES_INVALID",
            f"{REMOVED_FILE} is unreadable: {exc}",
            "Restore the Reference registry from version control",
        ) from None


def _save_tombstones(tree: durable.Tree, entries: list[dict[str, Any]]) -> None:
    data = {"schema": REMOVED_SCHEMA, "removed": sorted(entries, key=lambda e: (e["rule"], e["removal_id"]))}
    _write_file(tree, REGISTRY_REL, REMOVED_FILE, record_text(data).encode("utf-8"))


def _rule_rel(ref: RuleRef) -> str:
    return f"{REGISTRY_REL}/{ref.namespace}/{ref.version}/{ref.rule_id}"


def _delete_rule_files(tree: durable.Tree, ref: RuleRef) -> None:
    """Remove `reference.json` (and staged temporaries) and the then-empty rule folder."""
    fd = tree.opt_dir(_rule_rel(ref))
    if fd is None:
        return
    try:
        for name, _ in durable.listdir(fd):
            if name == RULE_FILE or (name.startswith(f".{RULE_FILE}.") and name.endswith(".tmp")):
                durable.unlink(fd, name)
    finally:
        durable.close(fd)
    parent = tree.dir(f"{REGISTRY_REL}/{ref.namespace}/{ref.version}")
    try:
        durable.rmdir_empty(parent, ref.rule_id)
    except OSError:
        pass  # other files remain: the folder is kept (never deleted with unknown content)
    finally:
        durable.close(parent)


def _exists(tree: durable.Tree, rel: str) -> bool:
    fd = tree.opt_dir(rel)
    durable.close(fd)
    return fd is not None


def recover(tree: durable.Tree) -> None:
    """Light registry recovery: finish interrupted removals and append missing changelog entries."""
    if not _exists(tree, REGISTRY_REL):
        return
    for stone in _tombstones(tree):
        ref = RuleRef.parse(stone["rule"])
        old = lifecycle.read_at(tree, _rule_rel(ref), RULE_FILE)
        if old is not None:
            _delete_rule_files(tree, ref)
        ns_ver = f"{ref.namespace}/{ref.version}"
        log = lifecycle.read_at(tree, f"{REGISTRY_REL}/{ns_ver}", CHANGELOG) or b""
        if stone["removal_id"].encode("utf-8") not in log:
            _log(
                tree,
                ns_ver,
                "removed rule",
                ref.rel,
                None,
                RULE_FILE,
                old.decode("utf-8", "replace") if old is not None else "",
                None,
                stone["removal_id"],
            )


# --------------------------------------------------------------------------- validation
def _text(value: Any, field: str, limit: int, reason: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or not value.isprintable():
        raise invalid(reason, f"{field} must be one line of 1-{limit} printable characters")
    if mask_text(value)[1]:
        raise invalid(reason, f"{field} contains a credential-like value")
    return value


def _refusal(exc: urls.UrlRefusal) -> RefError:
    return invalid(exc.reason, exc.message)


def check_source_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Normalized domains, scheme, port, path prefix and display name (REGISTRATION_INVALID otherwise)."""
    domains = fields.get("domains")
    if not isinstance(domains, list) or not domains or len(domains) > MAX_DOMAINS:
        raise invalid("domain_invalid", f"domains must be a list of 1-{MAX_DOMAINS} domain names")
    try:
        normalized = sorted({urls.normalize_domain(d) for d in domains})
        scheme = urls.check_scheme(fields.get("scheme", "https"), normalized)
        port = urls.check_port(fields.get("port"))
        prefix = urls.check_prefix(fields.get("path_prefix"))
    except urls.UrlRefusal as exc:
        raise _refusal(exc) from None
    display = fields.get("display_name")
    if display is not None:
        display = _text(display, "display_name", MAX_DISPLAY, "display_name_invalid")
    return {
        "domains": normalized,
        "scheme": scheme,
        "port": port,
        "path_prefix": prefix,
        "display_name": display,
    }


def check_rule_fields(fields: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    title = _text(fields.get("title"), "title", registry.MAX_TITLE, "title_invalid")
    try:
        applicability = registry.check_applicability(fields.get("applicability"))
    except ValueError as exc:
        raise invalid("applicability_invalid", str(exc)) from None
    try:
        target = urls.check_target(source, fields.get("entry_url"))
    except urls.UrlRefusal as exc:
        raise _refusal(exc) from None
    return {"title": title, "entry_url": target.url, "applicability": applicability}


def _identity(text: Any) -> RuleRef:
    try:
        return RuleRef.parse(text)
    except IdentityError as exc:
        raise RefError(exc.code, exc.message, REQUEST_STEP) from None


def _source_id(text: Any) -> tuple[str, str]:
    parts = text.split("/") if isinstance(text, str) else []
    if len(parts) != 2:
        raise RefError("REQUEST_INVALID", f"A source is NAMESPACE/VERSION: {text!r}", REQUEST_STEP)
    try:
        make_ref(parts[0], parts[1], "probe")
    except IdentityError as exc:
        raise RefError(exc.code, exc.message, REQUEST_STEP) from None
    return parts[0], parts[1]


def _case_clash(tree: durable.Tree, parts: tuple[str, ...]) -> str | None:
    """A registry folder differing from `parts` only by letter case (links are never followed)."""
    rel = REGISTRY_REL
    for part in parts:
        fd = tree.opt_dir(rel)
        if fd is None:
            return None
        try:
            names = [n for n, info in durable.listdir(fd) if stat.S_ISDIR(info.st_mode)]
        finally:
            durable.close(fd)
        if part in names:
            rel = f"{rel}/{part}"
            continue
        clash = [n for n in names if n.lower() == part.lower()]
        return (
            f"'{part}' collides with existing '{clash[0]}' (differs only by letter case)" if clash else None
        )
    return None


def _collision(tree: durable.Tree, view: registry.RegistryView, ref: RuleRef) -> None:
    if ref.rel in view.rules:
        raise RefError("IDENTITY_COLLISION", f"{ref.rel} is already registered", "Choose another identity")
    clash = _case_clash(tree, (ref.namespace, ref.version, ref.rule_id))
    if clash:
        raise RefError("IDENTITY_COLLISION", f"{ref.rel}: {clash}", "Choose another identity")
    exited = lifecycle.reserved(lifecycle.read_memory(tree), ref)
    if exited is not None:
        raise RefError(
            "IDENTITY_RESERVED",
            f"{exited['rule']} was {exited['action']} (exit {exited['exit_id']}) and stays reserved",
            "Choose another identity",
        )


def _usable_source(view: registry.RegistryView, ns_ver: str) -> dict[str, Any]:
    source = view.sources.get(ns_ver)
    if source is None:
        raise RefError(
            "SOURCE_NOT_FOUND",
            f"Reference source {ns_ver} is not registered",
            "Register the source first (an item of type source)",
        )
    if isinstance(source, Bad):
        raise RefError(
            "REGISTRY_INVALID",
            f"Reference source {ns_ver} is unusable: {source.detail}",
            "Restore the Reference registry from version control",
        )
    return source


# --------------------------------------------------------------------------- register
def _register_source(tree: durable.Tree, view: registry.RegistryView, item: dict[str, Any]) -> str:
    ns, ver = item.get("namespace"), item.get("version")
    try:
        make_ref(ns, ver, "probe")
    except IdentityError as exc:
        raise RefError(exc.code, exc.message, REQUEST_STEP) from None
    ns_ver = f"{ns}/{ver}"
    if ns_ver in view.sources:
        raise RefError(
            "IDENTITY_COLLISION",
            f"Reference source {ns_ver} is already registered",
            "Choose another identity",
        )
    clash = _case_clash(tree, (ns, ver))
    if clash:
        raise RefError("IDENTITY_COLLISION", f"{ns_ver}: {clash}", "Choose another identity")
    fields = check_source_fields(item)
    at = _now()
    record = {
        "schema": registry.SOURCE_SCHEMA,
        "namespace": ns,
        "version": ver,
        **fields,
        "revision": 1,
        "registered_at": at,
        "updated_at": at,
    }
    text = record_text(record)
    _write_file(tree, f"{REGISTRY_REL}/{ns_ver}", SOURCE_FILE, text.encode("utf-8"))
    _log(tree, ns_ver, "registered source", ns_ver, 1, SOURCE_FILE, None, text)
    return ns_ver


def _register_rule(tree: durable.Tree, view: registry.RegistryView, item: dict[str, Any]) -> str:
    ref = _identity(item.get("rule"))
    _collision(tree, view, ref)
    ns_ver = f"{ref.namespace}/{ref.version}"
    fields = check_rule_fields(item, _usable_source(view, ns_ver))
    at = _now()
    record = {
        "schema": registry.RULE_SCHEMA,
        "rule": ref.rel,
        **fields,
        "revision": 1,
        "registered_at": at,
        "updated_at": at,
    }
    stones = _tombstones(tree)
    if any(s["rule"] == ref.rel for s in stones):
        _save_tombstones(tree, [s for s in stones if s["rule"] != ref.rel])
    text = record_text(record)
    _write_file(tree, _rule_rel(ref), RULE_FILE, text.encode("utf-8"))
    _log(tree, ns_ver, "registered rule", ref.rel, 1, RULE_FILE, None, text)
    return ref.rel


def register_batch(project: str | None, batch: str, *, trust_paths: TrustPaths | None = None) -> Result:
    """Register sources and rules; items are processed in order, each validated and written on its own."""
    command = "knowledge reference register"
    try:
        data = load_request(batch, BATCH_SCHEMA, {"schema", "items"})
    except CatalogError as exc:
        return Result.refused(command, "REQUEST_INVALID", exc.message, REQUEST_STEP)
    items = data.get("items")
    if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
        return Result.refused(
            command, "REQUEST_INVALID", f"items must be a list of 1-{MAX_ITEMS} items", REQUEST_STEP
        )

    def apply(tree: durable.Tree) -> Result:
        outcomes = []
        for index, item in enumerate(items):
            kind = item.get("type") if isinstance(item, dict) else None
            row: dict[str, Any] = {"index": index, "type": kind, "id": None}
            try:
                if kind not in ("source", "rule"):
                    raise request_error("type must be source or rule")
                unknown = sorted(set(item) - (SOURCE_ITEM if kind == "source" else RULE_ITEM))
                if kind == "source":
                    row["id"] = f"{item.get('namespace')}/{item.get('version')}"
                else:
                    row["id"] = item.get("rule")
                if unknown:
                    raise request_error(f"Unknown item fields: {unknown}")
                view = registry.view_at(tree)
                (_register_source if kind == "source" else _register_rule)(tree, view, item)
                row["outcome"] = "registered"
            except RefError as exc:
                row.update({"outcome": "refused", "code": exc.code, "reason": exc.reason or exc.message})
            except durable.StoreError as exc:
                row.update({"outcome": "refused", "code": exc.code, "reason": exc.message})
            outcomes.append(row)
        refused = [r for r in outcomes if r["outcome"] == "refused"]
        out = {"items": outcomes, "registered": len(outcomes) - len(refused), "refused": len(refused)}
        if not refused:
            return Result(command, True, out, [], ["Run secure-code knowledge reference list to review"])
        message = "; ".join(f"item {r['index']} ({r['id']}): {r['code']} {r['reason']}" for r in refused)
        return Result(
            command,
            False,
            out,
            [Problem(refused[0]["code"], f"Refused items: {message}")],
            ["Fix the refused items and register them again (registered items are kept)"],
        )

    return _write(command, "register", project, trust_paths, apply)


# --------------------------------------------------------------------------- update
def update(
    project: str | None,
    *,
    rule: str | None = None,
    source: str | None = None,
    registration_digest: str | None,
    changes: dict[str, Any],
    trust_paths: TrustPaths | None = None,
) -> Result:
    """Update one source or rule against its current registration digest (STALE_REGISTRATION otherwise)."""
    command = "knowledge reference update"
    allowed = RULE_CHANGES if rule is not None else SOURCE_CHANGES
    if (rule is None) == (source is None):
        return Result.refused(
            command, "REQUEST_INVALID", "Name exactly one of --rule or --source", REQUEST_STEP
        )
    if not changes or set(changes) - allowed:
        return Result.refused(
            command,
            "REQUEST_INVALID",
            f"Changes must be a non-empty subset of {sorted(allowed)}",
            REQUEST_STEP,
        )

    def apply(tree: durable.Tree) -> Result:
        view = registry.view_at(tree)
        if rule is not None:
            return _update_rule(tree, view, _identity(rule), registration_digest, changes, command)
        return _update_source(tree, view, "/".join(_source_id(source)), registration_digest, changes, command)

    return _write(command, "update", project, trust_paths, apply)


def _stale(current: str) -> RefError:
    return RefError(
        "STALE_REGISTRATION",
        "The registration changed since it was shown (or no digest was given)",
        SHOW_STEP,
        {"current_digest": current},
    )


def _update_rule(
    tree: durable.Tree,
    view: registry.RegistryView,
    ref: RuleRef,
    digest: str | None,
    changes: dict[str, Any],
    command: str,
) -> Result:
    usable = view.usable(ref)
    if isinstance(usable, Bad):
        code = "RULE_NOT_REGISTERED" if ref.rel not in view.rules else "REGISTRY_INVALID"
        raise RefError(
            code,
            f"{ref.rel}: {usable.detail}",
            "Register the rule first (secure-code knowledge reference register)",
        )
    old, source = usable
    current = registry.registration_digest(old, source)
    if digest != current:
        raise _stale(current)
    fields = check_rule_fields({**registry.rule_summary(old), **changes}, source)
    new = {**old, **fields, "revision": old["revision"] + 1, "updated_at": _now()}
    new_digest = registry.registration_digest(new, source)
    keys = cache.invalidate_at(tree, rule=ref.rel) if new_digest != current else []
    text = record_text(new)
    _write_file(tree, _rule_rel(ref), RULE_FILE, text.encode("utf-8"))
    _log(
        tree,
        f"{ref.namespace}/{ref.version}",
        "updated rule",
        ref.rel,
        new["revision"],
        RULE_FILE,
        record_text(old),
        text,
    )
    out = {"rule": ref.rel, "record": new, "registration_digest": new_digest, "invalidated_cache": keys}
    return Result(command, True, out, [], [])


def _update_source(
    tree: durable.Tree,
    view: registry.RegistryView,
    ns_ver: str,
    digest: str | None,
    changes: dict[str, Any],
    command: str,
) -> Result:
    old = _usable_source(view, ns_ver)
    current = registry.source_digest(old)
    if digest != current:
        raise _stale(current)
    base = {k: old[k] for k in SOURCE_CHANGES}
    new = {
        **old,
        **check_source_fields({**base, **changes}),
        "revision": old["revision"] + 1,
        "updated_at": _now(),
    }
    outside = []
    for rel, record in sorted(view.rules.items()):
        if rel.startswith(ns_ver + "/") and not isinstance(record, Bad):
            try:
                urls.check_target(new, record["entry_url"])
            except urls.UrlRefusal as exc:
                outside.append(f"{rel} ({exc.reason})")
    if outside:
        raise RefError(
            "REGISTRATION_INVALID",
            "The change would leave registered rules outside the source: " + ", ".join(outside),
            "Update or remove those rules first",
            reason=outside[0].split("(")[-1].rstrip(")"),
        )
    new_digest = registry.source_digest(new)
    keys = cache.invalidate_at(tree, source=ns_ver, source_digest=current) if new_digest != current else []
    text = record_text(new)
    _write_file(tree, f"{REGISTRY_REL}/{ns_ver}", SOURCE_FILE, text.encode("utf-8"))
    _log(tree, ns_ver, "updated source", ns_ver, new["revision"], SOURCE_FILE, record_text(old), text)
    out = {"source": ns_ver, "record": new, "registration_digest": new_digest, "invalidated_cache": keys}
    return Result(command, True, out, [], [])


# --------------------------------------------------------------------------- removal
def _removal_impact(tree: durable.Tree, ref: RuleRef, reason: str, reg_digest: str) -> tuple[dict, str]:
    from ..knowledge import impact
    from ..policy import resolve

    found = impact.collect(impact.Context(tree, ref, None, resolve.snapshot(tree)))
    if "reference_cache" not in found:
        found["reference_cache"] = cache.impact_provider(
            impact.Context(tree, ref, None, resolve.snapshot(tree))
        )
    digest = lifecycle.sha(
        lifecycle.canonical(
            {
                "schema": REMOVAL_SCHEMA,
                "rule": ref.rel,
                "reason": reason,
                "registration_digest": reg_digest,
                "providers": {kind: f.fingerprint() for kind, f in found.items()},
            }
        )
    )
    return {kind: f.view() for kind, f in found.items()}, digest


def _removable(view: registry.RegistryView, ref: RuleRef, reason: Any) -> str:
    problem = lifecycle.reason_problem(reason)
    if problem:
        raise RefError(problem, "Give a one-line reason (at most 1000 characters)", REQUEST_STEP)
    usable = view.usable(ref)
    if isinstance(usable, Bad):
        code = "RULE_NOT_REGISTERED" if ref.rel not in view.rules else "REGISTRY_INVALID"
        raise RefError(
            code, f"{ref.rel}: {usable.detail}", "Check the identity (secure-code knowledge reference list)"
        )
    return registry.registration_digest(*usable)


def remove_preview(
    project: str | None, rule: str, reason: str, *, trust_paths: TrustPaths | None = None
) -> Result:
    """Step 1 of a rule removal: read-only impact (delivered providers plus `reference_cache`) and digest."""
    command = "knowledge reference remove-preview"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    authorize = _authorizer("remove", trust_paths)
    denied = authorize(command)
    if denied is not None:
        return denied

    def read(session: exit_journal.Session) -> Result:
        ref = _identity(rule)
        reg_digest = _removable(registry.view_at(session.tree), ref, reason)
        shown, digest = _removal_impact(session.tree, ref, reason, reg_digest)
        out = {
            "rule": ref.rel,
            "reason": reason,
            "impact": shown,
            "impact_digest": digest,
            "registration_digest": reg_digest,
            "note": "references elsewhere are not edited; they report the rule as deleted",
        }
        step = (
            "Show the impact to the Maintainer, then run secure-code knowledge reference remove-confirm "
            "with --impact-digest and --registration-digest"
        )
        return Result(command, True, out, [], [step])

    return run_locked(command, root, read, write=False)


def remove_confirm(
    project: str | None,
    rule: str,
    reason: str,
    impact_digest: str | None,
    registration_digest: str | None,
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    """Step 2: recompute the impact; invalidate cache → tombstone → delete files → changelog."""
    command = "knowledge reference remove-confirm"

    def apply(tree: durable.Tree) -> Result:
        ref = _identity(rule)
        view = registry.view_at(tree)
        current = _removable(view, ref, reason)
        if registration_digest != current:
            raise _stale(current)
        _, digest = _removal_impact(tree, ref, reason, current)
        if impact_digest != digest:
            raise RefError(
                "STALE_IMPACT",
                "The impact changed since the preview",
                "Preview again",
                {"impact_digest": digest},
            )
        record = view.rules[ref.rel]
        keys = cache.invalidate_at(tree, rule=ref.rel)
        removal_id = "rm-" + _now().replace("-", "").replace(":", "") + "-" + secrets.token_hex(4)
        stones = [s for s in _tombstones(tree) if s["rule"] != ref.rel]
        _save_tombstones(
            tree,
            [*stones, {"rule": ref.rel, "removal_id": removal_id, "removed_at": _now(), "reason": reason}],
        )
        _delete_rule_files(tree, ref)
        _log(
            tree,
            f"{ref.namespace}/{ref.version}",
            "removed rule",
            ref.rel,
            None,
            RULE_FILE,
            record_text(record),
            None,
            removal_id,
        )
        out = {"rule": ref.rel, "removed": True, "removal_id": removal_id, "invalidated_cache": keys}
        return Result(command, True, out, [], [])

    return _write(command, "remove", project, trust_paths, apply)


def remove_source(
    project: str | None,
    source: str,
    registration_digest: str | None,
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    """Remove a source without rules; its explore entries are invalidated, the changelog stays as history."""
    command = "knowledge reference remove-source"

    def apply(tree: durable.Tree) -> Result:
        ns_ver = "/".join(_source_id(source))
        view = registry.view_at(tree)
        old = _usable_source(view, ns_ver)
        current = registry.source_digest(old)
        if registration_digest != current:
            raise _stale(current)
        rules = sorted(rel for rel in view.rules if rel.startswith(ns_ver + "/"))
        if rules:
            raise RefError(
                "SOURCE_HAS_RULES",
                f"{ns_ver} still has registered rules: {', '.join(rules)}",
                "Remove the rules first (secure-code knowledge reference remove-preview/-confirm)",
            )
        keys = cache.invalidate_at(tree, source=ns_ver, source_digest=current)
        fd = tree.dir(f"{REGISTRY_REL}/{ns_ver}")
        try:
            durable.unlink(fd, SOURCE_FILE)
        finally:
            durable.close(fd)
        _log(tree, ns_ver, "removed source", ns_ver, None, SOURCE_FILE, record_text(old), None)
        return Result(command, True, {"source": ns_ver, "removed": True, "invalidated_cache": keys}, [], [])

    return _write(command, "remove-source", project, trust_paths, apply)
