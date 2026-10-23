"""`secure-code tools provision` and `tools remove-components` for Trivy.

FEATURE-002-D, AC-002D-02a…02c, 02h.

Provisioning needs a Maintainer, an accepted (open, not paused, time left) verification and FEATURE-002-C
`tool_update` grants covering every known host of the repository (DAO-001). Refusals after acceptance are
recorded as `used: false` declarations without attempt, budget or process; accepted operations run one
repository each, are verified strictly and installed through a crash-atomic journal.
"""

from __future__ import annotations

import math
import os
import time
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..auth.service import require_maintainer
from ..guard import budget, egress, runs, service
from ..guard.mask import mask_text
from ..guard.model import GuardError
from ..guard.toolctl import ack, cancelled_error, cap_time_limit
from ..knowledge import durable, store
from ..projects import knowledge_root
from ..results import Result
from . import digests, process, registry_store, trivy, trivy_cache, trivy_fs, trivy_journal
from .trivy_log import LogParser

MAX_PROVISION_SECONDS = 3600
STDOUT_CAP = 64 * 1024 * 1024
STEP_GRANT = (
    "Ask the user: secure-code guard allow-egress --purpose tool_update --recipient https://{host} "
    "--data metadata --scope {scope}"
)
CODES = {
    "maintainer": "NOT_AUTHORIZED",
    "argument": "PROVISION_REQUEST_INVALID",
    "component": "PROVISION_REQUEST_INVALID",
    "known_hosts": "TRIVY_KNOWN_HOSTS_UNKNOWN",
}
KNOWN_STEP = (
    "Use Trivy v0.76.1 with mirror.gcr.io or ghcr.io; another version needs tool-level re-validation first"
)


def _scope(repo: str) -> str:
    return f"https://{repo}"


def _hosts(state: dict[str, Any], version: str, registry: str, component: str) -> tuple[list, dict | None]:
    """Known hosts with their covering grants, or the first missing element."""
    known = trivy.KNOWN_HOSTS.get((version, registry))
    repo = trivy.REPOSITORIES[registry][component]
    if known is None:
        return [], {
            "missing": "known_hosts",
            "reason": f"no validated known-host list for Trivy {version} and {registry}",
            "code": "TRIVY_KNOWN_HOSTS_UNKNOWN",
            "step": KNOWN_STEP,
        }
    out = []
    for host in known:
        origin = f"https://{host}"
        scope = _scope(repo) if host == registry else origin + "/"
        missing, grant = egress.coverage(state, "tool_update", origin, ["metadata"], [scope], None)
        if missing:
            return out, {
                "missing": missing,
                "host": host,
                "code": "EGRESS_NOT_AUTHORIZED",
                "reason": f"{component}: no tool_update grant covers the {missing} for {host} "
                f"(scope {scope}, data metadata)",
                "step": STEP_GRANT.format(host=host, scope=scope),
            }
        out.append({"host": host, "origin": origin, "scope": scope, "grant": grant})
    return out, None


def _declaration(
    state: dict[str, Any],
    component: str | None,
    registry: str,
    hosts: list,
    refusal: dict | None,
    note: str | None = None,
) -> dict[str, Any]:
    decl = state["egress"]["declarations"]
    k = sum(1 for d in decl if str(d.get("operation", "")).startswith("trivy-provision-")) + 1
    repo = trivy.REPOSITORIES.get(registry, {}).get(component) if component else None
    out = {
        "id": f"eg-{len(decl) + 1}",
        "by": "toolkit",
        "operation": f"trivy-provision-{k}",
        "purpose": "tool_update",
        "recipient": f"https://{registry}" if registry in trivy.REPOSITORIES else None,
        "data": ["metadata"],
        "items": [f"trivy {component or 'components'} provisioning {repo or '(invalid request)'}"],
        "scope": [_scope(repo)] if repo else [],
        "known_hosts": hosts,
        "decision": "refused" if refusal else "allowed",
        "missing": (refusal or {}).get("missing"),
        "host": (refusal or {}).get("host"),
        "grant": hosts[0]["grant"] if hosts and not refusal else None,
        "at": service.now()[0],
        "used": False,
    }
    if note:
        out["note"] = note
    decl.append(out)
    return out


def _refusals(
    root: Path, state: dict[str, Any], components: Any, registry: Any, time_limit: Any, trust_paths: Any
) -> tuple[dict[str, dict], dict[str, Any], dict | None]:
    """Per requested component: refusal (or None) and its known hosts; plus the registration record."""
    common: dict | None = None
    maint = require_maintainer("tools.provision", paths=trust_paths)
    if not maint.allowed:
        common = {
            "missing": "maintainer",
            "code": "NOT_AUTHORIZED",
            "reason": f"Maintainer qualification required: {maint.status.reason}",
            "step": maint.status.next_step or "Run secure-code auth",
        }
    elif registry not in trivy.REPOSITORIES:
        common = {
            "missing": "argument",
            "code": "PROVISION_REQUEST_INVALID",
            "step": "Use --registry mirror.gcr.io or ghcr.io",
            "reason": f"registry must be one of {', '.join(trivy.REPOSITORIES)}",
        }
    elif not isinstance(time_limit, int) or isinstance(time_limit, bool) or not 1 <= time_limit <= 3600:
        common = {
            "missing": "argument",
            "code": "PROVISION_REQUEST_INVALID",
            "step": "Use --time-limit 1…3600",
            "reason": "time limit must be a whole number of seconds from 1 to 3600",
        }
    record = None
    if common is None:
        checked = registry_store.check(root, "trivy")
        if isinstance(checked, registry_store.Gap):
            common = {
                "missing": "binary",
                "code": checked.code,
                "reason": checked.reason,
                "step": checked.next_step,
            }
        else:
            record = checked[0]
    result, hosts = {}, {}
    for name in components:
        if name not in trivy.COMPONENTS:
            result[name] = {
                "missing": "component",
                "code": "PROVISION_REQUEST_INVALID",
                "step": "Use vulnerability_db, java_db or checks_bundle",
                "reason": f"unknown component {name!r}",
            }
        elif common is not None:
            result[name] = dict(common)
        else:
            hosts[name], result[name] = _hosts(state, record["version"], registry, name)
    return result, hosts, record


# --------------------------------------------------------------------------- provision
def provision(
    project: str | None,
    tool: str,
    run_id: str,
    components: list[str],
    registry: str = "mirror.gcr.io",
    time_limit: int = 600,
    trust_paths: Any = None,
) -> Result:
    command = "tools provision"
    if tool != "trivy":
        return Result.refused(
            command,
            "TOOL_UNKNOWN",
            f"No provisioning for {tool!r} in this toolkit version",
            "Available: trivy",
        )
    gap = registry_store.platform_gap("trivy", digests.host_platform())
    if gap is not None:
        return Result.refused(command, gap.code, gap.reason, gap.next_step)

    def body(root: Path) -> Result:
        with service._locked(root):
            trivy_journal.recover(root)
            vid = runs.check_id(run_id)
            state = runs.read_state(root, vid)
            runs.refuse_closed(root, vid)
            if state["status"] != "open":
                raise GuardError("RUN_FINISHED", f"Verification {vid} is already concluded", runs.NEW_RUN)
            budget.require_running(state, service.consumed(root, state))
            comps = components if isinstance(components, list) and components else ["(none)"]
            if len(set(comps)) != len(comps):
                comps = list(dict.fromkeys(comps))
            refusals, hosts, record = _refusals(root, state, comps, registry, time_limit, trust_paths)
            if any(refusals.values()):
                return _refuse(root, state, comps, registry, refusals, hosts)
            return _provision(root, state, comps, registry, time_limit, hosts, record, trust_paths)

    return service._call(command, project, body)


def _refuse(
    root: Path, state: dict[str, Any], comps: list[str], registry: str, refusals: dict, hosts: dict
) -> Result:
    rev = state["revision"]
    first = next(r for r in refusals.values() if r)
    ids = []
    for name in comps if any(c in trivy.COMPONENTS for c in comps) else [None]:
        refusal = (refusals.get(name) if name is not None else first) or {
            "missing": "other_component",
            "reason": "another requested component was refused",
        }
        known = name if name in trivy.COMPONENTS else None
        ids.append(_declaration(state, known, registry, hosts.get(name, []), refusal)["id"])
    runs.commit_state(root, state, expected_revision=rev)
    data = {
        "verification_id": state["verification_id"],
        "declarations": ids,
        "components": {
            k: {kk: vv for kk, vv in (v or {}).items() if kk in ("missing", "host", "reason")}
            for k, v in refusals.items()
        },
    }
    return Result.refused("tools provision", first["code"], first["reason"], first["step"], data)


def _provision(
    root: Path,
    state: dict[str, Any],
    comps: list[str],
    registry: str,
    time_limit: int,
    hosts: dict,
    record: dict,
    trust_paths: Any,
) -> Result:
    vid = state["verification_id"]
    req = {"time_limit": time_limit}
    used = cap_time_limit(root, state, req)
    attempt = budget.register(
        state, "tool_update", {"components": comps}, used, service.now()[0], internal=True
    )
    decls = {c: _declaration(state, c, registry, hosts[c], None, trivy.LIMIT) for c in comps}
    rev = state["revision"]
    runs.commit_state(root, state, expected_revision=rev)
    runs.write_run_json(
        root,
        vid,
        "tool-active.json",
        {"pid": os.getpid(), "attempt": attempt["id"], "at": attempt["started_at"]},
    )
    started = service.now()[0]
    try:
        ops, installed = _operations(root, state, comps, registry, req, hosts, decls, record)
        return _commit(root, vid, comps, registry, req, record, attempt, ops, installed, started, trust_paths)
    finally:
        runs.remove_run_file(root, vid, "tool-active.json")


def _use(root: Path, vid: str, decl_id: str) -> None:
    state = runs.read_state(root, vid)
    rev = state["revision"]
    d = next(x for x in state["egress"]["declarations"] if x["id"] == decl_id)
    d.update(used=True, used_at=service.now()[0])
    runs.commit_state(root, state, expected_revision=rev)


def _operations(root, state, comps, registry, req, hosts, decls, record) -> tuple[list, dict]:
    vid = state["verification_id"]
    deadline = time.monotonic() + req["time_limit"]
    should_stop = lambda: runs.cancel_marker(root, vid) is not None  # noqa: E731
    pointer = trivy_cache.load_pointer(root) or {"components": {}}
    ops, installed = [], {}
    for name in comps:
        repo = trivy.REPOSITORIES[registry][name]
        op = {
            "component": name,
            "repository": repo.rsplit(":", 1)[0],
            "tag": repo.rsplit(":", 1)[1],
            "known_hosts": hosts[name],
            "grants": [h["grant"] for h in hosts[name]],
            "declaration": decls[name]["id"],
            "outcome": "not_run",
            "previous": "kept" if name in pointer["components"] else "missing",
            "size_bytes": 0,
            "content_digest": None,
            "seconds": 0.0,
            "metadata": None,
            "reason": None,
        }
        ops.append(op)
        if time.monotonic() >= deadline:
            op["reason"] = "not run before the time limit"
            continue
        try:
            _use(root, vid, decls[name]["id"])
        except GuardError as exc:
            if exc.code == "RUN_CANCELLED":
                _discard(root, installed)
                ack(root, vid, True, "provisioning stopped before the next operation")
                raise cancelled_error(vid, True, "provisioning stopped before the next operation") from None
            raise
        _in_op_folder(root, vid, name, op, deadline, should_stop, installed)
    return ops, installed


def _in_op_folder(root, vid, name, op, deadline, should_stop, installed) -> None:
    """One operation in a fresh private folder (removed afterwards); the binary snapshot is what runs."""
    with durable.Tree(root) as tree:
        sroot = trivy_fs.open_root(tree, f"{trivy_cache.CACHE_REL}/staging")
        try:
            leaf, leaf_fd, identity = trivy_fs.make_leaf(sroot, "op-")
            opdir = root / trivy_cache.CACHE_REL / "staging" / leaf
            try:
                for sub in ("work", "home", "tmp", "cache", "empty", "bin"):
                    os.close(trivy_fs.make_dir(leaf_fd, sub))
                checked = registry_store.check(root, "trivy", opdir / "bin" / "trivy")
                if isinstance(checked, registry_store.Gap):
                    op.update(outcome="failed", reason=checked.reason)
                    return
                _one(root, vid, name, op, opdir, opdir / "bin" / "trivy", deadline, should_stop, installed)
            finally:
                try:
                    trivy_fs.remove_tree_at(sroot, leaf, identity)
                except (OSError, durable.StoreError, trivy_fs.IdentityChanged):
                    pass
                os.close(leaf_fd)
        finally:
            os.close(sroot)


def _one(root, vid, name, op, opdir, binary, deadline, should_stop, installed) -> None:
    timeout_s = math.ceil(deadline - time.monotonic()) + 60
    argv = trivy.provision_argv(binary, name, f"{op['repository']}:{op['tag']}", opdir, timeout_s)
    parser = LogParser()
    env = trivy.tool_env(opdir, opdir / "home")
    try:
        outcome = process.run(argv, opdir / "work", env, deadline, None, STDOUT_CAP, should_stop, parser.feed)
    except OSError as exc:
        op.update(outcome="failed", reason=f"the tool could not be started ({exc})")
        return
    facts = parser.finish()
    op["seconds"] = outcome.seconds
    if outcome.cancelled:
        _discard(root, installed)
        ack(root, vid, outcome.group_gone, "provisioning tool stopped")
        raise cancelled_error(vid, outcome.group_gone, "provisioning tool stopped")
    if outcome.timed_out or facts.timed_out:
        op.update(outcome="timed_out", reason="the time limit was reached; the previous state is kept")
        return
    if outcome.exit != 0:
        fatal = "; ".join(m["text"] for m in facts.messages if m["kind"] == "fatal")[:300]
        op.update(outcome="failed", reason=f"the tool exited {outcome.exit}: {fatal or 'no message'}")
        return
    try:
        records, meta = trivy_cache.verify_subtree(opdir / "cache", name, op["tag"], facts.embedded_fallback)
    except (trivy_cache.Rejected, OSError) as exc:
        op.update(outcome="failed", reason=f"download rejected: {exc}")
        return
    gen = trivy_cache.install_generation(root, name, opdir / "cache")
    installed[name] = {"generation": gen, "files": records, "metadata": meta}
    op.update(
        outcome="completed",
        previous="replaced" if op["previous"] == "kept" else "missing",
        size_bytes=sum(r["size"] for r in records.values()),
        content_digest=trivy_cache.content_digest(records),
        metadata=meta,
        reason=None,
    )


def _discard(root: Path, installed: dict) -> None:
    for name, item in installed.items():
        trivy_cache.remove_generation(root, name, item["generation"])


def _commit(root, vid, comps, registry, req, record, attempt, ops, installed, started, trust_paths) -> Result:
    state = runs.read_state(root, vid)
    rev = state["revision"]
    old_bytes = trivy_cache.read_pointer_bytes(root)
    pointer = trivy_cache.parse_pointer(old_bytes) or trivy_cache.empty_pointer()
    if pointer.get("unreadable"):
        pointer = trivy_cache.empty_pointer()
    replaced = []
    n = len(state.get("tool_provisioning", [])) + 1
    for op in ops:
        item = installed.get(op["component"])
        if not item:
            continue
        previous = pointer["components"].get(op["component"])
        if previous:
            replaced.append(f"{op['component']}/{previous['generation']}")
        gen_path = trivy_cache.generation_path(root, op["component"], item["generation"])
        pointer["components"][op["component"]] = {
            "generation": item["generation"],
            "registry": registry,
            "repository": op["repository"],
            "tag": op["tag"],
            "provisioned_at": service.now()[0],
            "verification_id": vid,
            "provisioning": n,
            "grants": op["grants"],
            "size_bytes": op["size_bytes"],
            "disk_bytes": trivy_cache.disk_bytes(gen_path) or 0,
            "content_digest": op["content_digest"],
            "files": item["files"],
            "metadata": item["metadata"],
            "invalid": None,
        }
    pointer["revision"] = int(pointer.get("revision", 0)) + 1
    pointer["tool_version"] = record.get("version")
    new_bytes = trivy_cache.pointer_bytes(pointer) if installed else old_bytes
    maint = require_maintainer("tools.provision", paths=trust_paths).status
    entry = {
        "n": n,
        "adapter": "trivy",
        "attempt": attempt["id"],
        "maintainer": {
            "action": "tools.provision",
            "role": "maintainer",
            "authorization_created_at": maint.created_at,
            "authorization_created_by": {
                k: mask_text(str(v))[0] for k, v in (maint.created_by or {}).items()
            },
        },
        "version": record.get("version"),
        "binary_digest": record.get("digest"),
        "platform_validated": bool(record.get("platform_validated")),
        "registry": registry,
        "time_limit": req["time_limit"],
        "time_limit_capped": req["time_limit"] < req["requested_time_limit"],
        "started_at": started,
        "finished_at": service.now()[0],
        "operations": ops,
        "limit": trivy.LIMIT,
    }
    state.setdefault("tool_provisioning", []).append(entry)
    done = next(a for a in state["attempts"] if a["id"] == attempt["id"])
    done.update(status="finished", finished_at=service.now()[0])
    used = service.consumed(root, state)
    done["overrun_seconds"] = round(max(0.0, used - done["deadline_consumed"]), 1)
    journal = None
    if installed:
        journal = {
            "schema": trivy_journal.SCHEMA,
            "op": "provision",
            "verification_id": vid,
            "provisioning": n,
            "attempt": attempt["id"],
            "expected_revision": rev,
            "intended_revision": rev + 1,
            "old_pointer": trivy_journal.encode(old_bytes),
            "new_pointer": trivy_journal.encode(new_bytes),
            "new_generations": [f"{k}/{v['generation']}" for k, v in installed.items()],
            "replaced_generations": replaced,
            "created_at": service.now()[0],
        }
        trivy_journal.write(root, journal)
    try:
        if journal:
            runs.commit_state(
                root,
                state,
                expected_revision=rev,
                on_commit=lambda: trivy_cache.write_pointer_bytes(root, new_bytes),
            )
        else:
            runs.commit_state(root, state, expected_revision=rev)
    except GuardError as exc:
        if trivy_cache.read_pointer_bytes(root) != old_bytes:
            trivy_cache.write_pointer_bytes(root, old_bytes)
        _discard(root, installed)
        if journal:
            trivy_journal.remove(root)
        if exc.code == "RUN_CANCELLED":
            ack(root, vid, True, "provisioning finished; results not recorded")
            raise cancelled_error(vid, True, "provisioning finished; results not recorded") from None
        raise
    if journal:
        trivy_journal.remove(root)
    trivy_cache.collect_garbage(root)
    data = {
        "verification_id": vid,
        "provisioning": n,
        "attempt": attempt["id"],
        "registry": registry,
        "time_limit": req["time_limit"],
        "time_limit_capped": entry["time_limit_capped"],
        "operations": ops,
        "limit": trivy.LIMIT,
        "budget": budget.status(state, used),
    }
    steps = ["Check the component state: secure-code status --project PATH"]
    return Result("tools provision", True, data, [], steps)


# --------------------------------------------------------------------------- removal
def remove_components(
    project: str | None,
    tool: str,
    components: list[str] | None = None,
    remove_all: bool = False,
    trust_paths: Any = None,
) -> Result:
    command = "tools remove-components"
    if tool != "trivy":
        return Result.refused(command, "TOOL_UNKNOWN", f"No component cache for {tool!r}", "Available: trivy")
    names = list(trivy.COMPONENTS) if remove_all else list(components or [])
    if (
        (remove_all and components)
        or not names
        or len(set(names)) != len(names)
        or any(n not in trivy.COMPONENTS for n in names)
    ):
        return Result.refused(
            command,
            "PROVISION_REQUEST_INVALID",
            "Name one or more of vulnerability_db, java_db, checks_bundle (each once), or --all",
            "Fix the --component values",
        )
    decision = require_maintainer("tools.remove_components", paths=trust_paths)
    if not decision.allowed:
        refused = decision.to_result()
        refused.command = command
        return refused
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        with service._locked(root):
            trivy_journal.recover(root)
            removed = trivy_cache.remove(root, names)
    except LockHeld:
        return Result.refused(
            command,
            "TRIVY_CACHE_BUSY",
            "a scan, provisioning or other Guard operation of this "
            "project is in progress; nothing was removed",
            "Retry when it has finished",
        )
    except (OSError, store.StoreError, GuardError) as exc:
        return Result.refused(
            command,
            "IO_ERROR",
            f"The component cache could not be changed: {exc}",
            "Check the permissions of the project's .x-ipe/private folder",
        )
    items = [{"component": k, **v} for k, v in removed.items()]
    data = {
        "removed": items,
        "freed_disk_bytes_total": sum(i["freed_disk_bytes"] for i in items),
        "not_present": [n for n in names if n not in removed],
    }
    return Result(command, True, data, [], ["Check the component state: secure-code status --project PATH"])
