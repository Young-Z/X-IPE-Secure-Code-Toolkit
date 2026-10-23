"""Trivy execution inside `guard tool` (FEATURE-002-D): ephemeral staging outside the run folder, pre-check,
per-check trees, offline processes (stdout in memory, stderr parsed in stream), accounting, normalization
and the post-scan re-hash of every used component (always, also on errors and cancellation).

Runs with the project Guard lock held (`guard tool`).
"""

from __future__ import annotations

import math
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..guard import targets
from ..guard.model import MAX_EVIDENCE_TOTAL, GuardError
from ..guard.toolctl import ToolCancelled
from ..knowledge import durable, store
from . import process, registry_store, safe_io, trivy, trivy_archive, trivy_cache, trivy_fs, trivy_journal
from .trivy_account import account
from .trivy_log import LogParser

STAGE_REL = f"{store.PRIVATE_REL}/adapter-stage/trivy"
STAGE_PATTERN = r"^stage-[0-9a-f]{16}$"
STDOUT_CAP = 64 * 1024 * 1024
ORDER = ("completed", "completed_with_errors", "failed", "timed_out", "precheck_failed")
STAGE_CHANGED = (
    "staging location changed during the run; the replacement was not deleted; the emptied original folder "
    "may remain at an unknown location"
)


def worst(statuses: list[str]) -> str:
    return max(statuses, key=ORDER.index) if statuses else "failed"


def _under(path: str, roots: list[str]) -> bool:
    return any(path == r or r == "." or path.startswith(r + "/") for r in roots)


def _new_check(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": None,
        "gaps": [],
        "found": [],
        "accounting": [],
        "processes": [],
        "scanners": c["scanners"],
        "mode": c["mode"],
        "config_types": c["config_types"],
        "components_used": [],
    }


def execute(root: Path, vid: str, state: dict[str, Any], req: dict[str, Any], n: int, prefix: str) -> dict:
    out: dict[str, Any] = {
        "n": n,
        "prefix": prefix,
        "gap": None,
        "per_check": {c["check"]: _new_check(c) for c in req["checks"]},
        "build": {},
        "staged_digests": {},
        "staging_left": False,
        "archives": {},
        "components": {},
        "rehash": {},
        "problems": [],
        "stage_gap": None,
        "outputs": {c["check"]: {} for c in req["checks"]},
    }
    trivy_journal.recover(root)
    with durable.Tree(root) as tree:
        root_fd = trivy_fs.open_root(tree, STAGE_REL)
        try:
            out["problems"] += trivy_fs.sweep(root_fd, STAGE_PATTERN)
            leaf, leaf_fd, identity = trivy_fs.make_leaf(root_fd, "stage-")
            ctx = {
                "root": root,
                "vid": vid,
                "state": state,
                "req": req,
                "out": out,
                "leaf_fd": leaf_fd,
                "stage": root / STAGE_REL / leaf,
                "links": [],
                "used": {},
                "pointer": {"components": {}},
            }
            cancelled: ToolCancelled | None = None
            try:
                _run(ctx)
            except ToolCancelled as exc:
                cancelled = exc
            finally:
                _finish(ctx, root_fd, leaf, identity)
            if cancelled is not None:
                raise cancelled
        finally:
            os.close(root_fd)
    return out


# --------------------------------------------------------------------------- pre-check and staging
def _run(ctx: dict[str, Any]) -> None:
    root, out, req, stage = ctx["root"], ctx["out"], ctx["req"], ctx["stage"]
    checked = registry_store.check(root, "trivy", stage / "bin" / "trivy")
    if isinstance(checked, registry_store.Gap):
        out["gap"] = checked
        return
    record, build = checked
    out["build"] = {
        "version": build.version,
        "asset": build.asset,
        "platform_validated": build.validated,
        "platform": {"os": build.os, "arch": build.arch, "libc": build.libc},
        "binary_digest": record["digest"],
    }
    ctx["pointer"] = trivy_cache.load_pointer(root) or {"components": {}}
    now = datetime.now(UTC)
    out["components"] = {
        name: trivy_cache.component_state(root, name, now, ctx["pointer"]) for name in trivy.COMPONENTS
    }
    staged = _stage(ctx)
    if staged is None:
        return
    files, irregular, changed = staged
    _quota(ctx, files)
    for name in ("work", "tmp", "home"):
        os.close(trivy_fs.make_dir(ctx["leaf_fd"], name))
    ctx["env"] = trivy.tool_env(stage, stage / "home")
    ctx["deadline"] = time.monotonic() + req["time_limit"]
    for ci, c in enumerate(req["checks"]):
        _check(ctx, ci, c, files, irregular, changed)


def _stage(ctx: dict[str, Any]) -> tuple[list[str], list[str], set[str]] | None:
    from ..guard import toolrun

    root, out, req, state, leaf_fd = ctx["root"], ctx["out"], ctx["req"], ctx["state"], ctx["leaf_fd"]
    artifact = state["artifact"]
    archives = {t for c in req["checks"] if c["mode"] == "image_archive" for t in c["targets"]}
    owners = sorted({targets.owning_target(artifact, t) for c in req["checks"] for t in c["targets"]})
    files: list[str] = []
    irregular: list[str] = []
    changed: set[str] = set()
    used_bytes = 0
    src_fd = trivy_fs.make_dir(leaf_fd, "src")
    try:
        for index, owner in enumerate(owners):
            entry = next(t for t in artifact["targets"] if t["path"] == owner)
            if entry["digest"] is None:
                changed.add(owner)
                continue
            is_archive = owner in archives
            if is_archive:
                limit = trivy_archive.MAX_ARCHIVE
                vfs = os.statvfs(ctx["stage"])
                if vfs.f_bavail * vfs.f_frsize < (root / owner).stat().st_size:
                    out["gap"] = registry_store.Gap(
                        "STAGE_NO_SPACE",
                        f"Not enough free disk space to stage {owner}",
                        "Free disk space, then retry",
                    )
                    return None
            else:
                limit = toolrun.MAX_STAGE_BYTES - used_bytes
            # An explicit archive is staged once at its own path within the archive maximum; a folder
            # target containing it skips it (hashed only), so the folder's limits are unchanged.
            nested = (
                not is_archive
                and any(o != owner and _under(owner, [o]) for o in owners)
                and not targets.not_in_tree(owner)
            )
            skip = frozenset(
                a
                for a in archives
                if not is_archive and a != owner and _under(a, [owner]) and not targets.not_in_tree(a)
            )
            dest_name = f"verify{index}" if nested else None
            dest_fd = trivy_fs.make_dir(leaf_fd, dest_name) if nested else src_fd
            try:
                result = targets.stage(
                    root,
                    owner,
                    entry["kind"],
                    ctx["stage"] / "src",
                    limit,
                    toolrun.MAX_STAGE_FILES - len(files),
                    dest_fd=dest_fd,
                    skip=skip,
                )
            finally:
                if nested:
                    st = os.fstat(dest_fd)
                    os.close(dest_fd)
                    trivy_fs.remove_tree_at(leaf_fd, dest_name, (st.st_dev, st.st_ino))
            if not is_archive:
                used_bytes += result["bytes"]
            out["staged_digests"][owner] = result["digest"]
            if result["digest"] != entry["digest"]:
                changed.add(owner)
            if not nested:
                files += result["files"]
                irregular += result["irregular"]
    except safe_io.TooLarge as exc:
        out["gap"] = registry_store.Gap(
            "STAGE_TOO_LARGE", f"Targets too large to stage: {exc}", "Use narrower targets or another method"
        )
        return None
    except (OSError, safe_io.UnsafePath, durable.StoreError, trivy_fs.IdentityChanged) as exc:
        out["gap"] = registry_store.Gap(
            "STAGE_UNSAFE",
            f"Targets could not be staged safely: {exc}",
            "Remove links or retry when the files are stable",
        )
        return None
    finally:
        os.close(src_fd)
    for rel in sorted(archives - changed):
        try:
            fd = safe_io.open_nofollow(ctx["stage"] / "src", rel)
        except (OSError, safe_io.UnsafePath) as exc:
            out["archives"][rel] = {"error": f"staged archive not readable: {exc}"}
            continue
        try:
            info = trivy_archive.validate_archive(fd, os.fstat(fd).st_size)
        finally:
            os.close(fd)
        out["archives"][rel] = (
            info.to_dict()
            if isinstance(info, trivy_archive.ArchiveInfo)
            else {"error": f"staged archive invalid: {info.reason}"}
        )
    return files, irregular, changed


def _quota(ctx: dict[str, Any], files: list[str]) -> None:
    used = sum(e.get("stored_bytes", 0) for e in ctx["state"]["evidence"])
    bound = sum(len(f.encode("utf-8", "surrogateescape")) + 256 for f in files)
    bound += 64 * 1024 * len(ctx["req"]["checks"]) + 1024 * 1024
    if used + bound > MAX_EVIDENCE_TOTAL:
        raise GuardError(
            "EVIDENCE_QUOTA",
            "Not enough evidence quota left to keep the tool accounting",
            "Open a new verification or use narrower targets",
        )


# --------------------------------------------------------------------------- one check
def _component_gaps(ctx: dict[str, Any], pc: dict[str, Any], needed: list[str]) -> bool:
    bad = False
    for name in needed:
        st = ctx["out"]["components"][name]
        if st["state"] == "present":
            continue
        bad = True
        code = "TRIVY_COMPONENT_MISSING" if st["state"] == "missing" else "TRIVY_COMPONENT_UNREADABLE"
        registry = st.get("registry") if st.get("registry") in trivy.REPOSITORIES else "mirror.gcr.io"
        pc["gaps"].append(
            f"[{code}] {name} {st['state']}: {st.get('reason')}; next step: "
            f"{trivy.provision_step(name, registry, ctx['vid'])}"
        )
    return bad


def _check(
    ctx: dict[str, Any], ci: int, c: dict[str, Any], files: list[str], irregular: list[str], changed: set[str]
) -> None:
    out, artifact = ctx["out"], ctx["state"]["artifact"]
    pc = out["per_check"][c["check"]]
    moved = sorted({targets.owning_target(artifact, t) for t in c["targets"]} & changed)
    if moved:
        pc["status"] = "failed"
        pc["gaps"].append(f"target {', '.join(moved)} changed since the verification opened; not run")
        return
    broken = [out["archives"][t]["error"] for t in c["targets"] if "error" in out["archives"].get(t, {})]
    if broken:
        pc["status"] = "failed"
        pc["gaps"] += broken
        return
    needed = sorted({n for s in c["scanners"] for n in trivy.needed_components(s, c["mode"])})
    if _component_gaps(ctx, pc, needed):
        pc["status"] = "precheck_failed"
        return
    leaf_fd, name = ctx["leaf_fd"], f"c{ci + 1}"
    cfd = trivy_fs.make_dir(leaf_fd, name)
    try:
        cache_fd = trivy_fs.make_dir(cfd, "cache")
        try:
            links = trivy_cache.scan_folder(ctx["root"], needed, cache_fd, ctx["pointer"])
        finally:
            os.close(cache_fd)
        ctx["links"] += [(name, link, target) for link, target in links.items()]
        for n_ in needed:
            ctx["used"][n_] = ctx["pointer"]["components"][n_]
        pc["components_used"] = needed
        object_files = [f for f in files if _under(f, c["targets"])]
        object_irregular = [f for f in irregular if _under(f, c["targets"])]
        if c["mode"] == "filesystem":
            tree_fd = trivy_fs.make_dir(cfd, "root")
            try:
                src_fd = durable.open_child(leaf_fd, "src")
                try:
                    for rel in object_files:
                        trivy_fs.link_into(tree_fd, rel, src_fd)
                finally:
                    os.close(src_fd)
            finally:
                os.close(tree_fd)
    finally:
        os.close(cfd)
    if c["mode"] == "filesystem" and not object_files and not object_irregular:
        pc["gaps"].append("no object file to scan under the requested targets")
    if object_irregular:
        pc["gaps"].append(
            f"{len(object_irregular)} link(s), special file(s) or non-UTF-8 name(s) not analysed, "
            f"e.g. {object_irregular[0]}"
        )
    statuses = []
    if c["mode"] == "filesystem":
        for scanner in c["scanners"]:
            statuses.append(
                _process(ctx, ci, c, pc, scanner, ctx["stage"] / name / "root", None, object_files)
            )
    else:
        for rel in c["targets"]:
            statuses.append(_process(ctx, ci, c, pc, "vuln", ctx["stage"] / "src" / rel, rel, [rel]))
    pc["status"] = worst(statuses)


def _process(ctx, ci, c, pc, scanner, target: Path, archive: str | None, object_files: list[str]) -> str:
    out, req, root = ctx["out"], ctx["req"], ctx["root"]
    info: dict[str, Any] = {
        "scanner": scanner,
        **({"archive": archive} if archive else {}),
        "exit": None,
        "seconds": 0.0,
        "status": "timed_out",
        "messages": [],
    }
    pc["processes"].append(info)
    if time.monotonic() >= ctx["deadline"]:
        pc["gaps"].append(f"{scanner}: not run before the time limit")
        return "timed_out"
    timeout_s = math.ceil(ctx["deadline"] - time.monotonic()) + 60
    patterns = [SimpleNamespace(**p) for p in c["config_types"]] if scanner == "misconfig" else []
    argv = trivy.scan_argv(
        ctx["stage"] / "bin" / "trivy",
        scanner,
        c["mode"],
        target,
        ctx["stage"] / f"c{ci + 1}" / "cache",
        timeout_s,
        patterns,
    )
    parser = LogParser(version=ctx["out"]["build"]["version"])
    try:
        outcome = process.run(
            argv,
            ctx["stage"] / "work",
            ctx["env"],
            ctx["deadline"],
            None,
            STDOUT_CAP,
            req.get("should_stop"),
            parser.feed,
        )
    except OSError as exc:
        info["status"] = "failed"
        pc["gaps"].append(f"{scanner}: the tool could not be started ({exc.strerror or exc})")
        return "failed"
    req["groups_gone"] = req.get("groups_gone", True) and outcome.group_gone
    if outcome.cancelled:
        raise ToolCancelled(req["groups_gone"])
    facts = parser.finish()
    doc = trivy.parse_output(outcome.stdout)
    fatal = [m for m in facts.messages if m["kind"] == "fatal"]
    degrading = [m for m in facts.messages if m["kind"] == "degrading"]
    if outcome.timed_out or facts.timed_out:
        status = "timed_out"
    elif outcome.oversized or outcome.exit != 0 or doc is None:
        status = "failed"
    else:
        status = "completed_with_errors" if degrading else "completed"
    info.update(
        exit=outcome.exit,
        seconds=outcome.seconds,
        status=status,
        messages=[f"{m['level']} {m['text']}" for m in facts.messages][:50],
    )
    if status != "completed":
        detail = "; ".join(m["text"] for m in fatal)[:600]
        why = (
            "output larger than 64 MiB" if outcome.oversized else "no parseable output" if doc is None else ""
        )
        pc["gaps"].append(
            f"{scanner}: tool status {status} (exit {outcome.exit})"
            + (f": {detail}" if detail else f": {why}" if why else "")
        )
    for m in degrading:
        pc["gaps"].append(f"{scanner}: tool {m['level']}: {m['text']}")
    for comp, st in sorted(facts.component_errors.items()):
        reg = (ctx["pointer"]["components"].get(comp) or {}).get("registry") or "mirror.gcr.io"
        pc["gaps"].append(
            f"{comp} {st} (reported by the tool); next step: {trivy.provision_step(comp, reg, ctx['vid'])}"
        )
        entry = ctx["pointer"]["components"].get(comp)
        if st == "unreadable" and entry:
            trivy_cache.mark_invalid(
                root, comp, entry["generation"], "the tool reported an invalid database", ctx["vid"], out["n"]
            )
    if outcome.exit == 0 and doc is not None and (not facts.recognized or scanner not in facts.anchors):
        pc["gaps"].append(
            f"{scanner}: tool log format not recognized for Trivy v0.76.1; coverage cannot be established"
        )
    if doc is None:
        return status
    clean = trivy.sanitize(doc, str(ctx["stage"]))
    key = scanner if archive is None else f"vuln:{archive}"
    out["outputs"][c["check"]][key] = clean
    acc = account(
        scanner=scanner,
        mode=c["mode"],
        files=object_files if archive is None else [],
        doc=clean,
        facts=facts,
        bundle_linked="checks_bundle" in pc["components_used"],
        archive=archive,
    )
    pc["accounting"].append(acc)
    pc["gaps"] += acc["gaps"]
    comp = None
    source = "checks_bundle" if scanner == "misconfig" else "vulnerability_db" if scanner == "vuln" else None
    if source and source in ctx["pointer"]["components"]:
        e = ctx["pointer"]["components"][source]
        comp = {
            "registry": e.get("registry"),
            "repository": f"{e.get('repository')}:{e.get('tag')}",
            "content_digest": e.get("content_digest"),
        }
    pc["found"] += trivy.normalize(clean, scanner=scanner, mode=c["mode"], archive=archive, component=comp)
    return status


# --------------------------------------------------------------------------- re-hash and cleanup
def _finish(ctx: dict[str, Any], root_fd: int, leaf: str, identity: tuple[int, int]) -> None:
    out, leaf_fd = ctx["out"], ctx["leaf_fd"]
    try:
        if ctx["used"]:
            out["rehash"] = trivy_cache.rehash(ctx["root"], ctx["used"])
            for name, result in out["rehash"].items():
                if result == "unchanged":
                    continue
                trivy_cache.mark_invalid(
                    ctx["root"], name, ctx["used"][name]["generation"], result, ctx["vid"], out["n"]
                )
                for pc in out["per_check"].values():
                    if name in pc["components_used"]:
                        pc["gaps"].append(
                            f"provisioned {name} changed since provisioning: {result}; re-provision"
                        )
        for cdir, link, target in ctx["links"]:
            try:
                cfd = durable.open_child(leaf_fd, cdir)
                try:
                    cache_fd = durable.open_child(cfd, "cache")
                    try:
                        trivy_fs.unlink_link(cache_fd, link, target)
                    finally:
                        os.close(cache_fd)
                finally:
                    os.close(cfd)
            except (OSError, durable.StoreError):
                pass  # an unexpected entry stays; the removal below never follows it
        replaced = not trivy_fs.leaf_matches(root_fd, leaf, leaf_fd, identity)
        if not replaced:
            try:
                trivy_fs.remove_tree_at(root_fd, leaf, identity)
            except trivy_fs.IdentityChanged:
                replaced = True
            except (OSError, durable.StoreError):
                out["staging_left"] = True
            if not replaced and durable.entry(root_fd, leaf) is not None:
                out["staging_left"] = True
        if replaced:
            try:
                trivy_fs.empty_by_fd(leaf_fd)
            except (OSError, durable.StoreError, trivy_fs.IdentityChanged):
                pass
            out["stage_gap"] = STAGE_CHANGED
            out["problems"].append(
                {
                    "code": "STAGING_LEFTOVER",
                    "name": leaf,
                    "message": f"staging folder {leaf} changed during the run; check it",
                }
            )
    finally:
        os.close(leaf_fd)
