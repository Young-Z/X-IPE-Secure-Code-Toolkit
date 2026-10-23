"""Read-only, sectioned status. Uses read/stat/listing only; never writes or scans code."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import __version__, routing
from .adapters_registry import ADAPTERS, NOT_PROVIDED, NOT_PROVIDED_NEXT
from .auth.trust_store import TrustPaths, resolve
from .auth.verify import verify
from .carrier_view import NO_LONGER_MANAGED_STEP, SUPPORTED, carrier_path, declaration, next_step, plan
from .environments import PROFILES
from .host_fragment import inspect
from .install_record import InstallRecord, RecordError, load, sha256_file
from .paths import RootError, unsafe_component, validate_root
from .project_init import DATA_ROOT, LAYOUT
from .results import Result

COMMAND = "status"


def _count_rules(folder: Path) -> int:
    """Rule entries are folders at depth <namespace>/<version>/<rule id>."""
    count = 0
    if not folder.is_dir():
        return 0
    for namespace in os.scandir(folder):
        if not namespace.is_dir(follow_symlinks=False):
            continue
        for version in os.scandir(namespace.path):
            if not version.is_dir(follow_symlinks=False):
                continue
            count += sum(1 for rule in os.scandir(version.path)
                         if rule.is_dir(follow_symlinks=False))
    return count


def _install(root: Path, record: InstallRecord | None, record_error: RecordError | None,
             problems: list[dict[str, str]]) -> dict[str, Any]:
    if record_error:
        problems.append({"code": record_error.code, "message": str(record_error)})
        return {"root": str(root), "state": "invalid record",
                "next_step": "Inspect the install record; it is not repaired automatically"}
    if record is None:
        return {"root": str(root), "state": "not installed",
                "next_step": f"secure-code init --project {root} --env <environment>"}
    drifted = 0
    for rel, expected in record.files.items():
        path = root / rel
        if not path.is_file() or sha256_file(path) != expected:
            drifted += 1
    if drifted:
        problems.append({"code": "TOOLKIT_FILES_CHANGED",
                         "message": f"{drifted} toolkit file(s) differ from the install record"})
    for rel in LAYOUT:
        if not (root / DATA_ROOT / rel).is_dir():
            problems.append({"code": "LAYOUT_MISSING",
                             "message": f"Missing folder {DATA_ROOT}/{rel}"})
    return {"root": str(root), "state": "installed", "version": record.toolkit_version,
            "environment": record.environment, "skills_dir": record.skills_dir,
            "host_entry": record.host_entry, "changed_toolkit_files": drifted,
            "next_step": "None" if not drifted else "Re-run project initialization to review"}


def _host(root: Path, record: InstallRecord | None,
          problems: list[dict[str, str]]) -> dict[str, Any]:
    if record is None:
        return {"environment": "not configured", "fragment": "not configured",
                "host_effect": "not verified", "next_step": "Run project initialization"}
    host = root / record.host_entry
    cannot_open = False
    try:
        data = host.read_bytes() if host.is_file() and not host.is_symlink() else None
        state = inspect(data, record.fragment_sha256)
    except OSError:  # exists but cannot be opened (defect fix, DAO-001): reported, no traceback
        state, cannot_open = "unreadable", True
    labels = {"absent_file": "missing file", "absent": "absent", "present": "present",
              "modified": "modified", "malformed": "malformed", "unreadable": "unreadable"}
    if state in ("malformed", "unreadable"):
        problems.append({"code": "FRAGMENT_" + state.upper(),
                         "message": f"Toolkit fragment in {record.host_entry} is {state}"})
    next_step = {"present": "None", "modified": "Re-run project initialization to review"}.get(
        state, "Run project initialization to add the toolkit fragment")
    if cannot_open:  # plain init cannot read that file either, so it is not the next step
        next_step = f"Make {record.host_entry} readable, then re-run status"
    section = {"environment": record.environment, "host_entry": record.host_entry,
               "fragment": labels[state], "host_effect": "not verified", "next_step": next_step}
    if record.environment in PROFILES:
        section.update(_carriers(root, record, problems))
    return section


RECORD_COMPATIBILITY = ("The install record holds the optional 'carriers' member; toolkit versions without "
                        "the carriers operation cannot read it and refuse it (RECORD_INVALID)")
PLAN_LABELS = {"created": ("missing file", "n/a"), "appended": ("absent", "n/a"),
               "current": ("present", "current"), "updated": ("present", "outdated"),
               "customized": ("customized", "n/a")}


def _carriers(root: Path, record: InstallRecord, problems: list[dict[str, str]]) -> dict[str, Any]:
    """FEATURE-003-B per-carrier entries (read-only; no lock; masked differences)."""
    profile = PROFILES[record.environment]
    member = record.carriers or {}
    entries = member.get("entries", {})
    selected = member.get("selected", ["host-entry"])
    host = entries.get("system-prompt", {}).get("host")
    carriers_step = f"secure-code carriers --project {root} --env {profile.name}"
    rel = f"{profile.skills_dir}/{routing.DEFINITION_REL}"
    try:
        if unsafe_component(root, rel, expect_dir=False):
            raise routing.RoutingError("ROUTING_DEFINITION_INVALID", f"{rel} is not a regular file")
        defn = routing.load_file(root / rel)
        identity = routing.RoutingIdentity(__version__, defn.digest)
    except routing.RoutingError as exc:
        problems.append({"code": "ROUTING_DEFINITION_INVALID", "message": f"{rel}: {exc.message}"})
        defn = identity = None
    items, plans, differences = [], [], {}
    for kind in SUPPORTED[profile.name]:
        path = carrier_path(kind, profile)
        if kind not in selected:
            if kind in entries:
                items.append({"carrier": kind, "path": path, "selection": "no longer managed",
                              "fragment": "no longer managed", "identity": "n/a", "front_matter": "n/a",
                              "user_content": "n/a", "host_effect": "not verified",
                              "next_step": NO_LONGER_MANAGED_STEP})
            continue
        file = root / path
        safe = not unsafe_component(root, path, expect_dir=False)
        recorded = (record.fragment_sha256 if kind == "host-entry" and record.host_entry == profile.host_entry
                    else entries.get(kind, {}).get("fragment_sha256"))
        item = {"carrier": kind, "path": path, "selection": "selected"}
        try:
            data = file.read_bytes() if safe and file.is_file() else None
        except OSError as exc:  # exists but cannot be opened: this carrier is unreadable, status goes on
            item.update(fragment="unreadable", identity="n/a", front_matter="n/a", user_content="n/a",
                        host_effect="not verified",
                        next_step=f"Make {path} readable ({exc.strerror or exc}), then re-run status")
            items.append(item)
            continue
        if defn is None:
            state = inspect(data, recorded)
            item.update(fragment={"absent_file": "missing file"}.get(state, state), identity="unknown",
                        front_matter="n/a", user_content="n/a",
                        next_step=f"secure-code init --project {root} --env {profile.name}")
        else:
            named = host if kind == "system-prompt" else None
            body = routing.render(defn, identity, profile, kind, host=named)
            result = plan(kind, path, data, body, recorded, entries.get(kind, {}).get("accepted"), identity)
            plans.append(result)
            if result.state == "blocked":
                unreadable = result.problem.code.endswith("UNREADABLE")
                fragment, ident = ("unreadable" if unreadable else "malformed"), "n/a"
            elif result.state == "kept-differs":
                fragment, ident = ("modified" if result.body_differs else "present"), "n/a"
            else:
                fragment, ident = PLAN_LABELS[result.state]
            step = next_step(result)
            if result.state in ("created", "appended", "updated"):
                step = carriers_step
            item.update(fragment=fragment, identity=ident, front_matter=result.front_matter,
                        user_content=result.user_content, next_step=step)
            if result.difference:
                differences[path] = result.difference
        item["host_effect"] = "not verified"
        items.append(item)
    section: dict[str, Any] = {
        "routing_identity": identity.display() if identity else "unknown",
        "carriers": items,
        "integration_declaration": (declaration(plans, identity) if identity
                                    else "unknown (no valid definition)"),
        "differences": differences,
    }
    if record.carriers:
        section["record_compatibility"] = RECORD_COMPATIBILITY
    return section


def _trivy(root: Path, info: dict[str, Any]) -> dict[str, Any]:
    """Trivy extras (FEATURE-002-D): execution support, component state and on-disk sizes; read-only."""
    from .adapters import digests, registry_store, trivy, trivy_journal

    gap = registry_store.platform_gap("trivy", digests.host_platform())
    execution = "supported" if gap is None else "not supported on this platform in this version"
    out = {**info, "execution": execution}
    if gap is not None and out.get("registered"):
        out["check"] = gap.reason
    try:
        view = trivy_journal.evaluate(root)
    except Exception as exc:  # noqa: BLE001 - status must always render
        view = {"components": {n: {"state": "unreadable", "reason": f"cache not readable: {exc}"}
                               for n in trivy.COMPONENTS}, "recovery_pending": None, "cache": "unreadable"}
    components = {}
    for name, st in view["components"].items():
        item = dict(st)
        if st["state"] == "present":
            item["next_step"] = "None"
        else:
            registry = st.get("registry") if st.get("registry") in trivy.REPOSITORIES else "mirror.gcr.io"
            item["next_step"] = trivy.provision_step(name, registry)
        components[name] = item
    out.update(
        recovery_pending=view["recovery_pending"],
        components=components,
        cache_disk_bytes_total=sum(c.get("disk_bytes") or 0 for c in components.values()
                                   if c["state"] in ("present", "unreadable")),
    )
    if view.get("cache") != "coherent":
        out["cache"] = view.get("cache")
    return out


def _tool(root: Path, name: str) -> dict:
    """Adapter state; a registered binary is hashed, never executed (FEATURE-002-B)."""
    from .adapters import provided

    if name not in provided():
        return {"state": NOT_PROVIDED, "next_step": NOT_PROVIDED_NEXT}
    if name == "trivy":
        return _trivy(root, _registration(root, name))
    return _registration(root, name)


def _registration(root: Path, name: str) -> dict:
    from .adapters import registry_store

    try:
        record = registry_store.load_record(root, name)
        gap = isinstance(record, registry_store.Gap)
        checked = record if gap else registry_store.check(root, name)
    except Exception as exc:  # noqa: BLE001 - status must always render
        return {"state": "provided", "registered": False, "check": f"unreadable: {exc}",
                "next_step": registry_store.register_step(name)}
    if isinstance(record, registry_store.Gap):
        return {"state": "provided", "registered": False, "check": record.reason,
                "next_step": record.next_step}
    info = {"state": "provided", "registered": True, "version": record.get("version"),
            "asset": record.get("asset"), "platform_validated": bool(record.get("platform_validated"))}
    if isinstance(checked, registry_store.Gap):
        return {**info, "check": checked.reason, "next_step": checked.next_step}
    return {**info, "check": "ok", "execution": "supported", "next_step": "None"}


def collect(project: str | None, trust_paths: TrustPaths | None = None) -> Result:
    try:
        root = validate_root(project)
    except RootError as exc:
        return Result.refused(COMMAND, exc.code, exc.message,
                              "Pass an existing project folder with --project PATH")
    problems: list[dict[str, str]] = []
    record, record_error = None, None
    try:
        record = load(root)
    except RecordError as exc:
        record_error = exc

    auth = verify(trust_paths or resolve())
    if auth.state == "invalid":
        problems.append({"code": "TRUST_INVALID", "message": auth.reason})
    local = _count_rules(root / DATA_ROOT / "knowledge" / "local")
    reference = _count_rules(root / DATA_ROOT / "knowledge" / "reference")
    data = {
        "install": _install(root, record, record_error, problems),
        "authorization": auth.to_dict(),
        "policies": {
            "local": local, "reference": reference,
            "next_step": ("Maintainer maintains Policies before use"
                          if local + reference == 0 else "None"),
        },
        "default_preset": {"exists": (root / DATA_ROOT / "presets" / "default.json").is_file()},
        "tools": {name: _tool(root, name) for name in ADAPTERS},
        "host_integration": _host(root, record, problems),
        "problems": problems,
    }
    return Result(COMMAND, True, data)
