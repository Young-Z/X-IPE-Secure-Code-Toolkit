"""`secure-code carriers`: generate, check and decide the host integration carriers (FEATURE-003-B).

Plan every selected carrier first; refuse the whole run on any blocking plan; then write the planned
carriers atomically in a fixed order and the install record last. Writes only carrier files and the
install record (never the skills folder), always under the file-free project lock.
"""

from __future__ import annotations

import re
from dataclasses import replace as dc_replace
from pathlib import Path
from typing import Any

from . import __version__, routing
from .atomic import LockHeld, LockUnavailable, ProjectLock, atomic_write_bytes
from .carrier_view import (
    NO_LONGER_MANAGED_STEP,
    SUPPORTED,
    WRITTEN,
    CarrierPlan,
    carrier_path,
    declaration,
    next_step,
    now,
    omit_if_unused,
    plan,
)
from .environments import PROFILES, EnvError, Profile, lookup
from .guard.mask import mask_text
from .install_record import RECORD_REL, InstallRecord, RecordError, load, save
from .paths import RootError, unsafe_component, validate_root
from .payload import SKILL_NAMES
from .results import Problem, Result

COMMAND = "carriers"
HOST_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
HOST_EFFECT = "written / component-checked; host effect not verified"
MANUAL_STEP = (
    "Adding this fragment to the host's system prompt is your manual step; the toolkit never "
    "changes host, global or user-level configuration"
)
NOTICE = (
    "The install record now holds the optional 'carriers' member. Toolkit versions without the carriers "
    "operation cannot read this record and refuse it (RECORD_INVALID)."
)


class _Refusal(Exception):
    def __init__(self, result: Result) -> None:
        super().__init__(result.problems[0].message if result.problems else "refused")
        self.result = result


def _refuse(code: str, message: str, step: str | None, data: dict[str, Any] | None = None) -> _Refusal:
    return _Refusal(Result.refused(COMMAND, code, message, step, data))


def _canonical(kinds, profile: Profile) -> list[str]:
    return [kind for kind in SUPPORTED[profile.name] if kind in kinds]


def run(
    project: str | None,
    env: str | None,
    *,
    select: list[str] | None = None,
    deselect: list[str] | None = None,
    regenerate: list[str] | None = None,
    accept: list[str] | None = None,
    host: str | None = None,
) -> Result:
    select, deselect = list(select or []), list(deselect or [])
    regenerate, accept = list(regenerate or []), list(accept or [])
    try:
        root = validate_root(project)
    except RootError as exc:
        return Result.refused(
            COMMAND, exc.code, exc.message, "Pass an existing project folder with --project PATH"
        )
    try:
        profile = lookup(env)
    except EnvError as exc:
        return Result.refused(
            COMMAND,
            exc.code,
            exc.message,
            f"Re-run with --env {' or --env '.join(PROFILES)}",
            {"supported_environments": list(PROFILES)},
        )
    try:
        _check_arguments(profile, select, deselect, regenerate, accept, host)
        with ProjectLock(root):
            return _locked(root, profile, select, deselect, regenerate, accept, host)
    except _Refusal as refusal:
        return refusal.result
    except LockHeld:
        return Result.refused(
            COMMAND,
            "LOCKED",
            "Another secure-code init or carriers run holds the project lock",
            "Retry when the other run has finished; nothing was written",
        )
    except LockUnavailable:
        return Result.refused(
            COMMAND,
            "LOCK_UNAVAILABLE",
            "The file-free project lock is not available on this platform or file system, so the carriers "
            "operation does not run (interim behaviour; Windows support is open gap B11, pending a human "
            "decision). No lock file was created and nothing was written.",
            "Run the carriers operation on a local POSIX file system meanwhile; plain init is unaffected",
        )


def _check_arguments(profile: Profile, select, deselect, regenerate, accept, host) -> None:
    supported = list(SUPPORTED[profile.name])
    unknown = [kind for kind in [*select, *deselect, *regenerate, *accept] if kind not in supported]
    if unknown:
        raise _refuse(
            "CARRIER_UNSUPPORTED",
            f"Carrier(s) {', '.join(dict.fromkeys(unknown))} not supported for {profile.name}; "
            f"supported: {', '.join(supported)}",
            "Use one of the listed carriers",
            {"supported_carriers": supported},
        )
    if select and deselect:
        raise _refuse("ARGUMENT_INVALID", "--select and --deselect cannot be combined", "Use one of them")
    if "host-entry" in deselect:
        raise _refuse(
            "ARGUMENT_INVALID",
            f"The host entry carrier ({profile.host_entry}) cannot be deselected; "
            "it is the FEATURE-001-A fragment that init keeps",
            "Deselect only optional carriers",
        )
    both = set(regenerate) & set(accept)
    if both:
        raise _refuse(
            "ARGUMENT_INVALID",
            f"{', '.join(sorted(both))}: choose either --regenerate or --accept",
            "Give one decision per carrier",
        )
    if host is not None and not HOST_NAME.fullmatch(host):
        raise _refuse(
            "ARGUMENT_INVALID",
            f"Invalid host name '{host}' (lowercase letters, digits, '.', '_', '-')",
            "Pass --system-prompt-host NAME, e.g. copilot-cli",
        )


def _load_record(root: Path, profile: Profile) -> InstallRecord:
    init_step = f"secure-code init --project {root} --env {profile.name}"
    try:
        record = load(root)
    except RecordError as exc:
        raise _refuse(exc.code, str(exc), f"Inspect {RECORD_REL}; it is not repaired automatically") from None
    if record is None:
        raise _refuse("PROJECT_NOT_INITIALIZED", f"{root} is not initialized for the toolkit", init_step)
    if record.environment != profile.name:
        raise _refuse(
            "ENV_MISMATCH",
            f"The install record is for {record.environment}, not {profile.name}; "
            "one install record covers one environment",
            init_step,
        )
    return record


def _check_installed(root: Path, profile: Profile) -> routing.RoutingDefinition:
    init_step = f"secure-code init --project {root} --env {profile.name}"
    for name in SKILL_NAMES:
        rel = f"{profile.skills_dir}/{name}/SKILL.md"
        path = root / rel
        try:
            if unsafe_component(root, rel, expect_dir=False) or not path.is_file():
                raise OSError("missing or not a regular file")
            path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise _refuse(
                "SKILLS_INVALID",
                f"Installed skill {rel} is missing or unreadable ({exc}); the carriers "
                "operation never reinstalls skills",
                init_step,
            ) from None
    rel = f"{profile.skills_dir}/{routing.DEFINITION_REL}"
    try:
        if unsafe_component(root, rel, expect_dir=False):
            raise routing.RoutingError("ROUTING_DEFINITION_INVALID", f"{rel} is not a regular file")
        return routing.load_file(root / rel)
    except routing.RoutingError as exc:
        raise _refuse(
            "ROUTING_DEFINITION_INVALID",
            f"{rel}: {exc.message}",
            f"{init_step}; if you edited the definition, fix it or re-run init with --replace {rel}",
        ) from None


def _selection(record: InstallRecord, profile: Profile, select, deselect) -> tuple[list[str], list[str]]:
    member = record.carriers or {}
    stored = list(member.get("selected", ["host-entry"]))
    if select:
        new = _canonical(["host-entry", *select], profile)
    elif deselect:
        new = _canonical([k for k in stored if k not in deselect], profile)
    else:
        new = _canonical(stored, profile)
    known = set(stored) | {k for k in member.get("entries", {}) if k != "host-entry"}
    return new, [k for k in SUPPORTED[profile.name] if k in known and k not in new]


def _locked(root: Path, profile: Profile, select, deselect, regenerate, accept, host) -> Result:
    record = _load_record(root, profile)
    selected, no_longer = _selection(record, profile, select, deselect)
    entries = dict((record.carriers or {}).get("entries", {}))
    outside = [kind for kind in [*regenerate, *accept] if kind not in selected]
    if outside:
        raise _refuse(
            "ARGUMENT_INVALID", f"{', '.join(outside)} is not a selected carrier", "Select it first"
        )
    stored_host = entries.get("system-prompt", {}).get("host")
    if host is not None and "system-prompt" not in selected:
        raise _refuse(
            "ARGUMENT_INVALID",
            "--system-prompt-host needs the system-prompt carrier selected",
            "Add --select system-prompt",
        )
    host = host or stored_host
    if "system-prompt" in selected and not host:
        raise _refuse(
            "ARGUMENT_INVALID",
            "The system-prompt fragment needs an explicitly named host",
            "Re-run with --system-prompt-host NAME (e.g. copilot-cli)",
        )
    defn = _check_installed(root, profile)
    identity = routing.RoutingIdentity(__version__, defn.digest)
    unsafe = [
        f"{rel}: {reason}"
        for rel in [RECORD_REL, *(carrier_path(k, profile) for k in selected)]
        if (reason := unsafe_component(root, rel, expect_dir=False))
    ]
    if unsafe:
        return Result(
            COMMAND,
            False,
            {"root": str(root), "environment": profile.name},
            [Problem("PATH_UNSAFE", item) for item in unsafe],
            ["Replace the symbolic link with a regular file or folder; nothing was written"],
        )
    plans = [
        _plan_kind(root, profile, record, entries, kind, defn, identity, host, regenerate, accept)
        for kind in selected
    ]
    blocked = [p for p in plans if p.blocking]
    if blocked:
        return Result(
            COMMAND,
            False,
            {"root": str(root), "environment": profile.name},
            [p.problem for p in blocked],
            ["Fix the named carriers; nothing was written"],
        )
    written: list[str] = []
    try:
        for item in plans:
            if item.new_bytes is not None:
                atomic_write_bytes(root / item.path, item.new_bytes)
                written.append(item.path)
    except OSError as exc:
        return Result(
            COMMAND,
            False,
            {"root": str(root), "environment": profile.name, "written_before_failure": written},
            [
                Problem(
                    "IO_ERROR", f"Writing failed: {exc.strerror or exc}; the install record was not updated"
                )
            ],
            ["Fix the file-system problem and re-run; written carriers are recognized as current"],
        )
    new_record = _new_record(record, profile, selected, entries, plans, identity, host)
    record_written = record.full_comparable() != new_record.full_comparable()
    if record_written:
        try:
            save(root, new_record)
        except OSError as exc:
            return Result(
                COMMAND,
                False,
                {"root": str(root), "environment": profile.name, "written_before_failure": written},
                [Problem("IO_ERROR", f"Writing the install record failed: {exc.strerror or exc}")],
                ["Fix the file-system problem and re-run"],
            )
    return _result(root, profile, plans, no_longer, identity, defn, host, new_record, record_written)


def _plan_kind(root, profile, record, entries, kind, defn, identity, host, regenerate, accept) -> CarrierPlan:
    rel = carrier_path(kind, profile)
    path = root / rel
    try:
        data = path.read_bytes() if path.is_file() else None
    except OSError as exc:  # exists but cannot be opened: blocked like a non-UTF-8 carrier
        code = "HOST_ENTRY_UNREADABLE" if kind == "host-entry" else "CARRIER_UNREADABLE"
        reason = f"{rel}: the carrier file cannot be read ({exc.strerror or exc})"
        return CarrierPlan(kind, rel, "blocked", problem=Problem(code, reason))
    if kind == "host-entry":
        recorded = record.fragment_sha256 if record.host_entry == profile.host_entry else None
    else:
        recorded = entries.get(kind, {}).get("fragment_sha256")
    accepted = entries.get(kind, {}).get("accepted")
    body = routing.render(defn, identity, profile, kind, host=host if kind == "system-prompt" else None)
    decision = "regenerate" if kind in regenerate else None
    base = plan(kind, rel, data, body, recorded, accepted, identity, decision)
    if kind in accept:
        if base.state != "kept-differs":
            raise _refuse(
                "DECISION_NOT_APPLICABLE",
                f"{rel} has no reported difference to accept (state {base.state})",
                "Only accept a reported difference; nothing was written",
            )
        return plan(kind, rel, data, body, recorded, accepted, identity, "accept")
    return base


def _new_record(
    record: InstallRecord,
    profile: Profile,
    selected: list[str],
    entries: dict[str, Any],
    plans: list[CarrierPlan],
    identity: routing.RoutingIdentity,
    host: str | None,
) -> InstallRecord:
    fragment_sha = record.fragment_sha256
    new_entries = {k: v for k, v in entries.items() if k != "host-entry"}
    for item in plans:
        synced = item.state in WRITTEN
        if item.kind == "host-entry":
            if synced:
                fragment_sha = item.rendered_sha
            if item.accepted and item.state in ("customized", "kept-differs"):
                new_entries["host-entry"] = {"accepted": item.accepted}
            continue
        old = entries.get(item.kind, {})
        entry: dict[str, Any] = {
            "path": item.path,
            "fragment_sha256": item.rendered_sha if synced else old.get("fragment_sha256"),
            "routing": identity.to_dict() if synced or "routing" not in old else old["routing"],
        }
        if item.kind == "system-prompt":
            entry["host"] = host
        if item.accepted and item.state in ("customized", "kept-differs"):
            entry["accepted"] = item.accepted
        new_entries[item.kind] = entry
    ordered = {k: new_entries[k] for k in SUPPORTED[profile.name] if k in new_entries}
    member = omit_if_unused({"selected": selected, "entries": ordered})
    return dc_replace(record, fragment_sha256=fragment_sha, carriers=member, updated_at=now())


def _result(root, profile, plans, no_longer, identity, defn, host, new_record, record_written) -> Result:
    carriers: list[dict[str, Any]] = []
    differences: dict[str, Any] = {}
    problems = [p.problem for p in plans if p.problem]
    for item in plans:
        entry = {
            "carrier": item.kind,
            "path": item.path,
            "selection": "selected",
            "state": item.state,
            "front_matter": item.front_matter,
            "user_content": item.user_content,
            "next_step": next_step(item),
        }
        if item.note:
            entry["note"] = item.note
        carriers.append(entry)
        if item.difference:
            differences[item.path] = item.difference
    for kind in no_longer:
        carriers.append(
            {
                "carrier": kind,
                "path": carrier_path(kind, profile),
                "selection": "no longer managed",
                "state": "no longer managed",
                "front_matter": "n/a",
                "user_content": "n/a",
                "next_step": NO_LONGER_MANAGED_STEP,
            }
        )
    order = list(SUPPORTED[profile.name])
    carriers.sort(key=lambda c: order.index(c["carrier"]))
    data: dict[str, Any] = {
        "root": str(root),
        "environment": profile.name,
        "routing_identity": identity.display(),
        "carriers": carriers,
        "integration_declaration": declaration(plans, identity),
        "differences": differences,
    }
    selected = {p.kind for p in plans}
    if "system-prompt" in selected:
        body = routing.render(defn, identity, profile, "system-prompt", host=host)
        data["system_prompt"] = {
            "path": carrier_path("system-prompt", profile),
            "host": host,
            "content": mask_text(body)[0].splitlines(),
            "manual_step": MANUAL_STEP,
        }
    data.update({"record": RECORD_REL, "record_written": record_written, "host_effect": HOST_EFFECT})
    if new_record.carriers:
        data["notices"] = [NOTICE]
    steps = [next_step(p) for p in plans if p.state in ("kept-differs", "customized")]
    return Result(COMMAND, True, data, problems, steps or ["None"])
