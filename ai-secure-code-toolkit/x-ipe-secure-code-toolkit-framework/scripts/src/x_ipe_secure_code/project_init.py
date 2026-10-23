"""Project initialization ("install"): plan everything first, write nothing on refusal."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace as dc_replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, routing
from .atomic import LockHeld, LockUnavailable, ProjectLock, atomic_write_bytes
from .carrier_view import MASK_LABEL, masked_diff, omit_if_unused
from .environments import PROFILES, EnvError, Profile, lookup
from .host_fragment import fragment_text, plan_upsert, render_minimal_body, sha256_text
from .install_record import RECORD_REL, InstallRecord, RecordError, load, save, sha256_file
from .paths import RootError, safe_relative, unsafe_component, validate_root
from .payload import PayloadError, files, locate
from .results import Problem, Result

DATA_ROOT = "x-ipe-docs/secure-code"
LAYOUT = ("knowledge/local", "knowledge/reference", "presets", "tags", "improvements",
          "reports/copilot", "reports/guard")
WRITE_OUTCOMES = ("create", "update", "replace")
COMMAND = "init"
CUSTOMIZED_NOTE = "accepted customization, not synced with the routing definition"


@dataclass(frozen=True)
class FilePlan:
    target_rel: str
    source: Path
    outcome: str  # create | current | update | locally_edited | replace | conflict
    new_sha: str
    recorded_sha: str | None


def _plan_file(root: Path, target_rel: str, source: Path, recorded: str | None,
               replace: set[str]) -> FilePlan:
    target = root / target_rel
    new_sha = sha256_file(source)
    if unsafe_component(root, target_rel, expect_dir=False):
        return FilePlan(target_rel, source, "unsafe", new_sha, recorded)
    if not target.exists():
        return FilePlan(target_rel, source, "create", new_sha, recorded)
    disk = sha256_file(target)
    if disk == new_sha:
        outcome = "current"
    elif recorded is not None and disk == recorded:
        outcome = "update"
    elif recorded is not None:
        outcome = "replace" if target_rel in replace else "locally_edited"
    else:
        outcome = "conflict"
    return FilePlan(target_rel, source, outcome, new_sha, recorded)


def _summary(plans: list[FilePlan]) -> dict[str, list[str]]:
    keys = {"create": "created", "update": "updated", "current": "current",
            "locally_edited": "locally_edited", "replace": "replaced", "conflict": "conflicts",
            "unsafe": "unsafe"}
    summary: dict[str, list[str]] = {name: [] for name in keys.values()}
    for plan in plans:
        summary[keys[plan.outcome]].append(plan.target_rel)
    return summary


def initialize_project(project: str | None, env: str | None, replace: list[str] | None = None,
                       toolkit_source: str | None = None) -> Result:
    try:
        root = validate_root(project)
        profile = lookup(env)
        replace_set = {safe_relative(item) for item in (replace or [])}
        source_root = locate(toolkit_source)
        payload = files(source_root)
    except RootError as exc:
        return Result.refused(COMMAND, exc.code, exc.message,
                              "Pass an existing project folder with --project PATH")
    except EnvError as exc:
        return Result.refused(COMMAND, exc.code, exc.message,
                              f"Re-run with --env {' or --env '.join(PROFILES)}",
                              {"supported_environments": list(PROFILES)})
    except PayloadError as exc:
        return Result.refused(COMMAND, exc.code, exc.message,
                              "Use a complete toolkit folder (--toolkit-source DIR)")
    try:
        payload_defn = _payload_definition(payload)
    except routing.RoutingError as exc:  # present but invalid: refused before the lock and any write
        return Result.refused(COMMAND, "ROUTING_DEFINITION_INVALID",
                              f"The toolkit source's routing definition is invalid: {exc.message}",
                              "Use a complete, unmodified toolkit folder (--toolkit-source DIR)")
    if not ProjectLock.available(root):  # Windows / no flock: exactly the FEATURE-001-A path
        return _locked_body(root, profile, replace_set, payload, payload_defn)
    try:
        with ProjectLock(root):
            return _locked_body(root, profile, replace_set, payload, payload_defn)
    except LockHeld:
        return Result.refused(COMMAND, "LOCKED",
                              "Another secure-code init or carriers run holds the project lock",
                              "Retry when the other run has finished; nothing was written")
    except LockUnavailable:
        return _locked_body(root, profile, replace_set, payload, payload_defn)


def _payload_definition(payload: dict[str, Path]) -> routing.RoutingDefinition | None:
    """None for a FEATURE-001-A-era payload (no definition); RoutingError if present but invalid."""
    source = payload.get(routing.DEFINITION_REL)
    return None if source is None else routing.load_file(source)


def _locked_body(root: Path, profile: Profile, replace: set[str], payload: dict[str, Path],
                 payload_defn: routing.RoutingDefinition | None) -> Result:
    try:
        record = load(root)
    except RecordError as exc:
        return Result.refused(COMMAND, exc.code, str(exc),
                              f"Inspect {RECORD_REL}; it is not repaired automatically")
    return _plan_and_apply(root, profile, replace, payload, record, payload_defn)


def _host_body(root: Path, profile: Profile, plans: list[FilePlan],
               payload_defn: routing.RoutingDefinition | None) -> tuple[str, routing.RoutingIdentity | None]:
    """The host entry body from the effective installed definition (FEATURE-001-A text without one)."""
    if payload_defn is None:
        return render_minimal_body(profile), None
    defn = payload_defn
    target = f"{profile.skills_dir}/{routing.DEFINITION_REL}"
    if any(p.target_rel == target and p.outcome == "locally_edited" for p in plans):
        try:
            defn = routing.load_file(root / target)  # a valid Maintainer edit stays in force
        except routing.RoutingError:
            defn = payload_defn
    identity = routing.RoutingIdentity(__version__, defn.digest)
    return routing.render(defn, identity, profile, "host-entry"), identity


def _accepted_host_entry(record: InstallRecord | None, profile: Profile) -> dict[str, Any] | None:
    """The accepted host-entry customization of a valid member of the same environment, else None."""
    if record is None or not record.carriers or record.environment != profile.name:
        return None
    return record.carriers.get("entries", {}).get("host-entry", {}).get("accepted")


def _without_host_entry_acceptance(member: dict[str, Any]) -> dict[str, Any] | None:
    entries = {k: v for k, v in member.get("entries", {}).items() if k != "host-entry"}
    return omit_if_unused({**member, "entries": entries})


def _plan_and_apply(root: Path, profile: Profile, replace: set[str], payload: dict[str, Path],
                    record: InstallRecord | None, payload_defn: routing.RoutingDefinition | None) -> Result:
    recorded_files = record.files if record else {}
    plans = [
        _plan_file(root, f"{profile.skills_dir}/{rel}", source,
                   recorded_files.get(f"{profile.skills_dir}/{rel}"), replace)
        for rel, source in payload.items()
    ]
    host = root / profile.host_entry
    recorded_fragment = (record.fragment_sha256
                         if record and record.host_entry == profile.host_entry else None)
    problems: list[Problem] = []
    exception: dict[str, Any] = {}
    member = record.carriers if record and record.environment == profile.name else None
    host_unsafe = unsafe_component(root, profile.host_entry, expect_dir=False)
    if host_unsafe:
        problems.append(Problem("PATH_UNSAFE", f"Host entry file: {host_unsafe}"))
        fragment = None
    else:
        data = host.read_bytes() if host.exists() else None
        body, identity = _host_body(root, profile, plans, payload_defn)
        fragment = plan_upsert(data, body, recorded_fragment, profile.host_entry in replace)
        fragment, member = _accepted_exception(root, record, profile, data, body, identity, fragment,
                                               replace, member, exception)
        if fragment.problem:
            problems.append(fragment.problem)
    conflicts = [p.target_rel for p in plans if p.outcome == "conflict"]
    for target_rel in conflicts:
        problems.append(Problem("SKILL_NAME_CONFLICT",
                                f"{target_rel} exists and was not placed by this toolkit"))
    for plan in plans:
        if plan.outcome == "unsafe":
            reason = unsafe_component(root, plan.target_rel, expect_dir=False)
            problems.append(Problem("PATH_UNSAFE", f"Skill file {plan.target_rel}: {reason}"))
    for rel, expect_dir in [(RECORD_REL, False)] + [(f"{DATA_ROOT}/{d}", True) for d in LAYOUT]:
        reason = unsafe_component(root, rel, expect_dir=expect_dir)
        if reason:
            problems.append(Problem("PATH_UNSAFE", reason))
    blocked = any(p.code == "PATH_UNSAFE" for p in problems)
    summary = _summary(plans)
    data = {"root": str(root), "environment": profile.name, "skills_dir": profile.skills_dir,
            "host_entry": profile.host_entry, "files": summary,
            "fragment": fragment.outcome if fragment else "blocked"}
    if conflicts or blocked or fragment is None or fragment.blocking:
        return Result(COMMAND, False, data, problems,
                      ["Resolve the listed problems; nothing was written"])

    written: list[str] = []
    layout_created: list[str] = []
    try:
        for plan in plans:
            if plan.outcome in WRITE_OUTCOMES:
                atomic_write_bytes(root / plan.target_rel, plan.source.read_bytes())
                written.append(plan.target_rel)
        for rel in LAYOUT:
            folder = root / DATA_ROOT / rel
            if not folder.is_dir():
                folder.mkdir(parents=True, exist_ok=True)
                layout_created.append(f"{DATA_ROOT}/{rel}")
        if fragment.new_bytes is not None:
            atomic_write_bytes(host, fragment.new_bytes)
            written.append(profile.host_entry)
    except OSError as exc:
        data.update({"written_before_failure": written, "layout_created": layout_created})
        problems.append(Problem("IO_ERROR", f"Writing failed: {exc.strerror or exc}; "
                                            "the install record was not updated"))
        return Result(COMMAND, False, data, problems,
                      ["Fix the file-system problem and re-run; already written files that "
                       "match the toolkit are recognized as current"])

    file_hashes = {p.target_rel: (p.recorded_sha if p.outcome == "locally_edited" else p.new_sha)
                   for p in plans}
    kept = fragment.outcome in ("edited_kept", "customized")
    fragment_sha = recorded_fragment if kept else fragment.inner_sha
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_record = InstallRecord(
        toolkit_version=__version__, environment=profile.name, skills_dir=profile.skills_dir,
        host_entry=profile.host_entry, fragment_sha256=fragment_sha,
        initialized_at=record.initialized_at if record else now, updated_at=now,
        files=file_hashes, carriers=member)
    if (record is None or record.comparable() != new_record.comparable()
            or record.carriers != new_record.carriers):
        try:
            save(root, new_record)
        except OSError as exc:
            data.update({"written_before_failure": written})
            problems.append(Problem("IO_ERROR", f"Writing the install record failed: "
                                                f"{exc.strerror or exc}"))
            return Result(COMMAND, False, data, problems, ["Fix the file-system problem and re-run"])

    for target_rel in summary["locally_edited"]:
        problems.append(Problem("LOCALLY_EDITED",
                                f"{target_rel} was edited locally and was kept"))
    wrote = any(p.outcome in WRITE_OUTCOMES for p in plans) or fragment.new_bytes is not None
    data.update({"layout_created": layout_created, "record": RECORD_REL,
                 "already_current": not wrote and not layout_created and fragment.outcome != "customized"})
    data.update(exception.get("data", {}))
    next_steps = ["Owner runs 'secure-code auth init' in a terminal if not yet authorized",
                  f"Check status: secure-code status --project {root}"]
    if summary["locally_edited"] or fragment.outcome == "edited_kept":
        next_steps.insert(0, "Review the kept local edits; re-run with --replace PATH for each "
                             "file that should take the toolkit version")
    if "problem" in exception:
        problems.append(exception["problem"])
        next_steps.insert(0, exception["next_step"])
    return Result(COMMAND, True, data, problems, next_steps)


def _accepted_exception(root, record, profile, data, body, identity, fragment, replace, member, exception):
    """The single plain-init exception (FEATURE-003-B, DAO-003/DAO-004): an exactly matching accepted
    host-entry customization is kept and reported as customized; an explicit --replace lapses it."""
    accepted = _accepted_host_entry(record, profile)
    if accepted is None or data is None:
        return fragment, member
    inner = fragment_text(data.decode("utf-8")) if fragment.outcome in ("edited_kept", "replaced") else None
    if inner is None:
        return fragment, member
    if profile.host_entry not in replace and fragment.outcome == "edited_kept":
        if sha256_text(inner) != accepted["fragment_sha256"]:
            return fragment, member  # edited again after acceptance: FEATURE-001-A FRAGMENT_EDITED
        exception["data"] = {"fragment": "customized", "fragment_note": CUSTOMIZED_NOTE}
        if identity is None or accepted["routing"] != identity.to_dict():
            was = routing.RoutingIdentity.from_dict(accepted["routing"]).display()
            now_text = identity.display() if identity else "not installed"
            exception["problem"] = Problem(
                "CUSTOMIZATION_ROUTING_CHANGED",
                f"The accepted {profile.host_entry} customization was accepted against routing identity "
                f"{was}; the routing definition is now {now_text}")
            exception["next_step"] = (f"Decide the accepted customization: secure-code carriers --project "
                                      f"{root} --env {profile.name} (keep, "
                                      "--regenerate host-entry or --accept host-entry)")
        return dc_replace(fragment, outcome="customized", problem=None), member
    if profile.host_entry in replace and fragment.outcome == "replaced":
        diff, kinds = masked_diff(inner, body, "fragment")
        exception["data"] = {"replaced_customization": {
            "statement": (f"An accepted customization of {profile.host_entry} was replaced with the toolkit "
                          "rendering (explicit --replace); the acceptance no longer applies"),
            "content": MASK_LABEL, "masked_kinds": kinds, "diff": diff}}
        return fragment, _without_host_entry_acceptance(member or {})
    return fragment, member
