"""Per-carrier planning and inspection, shared by `secure-code carriers` and status (FEATURE-003-B).

Every body change goes through the FEATURE-001-A writer (`host_fragment.plan_upsert`); this module adds
only the accepted-customization branch, the instructions front-matter boundary and masked differences.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import host_fragment as hf
from .environments import Profile
from .guard.mask import mask_text
from .install_record import CARRIER_KINDS, CARRIER_PATHS
from .results import Problem
from .routing import RoutingIdentity

INSTRUCTIONS = "github-instructions"
SUPPORTED = {"github-copilot": CARRIER_KINDS, "claude-code": ("host-entry", "system-prompt")}
MASK_LABEL = "secret-masked (pattern-based; not a complete data-loss-prevention guarantee)"
DIFF_LINE_LIMIT = 400
USER_CONTENT = "detected outside the managed boundaries (kept)"
NO_LONGER_MANAGED_STEP = (
    "Left in place; remove it manually if no longer wanted (the toolkit never deletes carriers)"
)
SIMILAR_NOTE = "similar toolkit text found outside the fragment; it is user content and was not taken over"
WRITTEN = ("created", "appended", "current", "updated", "replaced")


def carrier_path(kind: str, profile: Profile) -> str:
    return profile.host_entry if kind == "host-entry" else CARRIER_PATHS[kind]


def choices(kind: str) -> list[str]:
    return [
        "keep (default)",
        "modify, then keep or accept",
        "change the routing definition",
        f"regenerate (--regenerate {kind})",
        f"accept customization (--accept {kind})",
    ]


def masked_diff(current: str, rendered: str, label: str) -> tuple[list[str], list[str]]:
    """Unified diff of the masked current text against the masked toolkit text."""
    cur, kinds_current = mask_text(current.replace("\r\n", "\n"))
    new, kinds_new = mask_text(rendered.replace("\r\n", "\n"))
    lines = list(
        difflib.unified_diff(
            cur.splitlines(),
            new.splitlines(),
            fromfile=f"current {label} (masked)",
            tofile=f"toolkit {label}",
            lineterm="",
            n=2,
        )
    )
    lines = [mask_text(line)[0] for line in lines]
    if len(lines) > DIFF_LINE_LIMIT:
        lines = lines[:DIFF_LINE_LIMIT] + [
            f"… truncated after {DIFF_LINE_LIMIT} lines; open the file to see the rest"
        ]
    return lines, sorted(set(kinds_current) | set(kinds_new))


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CarrierPlan:
    kind: str
    path: str
    state: str  # created|appended|current|updated|kept-differs|replaced|customized|blocked
    new_bytes: bytes | None = None
    rendered_sha: str | None = None
    problem: Problem | None = None
    accepted: dict[str, Any] | None = None
    front_matter: str = "n/a"
    user_content: str = "n/a"
    difference: dict[str, Any] | None = None
    note: str | None = None
    body_differs: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        return self.state == "blocked"


def _front_matter_region_text(text: str, state: str, region: tuple[int, int] | None) -> str:
    """The front matter at file start (ok or altered); a moved or missing block leaves none there."""
    return text[region[0] : region[1]] if region is not None and state in ("ok", "altered") else ""


def _difference(
    kind: str,
    inner: str | None,
    body: str,
    *,
    replaced: bool = False,
    front_matter: tuple[str, str] | None = None,
) -> dict[str, Any]:
    diff, kinds = masked_diff(inner or "", body, "fragment") if inner is not None else ([], [])
    result: dict[str, Any] = {"content": MASK_LABEL, "masked_kinds": kinds, "diff": diff}
    if front_matter is not None:
        fm_diff, fm_kinds = masked_diff(front_matter[0], front_matter[1], "front matter")
        result["front_matter_diff"] = fm_diff
        result["masked_kinds"] = sorted(set(kinds) | set(fm_kinds))
    if replaced:
        result["replaced"] = True
    else:
        result["choices"] = choices(kind)
    return result


def _acceptance(inner: str, identity: RoutingIdentity, kind: str, fm_text: str | None) -> dict[str, Any]:
    accepted: dict[str, Any] = {
        "fragment_sha256": hf.sha256_text(inner),
        "routing": identity.to_dict(),
        "accepted_at": now(),
    }
    if kind == INSTRUCTIONS:
        accepted["front_matter_sha256"] = hf.sha256_text(fm_text) if fm_text else None
    return accepted


def _accepted_matches(
    accepted: dict[str, Any] | None, inner: str, identity: RoutingIdentity, kind: str, fm_text: str | None
) -> bool:
    if not accepted or accepted.get("fragment_sha256") != hf.sha256_text(inner):
        return False
    if accepted.get("routing") != identity.to_dict():
        return False
    if kind == INSTRUCTIONS and "front_matter_sha256" in accepted:
        return accepted["front_matter_sha256"] == (hf.sha256_text(fm_text) if fm_text else None)
    return True


def plan(
    kind: str,
    path: str,
    data: bytes | None,
    body: str,
    recorded_sha: str | None,
    accepted: dict[str, Any] | None,
    identity: RoutingIdentity,
    decision: str | None = None,
) -> CarrierPlan:
    """One carrier's state and new bytes (design: Algorithms and State Transitions, steps 1…11)."""
    rendered = hf.sha256_text(body)
    result = CarrierPlan(kind, path, "blocked", rendered_sha=rendered)
    instructions = kind == INSTRUCTIONS
    if instructions:
        result.front_matter, result.user_content = "ok", "none"
    if data is None:  # 1. created
        block = hf.plan_upsert(None, body, None, False).new_bytes
        result.state = "created"
        result.new_bytes = (hf.FRONT_MATTER + "\n").encode("utf-8") + block if instructions else block
        return result
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:  # 2. blocked (not UTF-8)
        code = "HOST_ENTRY_UNREADABLE" if kind == "host-entry" else "CARRIER_UNREADABLE"
        result.problem = Problem(code, f"{path}: the carrier file is not UTF-8")
        return result
    probe = hf.plan_upsert(data, body, recorded_sha, False)
    if probe.blocking:  # 3. blocked (markers)
        result.problem = Problem(probe.problem.code, f"{path}: {probe.problem.message}")
        return result
    inner = hf.fragment_text(text)
    if instructions:
        result.user_content = USER_CONTENT if hf.user_content_outside(text) else "none"
    if inner is None and _similar_outside(text, body):
        result.note = SIMILAR_NOTE
    fm_state, region = hf.front_matter_state(text) if instructions else ("ok", None)
    fm_text = _front_matter_region_text(text, fm_state, region) if instructions else None
    result.body_differs = inner is not None and hf.sha256_text(inner) != rendered
    if fm_state != "ok":  # 4. front-matter drift
        result.front_matter = f"drift: {fm_state}"
        drift = (fm_text or "", hf.FRONT_MATTER)
        if decision == "regenerate":
            regenerated = hf.plan_upsert(data, body, recorded_sha, True).new_bytes
            new_text = regenerated.decode("utf-8") if regenerated is not None else text
            state, new_region = hf.front_matter_state(new_text)
            result.state, result.front_matter = "replaced", "ok"
            result.new_bytes = hf.restore_front_matter(new_text, state, new_region).encode("utf-8")
            result.difference = _difference(kind, inner, body, replaced=True, front_matter=drift)
            return result
        if decision == "accept":
            result.state, result.accepted = "customized", _acceptance(inner or "", identity, kind, fm_text)
            return result
        if _accepted_matches(accepted, inner or "", identity, kind, fm_text):
            result.state, result.accepted = "customized", accepted
            return result
        result.state, result.accepted = "kept-differs", accepted
        result.problem = Problem(
            "FRONT_MATTER_DRIFT", f"{path}: the toolkit front matter is {fm_state}; the file was kept"
        )
        result.difference = _difference(
            kind, inner if result.body_differs else None, body, front_matter=drift
        )
        return result
    if inner is None:  # 5. appended
        result.state, result.new_bytes = "appended", probe.new_bytes
        return result
    if not result.body_differs:  # 6. current
        result.state = "current"
        return result
    if decision == "regenerate":  # 7. replaced
        result.state = "replaced"
        result.new_bytes = hf.plan_upsert(data, body, recorded_sha, True).new_bytes
        result.difference = _difference(kind, inner, body, replaced=True)
        return result
    if _accepted_matches(accepted, inner, identity, kind, fm_text):  # 8. customized
        result.state, result.accepted = "customized", accepted
        return result
    if probe.outcome == "update":  # 9. unedited fragment, new rendering
        result.state, result.new_bytes = "updated", probe.new_bytes
        return result
    if decision == "accept":  # 10. accept
        result.state, result.accepted = "customized", _acceptance(inner, identity, kind, fm_text)
        return result
    result.state, result.accepted = "kept-differs", accepted  # 11. kept, reported
    result.problem = Problem(
        "FRAGMENT_EDITED", f"{path}: the toolkit fragment differs from the toolkit rendering and was kept"
    )
    result.difference = _difference(kind, inner, body)
    return result


def _similar_outside(text: str, body: str) -> bool:
    lines = body.splitlines()
    identity_line = lines[2] if len(lines) > 2 else ""
    return bool(lines) and (lines[0] in text or (identity_line and identity_line in text))


def next_step(plan_: CarrierPlan) -> str:
    kind = plan_.kind
    if plan_.state == "kept-differs":
        if plan_.front_matter.startswith("drift"):
            return (
                f"Decide: keep (default), --regenerate {kind} restores the front matter and the body, "
                f"or --accept {kind}"
            )
        return (
            f"Decide: keep (default), modify then keep or accept, change the routing definition, "
            f"--regenerate {kind}, or --accept {kind}"
        )
    if plan_.state == "customized":
        return (
            f"customized (accepted) — not synced with the routing definition; "
            f"--regenerate {kind} takes the toolkit version"
        )
    if plan_.state == "blocked":
        return "Fix the named carrier; nothing was written"
    return "None"


def omit_if_unused(member: dict[str, Any] | None) -> dict[str, Any] | None:
    """The member is kept only while an optional carrier has an entry or a customization is accepted."""
    if not member:
        return None
    entries = member.get("entries", {})
    optional = any(kind != "host-entry" for kind in entries)
    accepted = any("accepted" in entry for entry in entries.values())
    return member if optional or accepted else None


def declaration(plans: list[CarrierPlan], identity: RoutingIdentity) -> str:
    """The managed carriers that share the current routing identity form one integration declaration."""
    synced = [p.path for p in plans if p.state in WRITTEN]
    other = [p.path for p in plans if p.state not in WRITTEN]
    count = len(synced)
    verb = "share" if count != 1 else "has"
    form = "form" if count != 1 else "forms"
    text = (
        f"{count} managed carrier{'s' if count != 1 else ''} {verb} routing identity {identity.display()} "
        f"and {form} one integration declaration: {', '.join(synced) or 'none'}"
    )
    if other:
        text += f"; not synced with the routing definition: {', '.join(other)}"
    return text
