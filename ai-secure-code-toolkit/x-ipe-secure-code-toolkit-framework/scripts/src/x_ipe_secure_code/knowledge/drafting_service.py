"""`knowledge draft-check` and `knowledge draft-approve` (FEATURE-001-G, FR-001G-2, FR-001G-3).

`draft-check` is read-only. `draft-approve` (Maintainer) recomputes the check, refuses on any
difference from the shown `validation_digest`, stages exactly the reviewed payload in an owner-only
lease-held staging area and calls the delivered, unchanged `update_rule` — the only path by which
drafted content enters formal knowledge. No knowledge lock is held across that call. Narrowed
exact-bytes claim (DAO-015): a same-account process that swaps the staged file between the final
re-read and `update_rule`'s own open is detected after the write and reported `WRITE_MISMATCH`.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..auth.service import require_maintainer
from ..auth.trust_store import TrustPaths
from ..paths import unsafe_component
from ..projects import knowledge_root
from ..results import Problem, Result
from . import drafting_blocks as blocks
from . import drafting_mask, durable, exit_journal, service, store
from .batch import DIGEST, UPDATE_SCHEMA
from .drafting_model import read_nofollow
from .drafting_pipeline import STALE_STEP, Refusal, Report, run
from .identity import IdentityError, RuleRef

CHECK = "knowledge draft-check"
APPROVE = "knowledge draft-approve"
STAGING_REL = f"{store.PRIVATE_REL}/drafting-staging"
LEASE = re.compile(r"lease-([0-9a-f]{32})\.lock")
PAYLOAD = re.compile(r"\.?payload-([0-9a-f]{32})\.json(?:\.tmp)?")
FINGERPRINT = re.compile(r"[0-9a-f]{16}")
CHECK_AGAIN = "Run knowledge draft-check again and show the new report"
FP_STEP = "Declare exactly the listed findings as --false-positive RULE:FINGERPRINT for this rule"
_counts: dict[str, int] = {}


def _crash_point(name: str) -> None:
    """Test-only (`SECURE_CODE_TEST_CRASH_AT=<point>[@n]`), same semantics as the delivered store hook."""
    point, _, nth = os.environ.get(store.CRASH_ENV, "").partition("@")
    if point == name:
        _counts[name] = _counts.get(name, 0) + 1
        if _counts[name] == int(nth or 1):
            os._exit(86)


def _pause_point(name: str) -> None:
    """Test-only (`SECURE_CODE_TEST_PAUSE_AT=<point>=<path>`): write `<path>.ready`, wait ≤ 30 s for `.go`."""
    point, _, path = os.environ.get(store.PAUSE_ENV, "").partition("=")
    if point != name or not path:
        return
    marker = Path(path)
    marker.with_suffix(".ready").write_text("ready\n", encoding="utf-8")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not marker.with_suffix(".go").exists():
        time.sleep(0.02)


def _swept(result: Result, pairs: list[tuple[str, str]]) -> Result:
    """FR-001G-10: no pre-check-matched value is ever printed."""
    result.data = drafting_mask.sweep(result.data, pairs)
    result.problems = [Problem(p.code, drafting_mask.sweep(p.message, pairs)) for p in result.problems]
    result.next_steps = drafting_mask.sweep(result.next_steps, pairs)
    return result


def _refused(command: str, exc: BaseException) -> Result:
    if isinstance(exc, Refusal):
        return Result.refused(command, exc.code, exc.message, exc.next_step, exc.data)
    return exit_journal.refusal(command, exc)


# --------------------------------------------------------------------------- draft-check
def draft_check(project: str | None, draft: str, review: str | None) -> Result:
    root = knowledge_root(project, CHECK)
    if isinstance(root, Result):
        return root
    try:
        report = run(root, draft, review)
    except (Refusal, LockHeld, store.StoreError, OSError) as exc:
        return _refused(CHECK, exc)
    steps = {
        "valid": [
            "Show the Maintainer the masked final diff, the validation report, the advisory lint result "
            "and the non-normative statement; run knowledge draft-approve with this validation_digest only "
            "after the Maintainer explicitly confirms"
        ],
        "review_incomplete": [
            "Show this report; the Maintainer inspects the draft file and writes the review "
            "file (review_required), then check again with --review"
        ],
        "invalid": ["Correct the draft and check again"],
        "stale_base": [STALE_STEP],
        "rule_inactive": ["Reactivate the rule first (knowledge exit-preview --action reactivate)"],
    }[report.status]
    return _swept(Result(CHECK, report.status == "valid", report.data, report.problems, steps), report.pairs)


# --------------------------------------------------------------------------- draft-approve
def draft_approve(
    project: str | None,
    draft: str,
    review: str | None,
    validation_digest: str | None,
    false_positives: list[str],
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    root = knowledge_root(project, APPROVE)
    if isinstance(root, Result):
        return root
    try:
        recovered = exit_journal.ensure_recovered(root)
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(APPROVE, exc)
    result = _approve(root, draft, review, validation_digest, false_positives, trust_paths)
    return exit_journal.with_recovered(result, recovered)


def _parse_declarations(values: list[str]) -> list[tuple[RuleRef, str]]:
    parsed = []
    for value in values:
        rule, sep, fingerprint = value.rpartition(":")
        try:
            ref = RuleRef.parse(rule) if sep and rule else None
        except IdentityError:
            ref = None
        if ref is None or not FINGERPRINT.fullmatch(fingerprint):
            raise Refusal("ARGUMENT_INVALID", f"--false-positive must be RULE:FINGERPRINT: {value}", FP_STEP)
        parsed.append((ref, fingerprint))
    if len(set(values)) != len(values) or len({fp for _, fp in parsed}) != len(parsed):
        raise Refusal("ARGUMENT_INVALID", "duplicate --false-positive declaration", FP_STEP)
    return parsed


def _approve(
    root: Path,
    draft: str,
    review: str | None,
    digest: str | None,
    false_positives: list[str],
    trust_paths: TrustPaths | None,
) -> Result:
    decision = require_maintainer("knowledge.draft-approve", paths=trust_paths)
    if not decision.allowed:
        denied = decision.to_result()
        denied.command = APPROVE
        return denied
    try:
        if not review:
            raise Refusal(
                "DRAFT_REVIEW_INVALID",
                "draft-approve needs the Maintainer's review file (--review)",
                "The Maintainer writes the review file",
            )
        if not (isinstance(digest, str) and DIGEST.fullmatch(digest)):
            raise Refusal(
                "ARGUMENT_INVALID", "--validation-digest must look like sha256:<64 hex>", CHECK_AGAIN
            )
        declared = _parse_declarations(false_positives)
        with exit_journal.session(root, write=False):
            report = run(root, draft, review)
    except (Refusal, LockHeld, store.StoreError, OSError) as exc:
        return _refused(APPROVE, exc)
    gate = _gates(report, digest, declared)
    if gate is not None:
        return _swept(gate, report.pairs)
    forwarded = [f"{report.draft.ref.rel}:{fp}" for fp in sorted(fp for _, fp in declared)]
    try:
        result = _stage_and_update(root, report, digest, forwarded, trust_paths)
    except (Refusal, LockHeld, store.StoreError, OSError) as exc:
        result = _refused(APPROVE, exc)
    return _swept(result, report.pairs)


def _summary(report: Report) -> dict[str, Any]:
    data = report.data
    return {
        "status": report.status,
        "languages": data.get("languages"),
        "validation_digest": data.get("validation_digest"),
    }


def _gates(report: Report, digest: str, declared: list[tuple[RuleRef, str]]) -> Result | None:
    ref = report.draft.ref
    if report.status == "stale_base":
        return Result(
            APPROVE,
            False,
            {"item_digest": report.stored.digest, "state_digest": report.data["state_digest"]},
            [
                Problem("STATE_CONFLICT", f"{ref} changed since {report.draft.base_state}"),
                Problem("STALE_VALIDATION", "the draft's base rule state is no longer current"),
            ],
            [STALE_STEP],
        )
    if report.status == "rule_inactive":
        return Result.refused(
            APPROVE,
            "RULE_INACTIVE",
            f"{ref} is deactivated",
            "Reactivate the rule first (knowledge exit-preview --action reactivate)",
        )
    if report.validation_digest is None or report.validation_digest != digest:
        reason = (
            "the draft is not valid now"
            if report.validation_digest is None
            else "the draft, review, rule, validator version or pre-check key changed since the check"
        )
        return Result(
            APPROVE,
            False,
            {"report": _summary(report)},
            [Problem("STALE_VALIDATION", f"recomputed validation_digest differs: {reason}")]
            + report.problems,
            [CHECK_AGAIN],
        )
    if any(r != ref for r, _ in declared):
        return Result.refused(APPROVE, "ARGUMENT_INVALID", "declaration for another rule", FP_STEP)
    blocking = {f.fingerprint for f in report.blocking}
    fps = {fp for _, fp in declared}
    if blocking - fps:
        return Result.refused(
            APPROVE,
            "NEEDS_DECISION",
            "suspected credential or embedded instruction",
            "The Maintainer inspects the draft file and declares exactly the listed "
            "fingerprints with --false-positive",
            {"findings": [f.to_dict() for f in report.blocking]},
        )
    if fps - blocking:
        return Result.refused(
            APPROVE, "ARGUMENT_INVALID", "declared fingerprint not among the listed findings", FP_STEP
        )
    return None


# --------------------------------------------------------------------------- staging (DEC-3)
def _secure(dfd: int) -> None:
    if not durable.POSIX_FD:  # pragma: no cover - Windows: owner-only modes not enforced (documented)
        return
    info = os.fstat(dfd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise durable.unsafe(f"{STAGING_REL} is not a folder owned by this account")
    if info.st_mode & 0o077:
        os.fchmod(dfd, 0o700)


def _sweep(tree: durable.Tree, dfd: int, own: str) -> list[str]:
    """Remove crash leftovers whose lease is not held (by name pattern only); returns unknown names."""
    entries = durable.listdir(dfd)
    names = {name for name, _ in entries}
    unknown = []
    for name, info in entries:
        lease, payload = LEASE.fullmatch(name), PAYLOAD.fullmatch(name)
        if not (lease or payload):
            unknown.append(name)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise durable.unsafe(f"{STAGING_REL}/{name} is not a regular file")
        lid = (lease or payload).group(1)
        if lid == own:
            continue
        if lease:
            try:
                with durable.DirLock(tree, f"{STAGING_REL}/{name}", create=False, timeout=0):
                    durable.unlink(dfd, f"payload-{lid}.json")
                    durable.unlink(dfd, f".payload-{lid}.json.tmp")
                    durable.unlink(dfd, name)
            except LockHeld:
                continue
        elif f"lease-{lid}.lock" not in names:
            durable.unlink(dfd, name)
    return unknown


def _stage_and_update(
    root: Path, report: Report, digest: str, forwarded: list[str], trust_paths: TrustPaths | None
) -> Result:
    draft = report.draft
    data = json.dumps(
        {
            "schema": UPDATE_SCHEMA,
            "examples": {lang: report.payload[store.example_file(lang)] for lang in sorted(draft.examples)},
        },
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    lid = secrets.token_hex(16)
    lease_name, name = f"lease-{lid}.lock", f"payload-{lid}.json"
    with durable.Tree(root) as tree:
        lease = durable.DirLock(tree, f"{STAGING_REL}/{lease_name}", create=True, timeout=0)
        with lease:
            dfd = tree.dir(STAGING_REL)
            try:
                _secure(dfd)
                held = durable.entry(dfd, lease_name)
                if held is None or (lease._fd is not None and os.fstat(lease._fd).st_ino != held.st_ino):
                    raise Refusal(
                        "STAGING_CHANGED",
                        "the staging lease was removed by another process",
                        "Check the staging area for other processes, then approve again",
                    )
                unknown = _sweep(tree, dfd, lid)
                try:
                    upd = _write_and_call(root, dfd, name, data, draft, forwarded, trust_paths)
                finally:
                    durable.unlink(dfd, name)
                    durable.unlink(dfd, f".{name}.tmp")
                    durable.unlink(dfd, lease_name)
            finally:
                durable.close(dfd)
    return _outcome(root, report, digest, upd, unknown)


def _write_and_call(
    root: Path,
    dfd: int,
    name: str,
    data: bytes,
    draft: Any,
    forwarded: list[str],
    trust_paths: TrustPaths | None,
) -> Result:
    durable.write(dfd, name, data, f".{name}.tmp", mode=0o600)
    _crash_point("drafting_staged")
    _pause_point("drafting_staged")
    reason = unsafe_component(root, STAGING_REL, expect_dir=True)
    if reason:
        raise durable.unsafe(reason)
    if read_nofollow(dfd, name, len(data)) != data:
        raise Refusal(
            "STAGING_CHANGED",
            "the staged payload differs from the reviewed payload; update_rule was not called",
            "Check the staging area for other processes, then approve again",
        )
    _pause_point("drafting_after_reread")
    upd = service.update_rule(
        str(root),
        draft.ref.rel,
        draft.base_state,
        str(root / STAGING_REL / name),
        forwarded,
        trust_paths=trust_paths,
    )
    _crash_point("drafting_after_update")
    return upd


def _outcome(root: Path, report: Report, digest: str, upd: Result, unknown: list[str]) -> Result:
    ref = report.draft.ref
    if not upd.ok:
        return Result(
            APPROVE, False, {"update": upd.data, "report": _summary(report)}, upd.problems, upd.next_steps
        )
    with exit_journal.session(root, write=False):
        stored = store.read_rule(root, ref)
    files = stored.files if stored else {}
    current = store.state_digest(stored) if stored else None
    expected, written = report.new_item.digest(), upd.data.get("item_digest")
    # DEC-I16: a swap is decided solely by what update_rule itself wrote; a later legitimate write by
    # another command (seen only in the re-read) is not a mismatch and must never be "restored".
    if written != expected:
        log = files.get("changelog.md", "")
        heading = _entry_heading(log, written)
        state = upd.data.get("state_digest") or current
        return Result(
            APPROVE,
            False,
            {
                "rule": ref.rel,
                "state_digest": state,
                "changelog_entry": heading,
                "expected_item_digest": expected,
                "written_item_digest": written,
                "applied": False,
            },
            [
                Problem(
                    "WRITE_MISMATCH",
                    f"The formal rule {ref} now holds bytes that differ from the reviewed payload "
                    f"(written by draft-approve; state_digest {state}; changelog entry '{heading}')",
                )
            ],
            [
                f"Review the rule with `secure-code knowledge show --rule {ref}`",
                f"Restore the previous content with `secure-code knowledge update --base-state {state}` "
                "using the before-text of that changelog entry or version control",
            ],
        )
    changed_later = upd.data.get("outcome") == "updated" and (
        current != upd.data.get("state_digest") or any(files.get(n) != t for n, t in report.payload.items())
    )
    applied = []
    for lang in sorted(report.draft.examples):
        file_name = store.example_file(lang)
        found = blocks.scan_markers(file_name, report.payload[file_name])[0]
        applied.append(
            {
                "file": file_name,
                "language": lang,
                "draft_digest": found.draft_digest,
                "body_digest": found.body_digest,
            }
        )
    data = {
        "rule": ref.rel,
        "outcome": upd.data.get("outcome"),
        "update": upd.data,
        "applied_blocks": applied,
        "validation_digest": digest,
    }
    if unknown:
        data["staging_unknown_entries"] = unknown
    steps = []
    if changed_later:
        data["changed_after_approval"] = {
            "state_digest": current,
            "note": "the reviewed payload was written; another write changed the rule after this approval",
        }
        steps.append(f"Show the rule again (secure-code knowledge show --rule {ref}) before further drafting")
    return Result(APPROVE, True, data, [], steps)


def _entry_heading(log: str, item_digest: str | None) -> str | None:
    """Heading of the latest changelog entry that recorded `item_digest` (the draft-approve write)."""
    heading = None
    for entry in re.split(r"(?m)^(?=## )", log):
        if item_digest and f"- item digest: {item_digest}" in entry:
            heading = entry.splitlines()[0]
    return heading
