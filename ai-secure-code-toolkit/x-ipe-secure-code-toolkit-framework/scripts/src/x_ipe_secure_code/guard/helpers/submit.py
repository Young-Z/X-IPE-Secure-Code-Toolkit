"""`guard helper submit` (FR-002F-2/3/4, AC-002F-01a, 02a–02g, 03a, 06c, 12d; design §5).

Validation is all-or-nothing until storage; the `generation` attempt is pre-checked on a copy. Storage
writes the script and samples (0444) and the helper record, cites the attempt and records the submission's
failed auxiliary-method evidence. The checks then run in order (L-03, credential text, toolkit parse,
L-04, static rules, compile probe in a container) and the first failure makes the helper `check_failed`.
A cancellation during the compile probe commits nothing.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path
from typing import Any

from ...adapters import safe_io
from ...results import Result
from .. import budget, runs, service, targets
from ..mask import mask_text
from ..model import MAX_REQUEST_BYTES, Checker, GuardError, load_request
from ..toolctl import ToolCancelled, ack, cancelled_error
from . import evidence, execute, registry, static
from .model import (
    L01_HELPERS,
    L02_EACH,
    L02_SAMPLE_BYTES,
    L02_TOTAL,
    L05_COMPONENTS,
    L05_FILE_BYTES,
    L05_FILES,
    L05_PATH_BYTES,
    L05_TOTAL,
    SCHEMA_HELPER,
    STATIC_STATEMENT,
    declaration_digest,
    event,
    helper_digest,
    helpers,
    is_helper_method,
    samples_digest,
    sha,
    suffix,
)
from .snapshot import under

STEP = "Fix the helper request (see references/guard-records.md); nothing was stored"
KEYS = {
    "schema",
    "attempt",
    "usage",
    "check",
    "method",
    "goal",
    "read_scope",
    "judgement_basis",
    "language",
    "script_file",
    "samples",
}
REQUIRED = ("check", "method", "goal", "read_scope", "judgement_basis", "language", "script_file", "samples")


def _ck() -> Checker:
    return Checker("HELPER_INVALID", STEP)


def _read(root: Path, ck: Checker, raw: Any, where: str, limit: int) -> tuple[str, bytes]:
    try:
        rel = targets.normalize(raw, where)
    except GuardError as exc:
        raise ck.fail(exc.message) from None
    if rel == ".":
        raise ck.fail(f"{where} must name a file")
    try:
        fd = safe_io.open_nofollow(root, rel)
    except (OSError, safe_io.UnsafePath) as exc:
        raise ck.fail(f"{where} {rel} is not a readable regular file without links ({exc})") from None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    return rel, data


def _scope(root: Path, ck: Checker, state: dict[str, Any], raw: Any) -> list[str]:
    """Read scope (AC-002F-02b): inside a target, every component real, no escape, within L-05."""
    entries: list[str] = []
    for i, item in enumerate(ck.items(raw, "read_scope", required=True)):
        where = f"read_scope[{i}]"
        try:
            rel = targets.normalize(item, where)
            if len(rel.split("/")) > L05_COMPONENTS or len(rel.encode("utf-8")) > L05_PATH_BYTES:
                raise ck.fail(f"{where} {rel} exceeds L-05 path limits")
            if targets.owning_target(state["artifact"], rel) is None:
                raise ck.fail(f"{where} {rel} is not inside a verification target")
            kind = targets.kind_of(root, rel, where)
        except GuardError as exc:
            raise ck.fail(exc.message) from None
        if kind is None:
            raise ck.fail(f"{where} {rel} does not exist")
        if rel not in entries:
            entries.append(rel)
    files: dict[str, int] = {}
    for rel in entries:
        if (root / rel).is_file():
            files[rel] = os.lstat(root / rel).st_size
            continue
        tree = targets.tree_files(root, rel, limit=L05_FILES)
        if tree["truncated"]:
            raise GuardError(
                "HELPER_LIMIT",
                f"read scope {rel} has more than {L05_FILES} files (L-05)",
                "Use a narrower read scope or fewer/smaller samples",
            )
        if tree["not_bindable"]:
            bad = tree["not_bindable"][0]
            raise ck.fail(f"read scope {rel} contains {bad['path']} ({bad['reason']})")
        for path in tree["files"]:
            files[path] = os.lstat(root / path).st_size
    if (
        len(files) > L05_FILES
        or any(s > L05_FILE_BYTES for s in files.values())
        or sum(files.values()) > L05_TOTAL
    ):
        raise GuardError(
            "HELPER_LIMIT",
            "read scope exceeds L-05 (2,000 files, 5 MiB per file, 50 MiB total)",
            "Use a narrower read scope or fewer/smaller samples",
        )
    return entries


def _samples(
    root: Path, ck: Checker, state: dict[str, Any], raw: Any, scope: list[str]
) -> list[dict[str, Any]]:
    """Samples (AC-002F-03a, L-02): synthetic or explicitly labelled formal examples, never targets."""
    out: list[dict[str, Any]] = []
    target_digests = set()
    for rel in scope:
        if (root / rel).is_file():
            target_digests.add(targets.file_digest(root / rel))
        else:
            target_digests |= set(targets.tree_files(root, rel)["files"].values())
    for i, item in enumerate(ck.items(raw, "samples", required=True)):
        where = f"samples[{i}]"
        ck.obj(
            item,
            where,
            {"kind", "origin", "path", "content_file"},
            frozenset({"kind", "origin", "path", "content_file"}),
        )
        kind = ck.choice(item["kind"], f"{where}.kind", ("positive", "negative"))
        origin = ck.obj(item["origin"], f"{where}.origin", {"type", "rule", "example"}, frozenset({"type"}))
        if origin["type"] == "formal_example":
            raise ck.fail(f"{where}: formal example has no explicit safe/unsafe label")
        if origin["type"] != "synthetic" or set(origin) != {"type"}:
            raise ck.fail(f"{where}.origin must be {{'type': 'synthetic'}}")
        try:
            path = targets.normalize(item["path"], f"{where}.path")
        except GuardError as exc:
            raise ck.fail(exc.message) from None
        if not under(path, scope):
            raise ck.fail(f"{where}.path {path} is not under the read scope")
        rel, data = _read(root, ck, item["content_file"], f"{where}.content_file", L02_SAMPLE_BYTES)
        if targets.path_role(state["artifact"], rel) is not None:
            raise ck.fail(f"{where}: a verification target file cannot be a sample")
        if len(data) > L02_SAMPLE_BYTES:
            raise GuardError(
                "HELPER_LIMIT",
                f"{where} is larger than 64 KiB (L-02)",
                "Use a narrower read scope or fewer/smaller samples",
            )
        digest = sha(data)
        if digest in target_digests:
            raise ck.fail(f"{where}: a verification target file cannot be a sample")
        out.append(
            {
                "id": f"s{i + 1}",
                "kind": kind,
                "origin": {"type": "synthetic"},
                "path": path,
                "sha256": digest,
                "bytes": len(data),
                "data": data,
            }
        )
    kinds = [s["kind"] for s in out]
    if not kinds.count("positive") or not kinds.count("negative"):
        raise ck.fail("samples need at least one positive and one negative sample")
    if (
        kinds.count("positive") > L02_EACH
        or kinds.count("negative") > L02_EACH
        or sum(s["bytes"] for s in out) > L02_TOTAL
    ):
        raise GuardError(
            "HELPER_LIMIT",
            "samples exceed L-02 (5 positive, 5 negative, 256 KiB total)",
            "Use a narrower read scope or fewer/smaller samples",
        )
    return out


def _prepare(root: Path, state: dict[str, Any], doc: dict[str, Any], used: float) -> dict[str, Any]:
    ck = _ck()
    if len(helpers(state)) >= L01_HELPERS:
        raise GuardError(
            "HELPER_LIMIT",
            f"at most {L01_HELPERS} helpers per verification (L-01)",
            "Use other methods for further gaps",
        )
    unknown = sorted(set(doc) - KEYS)
    if unknown:
        raise ck.fail(f"helper request has unknown fields: {', '.join(unknown)}")
    for key in REQUIRED:
        if doc.get(key) in (None, "", [], {}):
            raise ck.fail(f"helper request is missing: {key}")
    checks = {c["id"]: c for c in state["plan"]["checks"]}
    cid = ck.key(doc["check"], "check")
    if cid not in checks:
        raise ck.fail(f"check {cid!r} is not a planned check of this verification")
    method = doc["method"]
    if not is_helper_method(method) or method not in {m["name"] for m in checks[cid]["methods"]}:
        raise ck.fail(
            f"method {method!r} is not a helper method of check {cid} (plan it or add it by a method change)"
        )
    basis = ck.obj(
        doc["judgement_basis"],
        "judgement_basis",
        {"finding", "no_finding"},
        frozenset({"finding", "no_finding"}),
    )
    if doc["language"] != "python":
        raise ck.fail("language must be python")
    goal = ck.text(doc["goal"], "goal")
    scope = _scope(root, ck, state, doc["read_scope"])
    samples = _samples(root, ck, state, doc["samples"], scope)
    script_rel, script = _read(root, ck, doc["script_file"], "script_file", MAX_REQUEST_BYTES)
    if len(script) > MAX_REQUEST_BYTES:
        raise GuardError("HELPER_LIMIT", "script file larger than 4 MiB", STEP)
    if doc.get("attempt") is None:
        raise GuardError(
            "ATTEMPT_REQUIRED",
            "A helper submission must cite the generation attempt registered before authoring",
            budget.ATTEMPT_STEP,
        )
    budget.cite(
        copy.deepcopy(state),
        doc["attempt"],
        {"generation"},
        {"pairs": {(cid, method)}},
        used,
        service.now()[0],
        doc.get("usage"),
    )
    return {
        "check": cid,
        "method": method,
        "rule": checks[cid]["rule"],
        "goal": goal,
        "read_scope": scope,
        "judgement_basis": {
            "finding": ck.text(basis["finding"], "judgement_basis.finding"),
            "no_finding": ck.text(basis["no_finding"], "judgement_basis.no_finding"),
        },
        "language": "python",
        "script": script,
        "samples": samples,
    }


def _version(root: Path) -> tuple[int, ...]:
    image = registry.image(root)
    if image is None:
        return tuple(sys.version_info[:3])
    return tuple(int(x) for x in image["cpython"].split("."))


def submit(project: str | None, run_id: str, request: str) -> Result:
    """Submit a helper script with its declaration and samples; run the checks (never executes the script)."""
    command = "guard helper submit"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_HELPER, "HELPER_INVALID", STEP)
        vid = runs.check_id(run_id)
        with service._locked(root):
            state = runs.read_state(root, vid)
            runs.refuse_closed(root, vid)
            if state["status"] != "open":
                raise GuardError("RUN_FINISHED", f"Verification {vid} is already concluded", runs.NEW_RUN)
            used = service.consumed(root, state)
            try:
                budget.require_running(state, used)
                service._needs_plan(state)
                prepared = _prepare(root, state, doc, used)
            except GuardError as exc:
                exc.data.setdefault("budget", budget.status(state, used))
                raise
            return _store_and_check(root, vid, state, doc, prepared, used)

    return service._call(command, project, body)


def _store_and_check(
    root: Path, vid: str, state: dict[str, Any], doc: dict[str, Any], prepared: dict[str, Any], used: float
) -> Result:
    new = copy.deepcopy(state)
    hid = f"h-{len(new.get('helpers') or []) + 1}-{suffix(new)}"
    folder = runs.run_dir(root, vid) / "helpers" / hid
    written: list[Path] = []
    at = service.now()[0]
    try:
        folder.mkdir(parents=True, mode=0o700)
        (folder / "samples").mkdir(mode=0o700)
        for path, data in [(folder / "script.py", prepared["script"])] + [
            (folder / "samples" / s["id"], s["data"]) for s in prepared["samples"]
        ]:
            path.write_bytes(data)
            path.chmod(0o444)
            written.append(path)
        script_sha = sha(prepared["script"])
        samples = [
            {k: v for k, v in s.items() if k != "data"} | {"file": f"helpers/{hid}/samples/{s['id']}"}
            for s in prepared["samples"]
        ]
        helper = {
            "id": hid,
            "check": prepared["check"],
            "method": prepared["method"],
            "rule": prepared["rule"],
            "generation_attempt": doc["attempt"],
            "submitted_at": at,
            "goal": prepared["goal"],
            "read_scope": prepared["read_scope"],
            "judgement_basis": prepared["judgement_basis"],
            "language": "python",
            "script": {
                "file": f"helpers/{hid}/script.py",
                "sha256": script_sha,
                "bytes": len(prepared["script"]),
                "lines": len(prepared["script"].splitlines()),
            },
            "samples": samples,
            "status": "checked",
            "blocked": None,
            "reason": None,
            "checks": {"statement": STATIC_STATEMENT},
            "runs": [],
            "events": [],
        }
        helper["declaration_sha256"] = declaration_digest(helper)
        helper["samples_sha256"] = samples_digest(samples)
        helper["helper_digest"] = helper_digest(
            script_sha, helper["declaration_sha256"], helper["samples_sha256"]
        )
        new.setdefault("helpers", []).append(helper)
        event(helper, "submitted", "stored", at, attempt=doc["attempt"])
        budget.cite(
            new,
            doc["attempt"],
            {"generation"},
            {"pairs": {(helper["check"], helper["method"])}},
            used,
            at,
            doc.get("usage"),
        )
        failure = static.check(prepared["script"], _version(root))
        steps = ("size", "credential", "parse", "ast_limits", "static")
        reached = steps.index(failure.step) if failure else len(steps)
        event(
            helper,
            "size_checked",
            "fail" if failure and reached <= 1 else "pass",
            at,
            detail=failure.reason if failure and reached <= 1 else None,
        )
        if reached > 1:
            event(
                helper,
                "ast_checked",
                "fail" if failure and reached <= 3 else "pass",
                at,
                detail=failure.reason if failure and reached <= 3 else None,
            )
        if reached > 3:
            event(
                helper,
                "static_checked",
                "fail" if failure else "pass",
                at,
                detail=failure.reason if failure else None,
            )
        helper["checks"].update(
            size="pass" if reached > 1 else "fail", static="pass" if not failure else "fail"
        )
        if failure is None:
            execute.sweep_stages(root, vid)
            active = execute.Active(root, vid, "helper-compile", hid, doc["attempt"])
            try:
                probe = execute.compile_probe(root, vid, new, helper, prepared["script"], active)
            finally:
                active.close()
            helper["checks"]["compile"] = {
                k: probe.get(k) for k in ("image", "cpython", "outcome", "probe_seconds", "config_digest")
            }
            event(
                helper,
                "compile_probe",
                probe["outcome"],
                service.now()[0],
                conformance=probe.get("conformance"),
                detail=probe["reason"],
            )
            if probe["outcome"] != "pass":
                failure = static.Failure("compile", None, None, probe["reason"])
        if failure is not None:
            helper["status"], helper["reason"] = "check_failed", failure.reason
        evidence.failed(
            new,
            helper,
            f"checks failed ({failure.reason}): counts as a failed auxiliary method"
            if failure
            else "submitted: counts as a failed auxiliary method unless an accepted result is recorded later",
        )
        runs.commit_state(root, new, expected_revision=state["revision"])
    except ToolCancelled as exc:
        _discard(folder)
        detail = "compile probe stopped" if exc.confirmed else "compile probe container removal not confirmed"
        ack(root, vid, exc.confirmed, detail)
        raise cancelled_error(vid, exc.confirmed, detail) from None
    except BaseException:
        _discard(folder)
        raise
    used_now = service.consumed(root, new)
    status = budget.status(new, used_now)
    data = {
        "verification_id": vid,
        "helper": hid,
        "status": helper["status"],
        "reason": helper["reason"],
        "script_sha256": script_sha,
        "declaration_sha256": helper["declaration_sha256"],
        "samples_sha256": helper["samples_sha256"],
        "helper_digest": helper["helper_digest"],
        "checks": helper["checks"],
        "expected_extra_attempts": expected_extra(new, helper),
        "extra_attempts_left": status["extra_left"],
        "budget": status,
    }
    if helper["status"] == "check_failed":
        return Result(
            "guard helper submit",
            False,
            data,
            [_problem("HELPER_CHECK_FAILED", helper["reason"])],
            ["Fix the script and submit it again under a new generation attempt, or rely on another method"],
        )
    steps = [
        "Register a reviewer attempt covering the new helpers and ask one independent read-only Reviewer to "
        "review them as a batch"
    ]
    if status["extra_left"] < data["expected_extra_attempts"]:
        steps.append(budget.EXTEND_STEP)
    return Result("guard helper submit", True, data, [], steps)


def _problem(code: str, message: str):
    from ...results import Problem

    return Problem(code, mask_text(message)[0])


def _discard(folder: Path) -> None:
    from .snapshot import unseal_remove

    unseal_remove(folder)
    try:
        folder.parent.rmdir()  # only when no other helper is stored
    except OSError:
        pass


def expected_extra(state: dict[str, Any], helper: dict[str, Any]) -> int:
    """Extra attempts the remaining steps cost under the unchanged 002-C rules (design §11.3)."""
    if helper["status"] != "checked" or helper.get("blocked"):
        return 0
    runs_done = [r for r in helper["runs"] if r["outcome"] in ("failed", "findings", "clean")]
    clean_pending = any(r["outcome"] == "clean" and r["acceptance"]["state"] == "pending" for r in runs_done)
    if clean_pending:
        return 1
    if runs_done:
        return 0
    return 2
