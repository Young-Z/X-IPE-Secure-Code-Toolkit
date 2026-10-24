"""`guard helper run` and the compile probe (design §9.0, §9.1, §9.5; AC-002F-03b, 04a–04n, 05a, 06a/06b).

Gates (no container) → orphan sweep → link-free snapshot bound to the open version → one container per
sample (same canonical configuration) → the target container → schema-checked result → records. Every
container operation follows the 002-B/002-C active-operation and cancellation protocol (`tool-active.json`,
cancel marker polled, acknowledgement). Pre-container and sample-infrastructure failures never cite the
`helper` attempt; a sample with the wrong outcome blocks the helper; any target outcome finishes it.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from ...atomic import dumps_json
from ...results import Problem, Result
from .. import budget, runs, service, targets
from ..model import GuardError
from ..toolctl import ToolCancelled, ack, cancelled_error
from . import evidence, execute_io, registry, results, review, snapshot
from .execute_io import RunSpec
from .model import GAP_NEXT, L02_EACH, L02_TOTAL, L10, event, find, granted, sha
from .runtime import CliRuntime, RuntimeGap

PROBE_CAP = 4096


class NotReady(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code, self.reason = code, reason


class Active:
    """`tool-active.json` of a running helper operation (cancel acknowledgement protocol)."""

    def __init__(self, root: Path, vid: str, operation: str, helper: str, attempt: str | None) -> None:
        self.root, self.vid = root, vid
        self.doc = {
            "pid": os.getpid(),
            "operation": operation,
            "helper": helper,
            "attempt": attempt,
            "containers": [],
            "volume": None,
            "at": service.now()[0],
        }
        runs.write_run_json(root, vid, "tool-active.json", self.doc)

    def objects(self, names: list[str], volume: str | None) -> None:
        self.doc["containers"] = list(dict.fromkeys([*self.doc["containers"], *names]))
        self.doc["volume"] = volume
        runs.write_run_json(self.root, self.vid, "tool-active.json", self.doc)

    def close(self) -> None:
        runs.remove_run_file(self.root, self.vid, "tool-active.json")


def stopper(root: Path, vid: str):
    return lambda: runs.cancel_marker(root, vid) is not None


def ready(root: Path) -> tuple[CliRuntime, dict[str, Any], dict[str, Any]]:
    """Runtime, registration and conformance for an execution now, or NotReady with the reason (05a, 11c)."""
    try:
        rt = CliRuntime.discover()
    except RuntimeGap as exc:
        code = "platform_unsupported" if exc.code == "HELPER_PLATFORM_UNSUPPORTED" else "runtime_unavailable"
        raise NotReady(code, exc.reason) from None
    if not isinstance(rt, CliRuntime):
        raise NotReady("runtime_unavailable", "not a container runtime CLI")
    image = registry.image(root)
    if image is None:
        raise NotReady("image_unavailable", "no valid helper image registration")
    try:
        execute_io.sweep(rt)
        present = rt.image(image["image"])
        found = str((present or {}).get("Id") or "")
        if present is None or (found if found.startswith("sha256:") else f"sha256:{found}") != image["image"]:
            raise NotReady("image_unavailable", "the registered image is not present locally (never pulled)")
        identity = rt.identity()
    except RuntimeGap as exc:
        raise NotReady("runtime_unavailable", exc.reason) from None
    conformance = registry.conformance(root, identity, image["image"])
    if conformance is None:
        raise NotReady(
            "conformance_missing", "no valid conformance record for this runtime, image and toolkit"
        )
    return rt, image, conformance


def _limit(root: Path, state: dict[str, Any], purpose: str) -> int:
    remaining = int(state["budget"]["total_seconds"] - service.consumed(root, state))
    limit = min(L10[purpose], remaining)
    if limit < 1:
        budget.require_running(state, state["budget"]["total_seconds"])
    return limit


def sweep_stages(root: Path, vid: str) -> None:
    """Remove `helper-stage-*` folders left by an interrupted helper operation of this verification."""
    for path in runs.run_dir(root, vid).glob("helper-stage-*"):
        if path.is_dir() and not path.is_symlink():
            snapshot.unseal_remove(path)


def _stage(root: Path, vid: str) -> Path:
    return runs.run_dir(root, vid) / f"helper-stage-{secrets.token_hex(6)}"


def _hidn(helper: dict[str, Any]) -> str:
    return "h" + helper["id"].split("-")[1]


def write_file(root: Path, vid: str, helper: dict[str, Any], name: str, data: bytes) -> str:
    folder = runs.run_dir(root, vid) / "helpers" / helper["id"]
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    (folder / name).write_bytes(data)
    return f"helpers/{helper['id']}/{name}"


# --------------------------------------------------------------------------- compile probe (02c)
def compile_probe(
    root: Path, vid: str, state: dict[str, Any], helper: dict[str, Any], script: bytes, active: Active
) -> dict[str, Any]:
    """Compile (never execute) the script with the registered image's interpreter in a container."""
    try:
        rt, image, conformance = ready(root)
    except NotReady as exc:
        return {"outcome": "fail", "reason": f"compile probe unavailable: {exc.reason}"}
    limit = _limit(root, state, "compile")
    stage = _stage(root, vid)
    try:
        folder = execute_io.stage_helper(stage / "helper", script)
        run = RunSpec(
            "compile",
            f"xsc-{vid[-8:]}-{_hidn(helper)}-compile-1",
            vid,
            image["image"],
            image["interpreter"],
            image["env"],
            limit,
            folder,
            with_results=False,
            rendered=conformance["rendered"],
        )
        out = execute_io.run_container(rt, run, stopper(root, vid), active.objects)
    except execute_io.ConfigMismatch as exc:
        return {"outcome": "fail", "reason": f"compile probe: configuration mismatch: {exc.invariant}"}
    finally:
        snapshot.unseal_remove(stage)
    if out.cancelled:
        raise ToolCancelled(out.cleanup)
    info = {
        "image": image["image"],
        "cpython": image["cpython"],
        "probe_seconds": out.seconds,
        "config_digest": out.config_digest,
        "conformance": conformance["id"],
    }
    if out.config is not None:
        write_file(root, vid, helper, "config-compile-1.json", dumps_json(out.config))
    if out.mismatch:
        return {**info, "outcome": "fail", "reason": f"compile probe: configuration mismatch: {out.mismatch}"}
    if out.infrastructure or out.limit or not out.cleanup:
        why = out.infrastructure or out.reason or "cleanup not confirmed"
        return {**info, "outcome": "fail", "reason": f"compile probe unavailable: {why}"}
    try:
        line = out.raw_stdout[:PROBE_CAP].decode("utf-8").strip().splitlines()[0]
        answer = json.loads(line)
        ok, version, error = answer["ok"], answer["version"], str(answer.get("error") or "")
    except (UnicodeError, ValueError, IndexError, KeyError, TypeError):
        return {**info, "outcome": "fail", "reason": "compile probe unavailable: unreadable probe answer"}
    if ".".join(map(str, version)) != image["cpython"]:
        return {**info, "outcome": "fail", "reason": "version: image interpreter changed"}
    if ok is not True:
        from ..mask import mask_text

        return {**info, "outcome": "fail", "reason": f"syntax: {mask_text(error)[0][:500]}"}
    return {**info, "outcome": "pass", "reason": None}


# --------------------------------------------------------------------------- guard helper run
def _not_executed(
    root: Path,
    state: dict[str, Any],
    helper: dict[str, Any],
    code: str,
    reason: str,
    attempt: str | None,
    refusal: str = "HELPER_NOT_EXECUTED",
    step: str = GAP_NEXT,
) -> GuardError:
    new = copy.deepcopy(state)
    event(find(new, helper["id"]), "not_executed", code, service.now()[0], attempt=attempt, detail=reason)
    try:
        runs.commit_state(root, new, expected_revision=state["revision"])
    except GuardError as exc:
        return exc
    message = reason if refusal != "HELPER_NOT_EXECUTED" else f"helper {helper['id']} not executed: {reason}"
    return GuardError(refusal, message, step, {"reason_code": code, "helper": helper["id"]})


def _gates(root: Path, state: dict[str, Any], helper: dict[str, Any], attempt: str | None, used: float):
    """Design §9.1 gates in order; returns (runtime, image, conformance) or raises the refusal."""

    def stop(
        code: str, reason: str, refusal: str = "HELPER_NOT_EXECUTED", step: str = GAP_NEXT
    ) -> GuardError:
        return _not_executed(root, state, helper, code, reason, attempt, refusal, step)

    try:
        budget.require_running(state, used)
    except GuardError as exc:
        raise stop(exc.code.lower(), exc.message, exc.code, exc.next_step) from None
    if helper["status"] != "checked":
        raise stop("check_failed", f"checks failed: {helper['reason']}")
    if helper.get("blocked"):
        raise stop("blocked", "samples failed; submit a new helper")
    for item in [helper["script"], *helper["samples"]]:
        try:
            current = sha(Path(runs.run_dir(root, state["verification_id"]) / item["file"]).read_bytes())
        except OSError:
            current = None
        if current != item["sha256"]:
            raise stop("helper_files_changed", "helper files changed after submission")
    observed = {t["path"]: targets.observe(root, t["path"]) for t in state["artifact"]["targets"]}
    decision = review.pre_execution(state, helper, observed)
    if decision != "accepted":
        code = "rejected" if decision == "rejected" else "not_reviewed"
        raise stop(
            code,
            "rejected by the Reviewer"
            if code == "rejected"
            else "not reviewed (no valid accepted pre-execution review bound to the current digests)",
        )
    if granted(state, helper) is None:
        raise stop("not_granted", "not granted (no user grant for the current digests)")
    if attempt is None:
        raise stop(
            "attempt_required",
            "a helper attempt must be registered first",
            "ATTEMPT_REQUIRED",
            budget.ATTEMPT_STEP,
        )
    try:
        budget.cite(
            copy.deepcopy(state),
            attempt,
            {"helper"},
            {"pairs": {(helper["check"], helper["method"])}},
            used,
            service.now()[0],
            None,
        )
    except GuardError as exc:
        raise stop("attempt_invalid", exc.message, exc.code, exc.next_step) from None
    try:
        rt, image, conformance = ready(root)
    except NotReady as exc:
        raise stop(exc.code, exc.reason) from None
    kinds = [s["kind"] for s in helper["samples"]]
    if (
        not (1 <= kinds.count("positive") <= L02_EACH and 1 <= kinds.count("negative") <= L02_EACH)
        or sum(s["bytes"] for s in helper["samples"]) > L02_TOTAL
    ):
        raise stop("limit", "limit L-02: samples")
    return rt, image, conformance


def _sample_ok(sample: dict[str, Any], parsed: dict[str, Any] | None) -> tuple[str, bool]:
    if parsed is None:
        return "failed", False
    hits = [f for f in parsed["findings"] if f["path"] == sample["path"]]
    if sample["kind"] == "positive":
        return ("finding" if hits else "clean"), bool(hits)
    clean = not parsed["findings"] and sample["path"] in parsed["scanned"]
    return ("clean" if clean else "finding"), clean


def run(project: str | None, run_id: str, helper_id: str, attempt_id: str | None) -> Result:
    """Run a reviewed, granted helper on its samples and then on the target snapshot."""
    command = "guard helper run"

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        with service._locked(root):
            state = runs.read_state(root, vid)
            runs.refuse_closed(root, vid)
            if state["status"] != "open":
                raise GuardError("RUN_FINISHED", f"Verification {vid} is already concluded", runs.NEW_RUN)
            service._needs_plan(state)
            helper = find(state, helper_id)
            sweep_stages(root, vid)
            used = service.consumed(root, state)
            rt, image, conformance = _gates(root, state, helper, attempt_id, used)
            return _execute(root, vid, state, helper, attempt_id, rt, image, conformance)

    return service._call(command, project, body)


def _execute(
    root: Path,
    vid: str,
    state: dict[str, Any],
    helper: dict[str, Any],
    attempt: str,
    rt: CliRuntime,
    image: dict[str, Any],
    conformance: dict[str, Any],
) -> Result:
    new = copy.deepcopy(state)
    h = find(new, helper["id"])
    n = len(h["runs"]) + 1
    record: dict[str, Any] = {
        "n": n,
        "attempt": attempt,
        "started_at": service.now()[0],
        "ended_at": None,
        "seconds": 0.0,
        "grant": granted(state, helper)["id"],
        "conformance": conformance["id"],
        "image": image["image"],
        "runtime": {"kind": rt.kind, "server_version": conformance["identity"].get("server_version")},
        "manifest": None,
        "time_limit": None,
        "time_limit_capped": False,
        "samples": [],
        "target": None,
        "diagnostics": None,
        "outcome": "not_started",
        "method_status": None,
        "reason": None,
        "object_files": None,
        "uncovered": [],
        "uncovered_count": 0,
        "acceptance": None,
        "evidence": None,
        "findings": [],
        "cleanup": "confirmed",
    }
    written: list[str] = []
    should_stop = stopper(root, vid)
    active = Active(root, vid, "helper-run", helper["id"], attempt)
    stage = _stage(root, vid)
    try:
        try:
            check = next(c for c in state["plan"]["checks"] if c["id"] == helper["check"])
            deadline = time.monotonic() + max(
                1.0, state["budget"]["total_seconds"] - service.consumed(root, state)
            )
            (stage / "target" / "input").mkdir(parents=True, mode=0o700)
            parts = snapshot.build(
                root,
                state["artifact"],
                helper["read_scope"],
                check["object"],
                stage / "target" / "input",
                should_stop,
                deadline,
            )
        except snapshot.SnapshotRefused as exc:
            if exc.code == "cancelled":
                raise ToolCancelled(True) from None
            if exc.code == "time":
                raise _not_executed(
                    root,
                    state,
                    helper,
                    "budget_time_exhausted",
                    exc.reason,
                    attempt,
                    "BUDGET_TIME_EXHAUSTED",
                    budget.EXTEND_STEP,
                ) from None
            raise _not_executed(root, state, helper, exc.code, exc.reason, attempt) from None
        manifest = snapshot.manifest(helper["id"], "target", parts)
        written.append(write_file(root, vid, h, f"run-{n}-manifest.json", dumps_json(manifest)))
        record["manifest"] = {
            "file": written[-1],
            "digest": parts["digest"],
            "files": len(parts["files"]),
            "bytes": sum(f["size"] for f in parts["files"]),
        }
        record["object_files"] = parts["object_files"]
        event(
            h,
            "snapshot_built",
            "ok",
            service.now()[0],
            attempt=attempt,
            manifest=parts["digest"],
            conformance=conformance["id"],
            grant=record["grant"],
        )
        script = (runs.run_dir(root, vid) / helper["script"]["file"]).read_bytes()
        snapshot.seal(stage / "target" / "input")
        # ---- samples (03b): own container each, same canonical configuration and limits
        for k, sample in enumerate(helper["samples"], 1):
            sdir = stage / f"sample-{k}"
            data = (runs.run_dir(root, vid) / sample["file"]).read_bytes()
            sparts = snapshot.place_sample(sdir / "input", sample["path"], data)
            snapshot.seal(sdir / "input")
            limit = _limit(root, state, "sample")
            spec = RunSpec(
                "sample",
                f"xsc-{vid[-8:]}-{_hidn(helper)}-sample-{k}",
                vid,
                image["image"],
                image["interpreter"],
                image["env"],
                limit,
                execute_io.stage_helper(sdir / "helper", script),
                str(sdir / "input"),
                rendered=conformance["rendered"],
            )
            out = execute_io.run_container(rt, spec, should_stop, active.objects)
            if out.cancelled:
                raise ToolCancelled(out.cleanup)
            if out.config is not None:
                written.append(
                    write_file(root, vid, h, f"config-{n}-sample-{k}.json", dumps_json(out.config))
                )
            entry = {
                "id": sample["id"],
                "kind": sample["kind"],
                "expected": "finding" if sample["kind"] == "positive" else "clean",
                "container": spec.name,
                "config_digest": out.config_digest,
                "seconds": out.seconds,
                "limit": out.limit,
                "outcome": None,
                "ok": False,
            }
            if out.mismatch or out.infrastructure or not out.stopped or not out.cleanup:
                why = (
                    f"configuration mismatch: {out.mismatch}"
                    if out.mismatch
                    else out.infrastructure or out.reason or "cleanup not confirmed"
                )
                entry["outcome"] = "infrastructure"
                record["samples"].append(entry)
                return _commit_refusal(
                    root,
                    state,
                    new,
                    h,
                    record,
                    written,
                    "samples_infrastructure",
                    f"sample run could not be completed: {why}",
                )
            if out.limit == "time" and limit < L10["sample"]:
                budget.require_running(state, state["budget"]["total_seconds"])
            parsed = None
            if out.result is not None:
                try:
                    parsed = results.parse(
                        out.result, helper["id"], helper["rule"], {f["path"] for f in sparts["files"]}
                    )
                except results.ResultInvalid:
                    parsed = None
            entry["outcome"], entry["ok"] = _sample_ok(sample, parsed)
            record["samples"].append(entry)
            event(
                h,
                "sample_run",
                "ok" if entry["ok"] else "mismatch",
                service.now()[0],
                attempt=attempt,
                detail=f"{sample['id']} {sample['kind']}: {entry['outcome']}",
            )
            if not entry["ok"]:
                h["blocked"] = "samples_mismatch"
                record["outcome"] = "samples_mismatch"
                record["reason"] = f"sample {sample['id']} ({sample['kind']}) gave {entry['outcome']}"
                evidence.failed(
                    new,
                    h,
                    f"samples failed: {record['reason']}; the helper was not run on targets",
                    run=n,
                    outcome="samples_mismatch",
                )
                h["runs"].append(record)
                return _commit(root, state, new, h, record, written)
        # ---- target run (finishes the attempt for every outcome)
        limit = _limit(root, state, "target")
        record["time_limit"], record["time_limit_capped"] = limit, limit < L10["target"]
        spec = RunSpec(
            "target",
            f"xsc-{vid[-8:]}-{_hidn(helper)}-target-{n}",
            vid,
            image["image"],
            image["interpreter"],
            image["env"],
            limit,
            execute_io.stage_helper(stage / "target" / "helper", script),
            str(stage / "target" / "input"),
            rendered=conformance["rendered"],
        )
        event(h, "target_run_started", "started", service.now()[0], attempt=attempt, manifest=parts["digest"])
        out = execute_io.run_container(rt, spec, should_stop, active.objects)
        if out.cancelled:
            raise ToolCancelled(out.cleanup)
        if out.config is not None:
            written.append(write_file(root, vid, h, f"config-{n}-target.json", dumps_json(out.config)))
        if out.mismatch or out.infrastructure:
            why = f"configuration mismatch: {out.mismatch}" if out.mismatch else out.infrastructure
            return _commit_refusal(
                root,
                state,
                new,
                h,
                record,
                written,
                "config_mismatch" if out.mismatch else "runtime_unavailable",
                why,
            )
        _target(root, vid, new, h, record, out, parts, written)
        return _commit(root, state, new, h, record, written)
    except ToolCancelled as exc:
        detail = (
            "helper containers stopped and removed"
            if exc.confirmed
            else "helper container removal not confirmed"
        )
        _remove(root, vid, written)
        ack(root, vid, exc.confirmed, detail)
        raise cancelled_error(vid, exc.confirmed, detail) from None
    finally:
        if not snapshot.unseal_remove(stage):
            record["cleanup"] = "not confirmed"
        active.close()


def _target(
    root: Path,
    vid: str,
    new: dict[str, Any],
    h: dict[str, Any],
    record: dict[str, Any],
    out: execute_io.Outcome,
    parts: dict[str, Any],
    written: list[str],
) -> None:
    n = record["n"]
    target = {
        "container": out.container,
        "config_digest": out.config_digest,
        "exit": out.exit,
        "limit": out.limit,
        "result_sha256": None,
        "status": None,
        "findings": 0,
        "scanned": 0,
        "scanned_paths": [],
    }
    record["target"] = target
    record["seconds"] = out.seconds
    record["diagnostics"] = {"stdout": out.stdout, "stderr": out.stderr, "truncated": out.truncated}
    record["cleanup"] = "confirmed" if out.cleanup else "not confirmed"
    paths = {f["path"] for f in parts["files"]}
    reason = None
    parsed = None
    if out.reason or not out.stopped:
        reason = out.reason or "container did not stop"
    elif out.collect_error:
        reason = out.collect_error
    else:
        target["result_sha256"] = sha(out.result)
        try:
            parsed = results.parse(out.result, h["id"], h["rule"], paths)
        except results.ResultInvalid as exc:
            reason = exc.reason
    event(
        h,
        "target_run_ended",
        "failed" if reason else "complete",
        service.now()[0],
        attempt=record["attempt"],
        manifest=parts["digest"],
        detail=reason,
    )
    if reason:
        record["outcome"], record["method_status"], record["reason"] = "failed", "failed", reason
        item = evidence.failed(
            new,
            h,
            f"helper run failed: {reason}",
            paths=sorted(paths) or None,
            run=n,
            outcome="failed",
            manifest=parts["digest"],
        )
        record["evidence"] = item["id"]
        h["runs"].append(record)
        return
    stored = {k: v for k, v in parsed.items()}
    written.append(write_file(root, vid, h, f"run-{n}-result.json", dumps_json(stored)))
    target.update(
        status="complete",
        findings=len(parsed["findings"]),
        scanned=len(parsed["scanned"]),
        scanned_paths=parsed["scanned"],
    )
    if parsed["findings"]:
        record["outcome"], record["method_status"] = "findings", "ok"
        item = evidence.append(
            new,
            h,
            "ok",
            f"helper result with {len(parsed['findings'])} finding(s); "
            f"{len(parsed['scanned'])} file(s) scanned; manifest {parts['digest']}",
            parsed["scanned"] or [f["path"] for f in parsed["findings"]],
            run=n,
            outcome="findings",
            manifest=parts["digest"],
        )
        record["evidence"] = item["id"]
        record["findings"] = [
            evidence.finding(new, h, record, f, item["id"])["id"] for f in parsed["findings"]
        ]
    else:
        record["outcome"] = "clean"
        uncovered = sorted(set(parts["object_files"]["files"]) - set(parsed["scanned"]))
        record["uncovered"], record["uncovered_count"] = uncovered, len(uncovered)
        record["acceptance"] = {"state": "pending", "review": None, "evidence": None}
    h["runs"].append(record)


def _remove(root: Path, vid: str, written: list[str]) -> None:
    base = runs.run_dir(root, vid)
    for rel in written:
        (base / rel).unlink(missing_ok=True)


def _commit_refusal(
    root: Path,
    state: dict[str, Any],
    new: dict[str, Any],
    h: dict[str, Any],
    record: dict[str, Any],
    written: list[str],
    code: str,
    reason: str,
) -> Result:
    vid = state["verification_id"]
    _remove(root, vid, written)
    event(h, "not_executed", code, service.now()[0], attempt=record["attempt"], detail=reason)
    try:
        runs.commit_state(root, new, expected_revision=state["revision"])
    except GuardError:
        pass
    raise GuardError(
        "HELPER_NOT_EXECUTED",
        f"helper {h['id']} not executed: {reason}",
        GAP_NEXT,
        {"reason_code": code, "helper": h["id"], "verification_id": vid},
    )


def _commit(
    root: Path,
    state: dict[str, Any],
    new: dict[str, Any],
    h: dict[str, Any],
    record: dict[str, Any],
    written: list[str],
) -> Result:
    vid = state["verification_id"]
    record["ended_at"] = service.now()[0]
    if record["outcome"] in ("failed", "findings", "clean"):
        used = service.consumed(root, new)
        budget.cite(
            new,
            record["attempt"],
            {"helper"},
            {"pairs": {(h["check"], h["method"])}},
            used,
            service.now()[0],
            None,
        )
    try:
        runs.commit_state(root, new, expected_revision=state["revision"])
    except GuardError as exc:
        _remove(root, vid, written)
        if exc.code == "RUN_CANCELLED":
            ack(root, vid, True, "helper had finished; results not recorded")
            raise cancelled_error(vid, True, "helper had finished; results not recorded") from None
        raise
    used = service.consumed(root, new)
    data = {
        "verification_id": vid,
        "helper": h["id"],
        "run": record["n"],
        "outcome": record["outcome"],
        "reason": record["reason"],
        "evidence": record["evidence"],
        "findings": record["findings"],
        "samples": record["samples"],
        "limit": (record["target"] or {}).get("limit"),
        "seconds": record["seconds"],
        "time_limit": record["time_limit"],
        "time_limit_capped": record["time_limit_capped"],
        "uncovered_count": record["uncovered_count"],
        "attempt": record["attempt"],
        "budget": budget.status(new, used),
    }
    steps = {
        "findings": [
            "Ask the Reviewer to re-check verdict-affecting helper findings",
            "Reference helper-… evidence in ledger states",
        ],
        "clean": [
            "Register a reviewer attempt re-covering the helper (one extra attempt) for post-run acceptance",
            "Reference helper-… evidence in ledger states",
        ],
        "failed": [
            "The helper method counts as a failed auxiliary method; re-execute with a new helper attempt or "
            "rely on other methods"
        ],
        "samples_mismatch": [
            "Samples failed: submit a corrected helper under a new generation attempt, or rely "
            "on other methods"
        ],
    }[record["outcome"]]
    if record["outcome"] == "samples_mismatch":
        data["reason_code"] = "samples_mismatch"
        return Result(
            "guard helper run",
            False,
            data,
            [Problem("HELPER_NOT_EXECUTED", f"helper {h['id']} not executed: {record['reason']}")],
            steps,
        )
    return Result("guard helper run", True, data, [], steps)
