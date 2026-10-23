"""`secure-code guard tool` (FEATURE-002-B): run an Adapter inside an open Guard verification.

Validates a typed request, pre-checks the registered binary against the official digests, stages
private copies (binary, targets, rules), runs one tool process per rule, accounts for every object
file from what the tool reported, masks the output and commits per-check runtime evidence and tool
findings in one state write after cleanup and integrity re-checks.
"""

from __future__ import annotations

import copy
import hashlib
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from ..adapters import opengrep as og
from ..adapters import process, registry_store, rules, safe_io, trivy_record, trivy_run
from ..atomic import atomic_write_bytes, dumps_json
from ..knowledge import store
from ..results import Problem, Result
from . import budget, runs, service, targets
from .mask import mask_text
from .model import MAX_EVIDENCE_TOTAL, MAX_TEXT, GuardError, load_request
from .toolctl import ToolCancelled
from .toolctl import ack as _ack
from .toolctl import cancelled_error as _cancelled_error
from .toolctl import start_attempt as _start_attempt
from .toolreq import SCHEMA_TOOL, STEP
from .toolreq import validate as _validate

MAX_STAGE_BYTES = 512 * 1024 * 1024
MAX_STAGE_FILES = 50_000
STDOUT_CAP = 16 * 1024 * 1024
MANIFEST_PER_FILE, MANIFEST_PER_RULE, MANIFEST_SLACK = 96, 4096, 1024 * 1024
STATUS_ORDER = ("completed", "completed_with_errors", "failed", "timed_out")
UNACCOUNTED_HINT = (
    "the tool did not analyse these files (other languages or not reported); make the check "
    "object list only files the rules apply to, or add another method"
)


# --------------------------------------------------------------------------- helpers
def _artifact_target(state: dict[str, Any], rel: str) -> dict[str, Any]:
    return next(t for t in state["artifact"]["targets"] if t["path"] == rel)


def _under(path: str, roots: list[str]) -> bool:
    return any(path == r or r == "." or path.startswith(r + "/") for r in roots)


def _sweep(root: Path, vid: str, state: dict[str, Any], adapter: str) -> None:
    """Remove staging and unreferenced Adapter files left by an interrupted run."""
    run_dir = runs.run_dir(root, vid)
    referenced = {e.get("stored") for e in state["evidence"]}
    referenced |= {
        r.get("manifest", {}).get("path") for r in state.get("adapter_runs", []) if r.get("manifest")
    }
    leftovers = []
    staging = run_dir / "adapter"
    if staging.is_dir() and not staging.is_symlink():
        leftovers += [p for p in staging.iterdir() if p.name.startswith("stage-")]
    evidence = run_dir / "evidence"
    if evidence.is_dir() and not evidence.is_symlink():
        leftovers += [
            p
            for p in evidence.iterdir()
            if p.name.startswith(f"{adapter}-") and f"evidence/{p.name}" not in referenced
        ]
    for path in leftovers:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
        if path.exists() or path.is_symlink():
            raise GuardError(
                "STAGING_LEFTOVER",
                f"Could not remove {path.name} left by an interrupted tool run",
                "Remove it manually from the private run folder, then retry",
            )


def _tool_home() -> Path | registry_store.Gap:
    """A private disposable home outside the project: Opengrep v1.31.0 unpacks its runtime into
    `$XDG_CACHE_HOME` and silently produces no output when that path has non-ASCII characters."""
    base = tempfile.gettempdir()
    if not base.isascii():
        return registry_store.Gap(
            "TOOL_HOME_UNSUPPORTED",
            f"The system temporary folder path is not ASCII-only ({base}); the tool cannot run from it",
            "Set TMPDIR to an existing private folder with an ASCII-only path, then retry",
        )
    return Path(tempfile.mkdtemp(prefix="secure-code-tool-home-", dir=base))


def _faithful(config: bytes, rule: dict[str, Any]) -> bool:
    """The staged single-rule config must parse back to exactly the source rule."""
    try:
        return rules.load_rules(config) == [rule]
    except rules.RuleError:
        return False


_env = process.minimal_env


def _worst(statuses: list[str]) -> str:
    if statuses == ["precheck_failed"]:
        return "precheck_failed"
    return max(statuses, key=STATUS_ORDER.index) if statuses else "failed"


def _text(value: str) -> str:
    return mask_text(value)[0][:MAX_TEXT]


def _write_private(root: Path, vid: str, name: str, data: bytes) -> str:
    rel = f"{runs.run_rel(vid)}/evidence/{name}"
    store.ensure_safe(root, f"{runs.run_rel(vid)}/evidence", expect_dir=True)
    store.ensure_safe(root, rel, expect_dir=False)
    atomic_write_bytes(root / rel, data, private=True)
    return f"evidence/{name}"


# --------------------------------------------------------------------------- execution
def _execute(root: Path, vid: str, state: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
    adapter, n = req["adapter"], state.get("next_adapter_run", 1)
    prefix = f"{adapter}-{n}"
    taken = {e["id"].casefold() for e in state["evidence"]} | {f["id"].casefold() for f in state["findings"]}
    if any(x.startswith(prefix.casefold() + "-") for x in taken):
        raise GuardError("ID_COLLISION", f"Adapter ids {prefix}-… already exist", "Report this run folder")
    if adapter == "trivy":
        return trivy_run.execute(root, vid, state, req, n, prefix)
    stage = runs.run_dir(root, vid) / "adapter" / f"stage-{secrets.token_hex(8)}"
    stage.mkdir(parents=True, mode=0o700)
    per_check = {
        c["check"]: {"status": None, "gaps": [], "rules": [], "acc": None, "found": []} for c in req["checks"]
    }
    run_gap: registry_store.Gap | None = None
    build_info: dict[str, Any] = {}
    staged_digests: dict[str, str] = {}
    home: Path | None = None
    try:
        checked = registry_store.check(root, adapter, stage / "bin" / adapter)
        made = _tool_home() if not isinstance(checked, registry_store.Gap) else None
        if isinstance(checked, registry_store.Gap):
            run_gap = checked
        elif isinstance(made, registry_store.Gap):
            run_gap = made
        else:
            home = made
            record, build = checked
            build_info = {
                "version": build.version,
                "asset": build.asset,
                "platform_validated": build.validated,
                "platform": {"os": build.os, "arch": build.arch, "libc": build.libc},
                "binary_digest": record["digest"],
            }
            run_gap = _stage_and_run(root, state, req, stage, home, per_check, staged_digests)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if home is not None:
            shutil.rmtree(home, ignore_errors=True)
    staging_left = stage.exists() or (home is not None and home.exists())
    return {
        "n": n,
        "prefix": prefix,
        "gap": run_gap,
        "per_check": per_check,
        "build": build_info,
        "staged_digests": staged_digests,
        "staging_left": staging_left,
    }


def _stage_and_run(
    root: Path,
    state: dict[str, Any],
    req: dict[str, Any],
    stage: Path,
    home: Path,
    per_check: dict[str, Any],
    staged_digests: dict[str, str],
) -> registry_store.Gap | None:
    owners = sorted(
        {targets.owning_target(state["artifact"], t) for c in req["checks"] for t in c["targets"]}
    )
    files: list[str] = []
    irregular: list[str] = []
    changed: set[str] = set()
    used_bytes = 0
    try:
        for index, owner in enumerate(owners):
            entry = _artifact_target(state, owner)
            if entry["digest"] is None:
                changed.add(owner)
                continue
            # a target nested in another staged target is copied there already; stage it apart only
            # to bind its own digest, then discard that copy
            nested = any(o != owner and _under(owner, [o]) for o in owners) and not targets.not_in_tree(owner)
            dest = stage / "verify" / str(index) if nested else stage / "src"
            staged = targets.stage(
                root,
                owner,
                entry["kind"],
                dest,
                MAX_STAGE_BYTES - used_bytes,
                MAX_STAGE_FILES - len(files),
            )
            used_bytes += staged["bytes"]
            staged_digests[owner] = staged["digest"]
            if staged["digest"] != entry["digest"]:
                changed.add(owner)
            if nested:
                shutil.rmtree(dest, ignore_errors=True)
                continue
            files += staged["files"]
            irregular += staged["irregular"]
    except safe_io.TooLarge as exc:
        return registry_store.Gap(
            "STAGE_TOO_LARGE", f"Targets too large to stage: {exc}", "Use narrower targets or another method"
        )
    except (OSError, safe_io.UnsafePath) as exc:
        return registry_store.Gap(
            "STAGE_UNSAFE",
            f"Targets could not be staged safely: {exc}",
            "Remove links or retry when the files are stable",
        )
    used = sum(e.get("stored_bytes", 0) for e in state["evidence"])
    bound = sum(len(f.encode("utf-8", "surrogateescape")) + MANIFEST_PER_FILE for f in files)
    bound += MANIFEST_PER_RULE * sum(len(f["rules"]) for c in req["checks"] for f in c["rule_files"])
    if used + bound + MANIFEST_SLACK > MAX_EVIDENCE_TOTAL:
        raise GuardError(
            "EVIDENCE_QUOTA",
            "Not enough evidence quota left to keep the tool accounting",
            "Open a new verification or use narrower targets",
        )
    deadline = time.monotonic() + req["time_limit"]
    env = _env(stage, home)
    binary = stage / "bin" / req["adapter"]
    src_prefix = str(stage / "src") + "/"
    for ci, check in enumerate(req["checks"]):
        state_check = per_check[check["check"]]
        object_files = [f for f in files if _under(f, check["targets"])]
        object_irregular = [f for f in irregular if _under(f, check["targets"])]
        moved = sorted({targets.owning_target(state["artifact"], t) for t in check["targets"]} & changed)
        if moved:
            state_check["status"] = "failed"
            state_check["gaps"].append(
                f"target {', '.join(moved)} changed since the verification opened; not run"
            )
            continue
        docs = []
        statuses = []
        k = 0
        for rule_file in check["rule_files"]:
            for rule in rule_file["rules"]:
                k += 1
                rule_path = stage / "rules" / f"{ci + 1}-{k}.yaml"
                rule_path.parent.mkdir(parents=True, exist_ok=True)
                config = rules.dump_single(rule).encode("utf-8")
                rule_path.write_bytes(config)
                info = {
                    "rule_id": rule["id"],
                    "rule_file": rule_file["path"],
                    "config_digest": "sha256:" + hashlib.sha256(config).hexdigest(),
                }
                if not _faithful(rule_path.read_bytes(), rule):
                    info.update(
                        status="failed", exit=None, seconds=0.0, gaps=["rule could not be staged faithfully"]
                    )
                    statuses.append("failed")
                    state_check["rules"].append(info)
                    continue
                if time.monotonic() >= deadline:
                    info.update(
                        status="timed_out", exit=None, seconds=0.0, gaps=["not run before the time limit"]
                    )
                    statuses.append("timed_out")
                    state_check["rules"].append(info)
                    continue
                argv = og.build_argv(
                    binary,
                    rule_path,
                    [stage / "src" / t for t in check["targets"]],
                    req["include_ignored"],
                )
                argv[2:2] = req.get("argv_extra", [])
                outcome = process.run(
                    argv,
                    stage / "work",
                    env,
                    deadline,
                    stage / "out" / f"{ci + 1}-{k}.json",
                    STDOUT_CAP,
                    req.get("should_stop"),
                )
                req["groups_gone"] = req.get("groups_gone", True) and outcome.group_gone
                if outcome.cancelled:
                    raise ToolCancelled(req["groups_gone"])
                doc = og.parse(stage / "out" / f"{ci + 1}-{k}.json")
                status = og.status_of(outcome, doc)
                statuses.append(status)
                gaps = []
                if doc is None:
                    raw = (stage / "out" / f"{ci + 1}-{k}.json").read_bytes()[:65536]
                    info["output"] = {"incomplete": True, "excerpt": _text(raw.decode("utf-8", "replace"))}
                    gaps.append(
                        f"tool exited {outcome.exit} with no output"
                        if not raw and not outcome.timed_out
                        else f"tool output not parseable ({status})"
                    )
                else:
                    clean = og.sanitize(doc, src_prefix)
                    info["output"] = clean
                    docs.append(clean)
                    gaps += og.rule_gaps(clean)
                    found, unattributed = og.results(clean, rule["id"])
                    for f in found:
                        f["rule_file"] = rule_file["path"]
                    state_check["found"] += found
                    if unattributed:
                        gaps.append(f"{len(unattributed)} result(s) not attributable to rule {rule['id']}")
                        info["unattributed"] = unattributed[:100]
                    for err in clean.get("errors") or []:
                        if not isinstance(err, dict):
                            continue
                        gaps.append(f"tool error: {str(err.get('message') or err.get('type'))[:300]}")
                if status != "completed":
                    gaps.append(
                        f"tool status {status} (exit {outcome.exit})"
                        + (f": {_text(outcome.stderr_tail[-300:])}" if outcome.stderr_tail else "")
                    )
                info.update(status=status, exit=outcome.exit, seconds=outcome.seconds, gaps=gaps)
                state_check["rules"].append(info)
        acc = og.account(object_files, docs)
        bad_py = og.unparseable_python(stage / "src", acc["scanned"])
        for f in bad_py:
            acc["scanned"].remove(f)
            acc["unaccounted"].append(f)
        acc["unaccounted"] = sorted(acc["unaccounted"])
        acc["not_followed"] = sorted(object_irregular)
        acc["syntax_errors"] = bad_py
        acc["non_python_scanned"] = sorted(
            {Path(f).suffix or Path(f).name for f in acc["scanned"] if not f.endswith(og.PYTHON)}
        )
        state_check["acc"] = acc
        state_check["status"] = _worst(statuses)
        gaps = state_check["gaps"]
        if not object_files and not object_irregular:
            gaps.append("no object file to scan under the requested targets")
        if acc["skipped"]:
            gaps.append(
                f"{len(acc['skipped'])} object file(s) skipped by the tool, e.g. "
                f"{acc['skipped'][0]['path']} ({acc['skipped'][0]['reason']})"
            )
        if bad_py:
            gaps.append(f"{len(bad_py)} Python file(s) with a syntax error: not analysable, e.g. {bad_py[0]}")
        others = [f for f in acc["unaccounted"] if f not in bad_py]
        if others:
            gaps.append(
                f"{len(others)} object file(s) not reported by the tool, e.g. {others[0]}: {UNACCOUNTED_HINT}"
            )
        if object_irregular:
            gaps.append(
                f"{len(object_irregular)} link(s), special file(s) or non-UTF-8 name(s) not analysed, "
                f"e.g. {object_irregular[0]}"
            )
        for info in state_check["rules"]:
            gaps += [f"rule {info['rule_id']}: {g}" for g in info["gaps"]]
    return None


# --------------------------------------------------------------------------- recording
def _integrity(root: Path, state: dict[str, Any], req: dict[str, Any], out: dict[str, Any]) -> tuple:
    """Run-level gaps shared by every Adapter: pre-check, staging left, originals/context/rules changed."""
    gap: registry_store.Gap | None = out["gap"]
    problems: list[Problem] = []
    global_gaps: list[str] = []
    if gap is not None:
        global_gaps.append(f"{gap.reason}")
    if out["staging_left"]:
        global_gaps.append("staging not removed after the run")
    for owner, digest in sorted(out["staged_digests"].items()):
        if targets.observe(root, owner)["digest"] != digest:
            global_gaps.append(f"original {owner} changed during the run")
    for ctx in state["artifact"]["context"]:
        if targets.snapshot(root, ctx["path"], ctx["kind"])["digest"] != ctx["digest"]:
            global_gaps.append(f"context file {ctx['path']} changed during the run")
    for c in req["checks"]:
        for f in c["rule_files"]:
            try:
                now = safe_io.hash_fd(safe_io.open_nofollow(root, f["path"]))
            except (OSError, safe_io.UnsafePath):
                now = None
            if now != "sha256:" + hashlib.sha256(f["data"]).hexdigest():
                global_gaps.append(f"rule file {f['path']} changed during the run")
    if any("changed during the run" in g for g in global_gaps):
        problems.append(
            Problem("ORIGINALS_CHANGED", "Files changed while the tool ran; its evidence is not used")
        )
    return global_gaps, problems


def _record(root: Path, vid: str, state: dict[str, Any], req: dict[str, Any], out: dict[str, Any]) -> dict:
    global_gaps, problems = _integrity(root, state, req, out)
    if req["adapter"] == "trivy":
        return trivy_record.record(root, vid, state, req, out, global_gaps, problems)
    new = copy.deepcopy(state)
    prefix, n = out["prefix"], out["n"]
    gap: registry_store.Gap | None = out["gap"]

    manifest = {
        "adapter": req["adapter"],
        "run": n,
        "checks": {
            cid: {
                "status": pc["status"],
                "accounting": pc["acc"],
                "rules": [{k: v for k, v in r.items() if k != "output"} for r in pc["rules"]],
                "gaps": pc["gaps"],
            }
            for cid, pc in out["per_check"].items()
        },
    }
    output = {
        cid: {r["rule_id"]: r.get("output") for r in pc["rules"]} for cid, pc in out["per_check"].items()
    }
    used = sum(e.get("stored_bytes", 0) for e in state["evidence"])
    manifest_bytes = dumps_json(og.sanitize(manifest, ""))
    output_bytes = dumps_json(output)
    stored = manifest_rel = None
    if gap is None:
        if used + len(manifest_bytes) + len(output_bytes) > MAX_EVIDENCE_TOTAL:
            global_gaps.append("tool output and accounting manifest not retained (evidence quota)")
        else:
            try:
                manifest_rel = _write_private(root, vid, f"{prefix}-manifest.json", manifest_bytes)
                stored = _write_private(root, vid, f"{prefix}-output.json", output_bytes)
            except (OSError, store.StoreError) as exc:
                global_gaps.append(f"tool output or accounting manifest not retained ({exc})")
                stored = manifest_rel = None

    evidence, findings = [], []
    m = 0
    summary_checks: dict[str, Any] = {}
    for ci, c in enumerate(req["checks"]):
        cid = c["check"]
        pc = out["per_check"][cid]
        acc = pc["acc"] or {"scanned": [], "skipped": [], "unaccounted": [], "non_python_scanned": []}
        gaps = global_gaps + pc["gaps"]
        status = "precheck_failed" if gap is not None else (pc["status"] or "failed")
        ok = (
            gap is None
            and status == "completed"
            and not gaps
            and stored is not None
            and manifest_rel is not None
        )
        eid = f"{prefix}-{ci + 1}"
        own = pc["found"]
        summary = (
            f"{req['adapter']} {out['build'].get('version', '?')} {status}: {len(acc['scanned'])} scanned, "
            f"{len(acc['skipped'])} skipped, {len(acc['unaccounted'])} unaccounted, {len(own)} findings"
        )
        if gaps:
            summary += "; gaps: " + "; ".join(gaps[:20])
        if acc.get("non_python_scanned"):
            summary += (
                f"; limit: files with syntax errors in {', '.join(acc['non_python_scanned'][:10])} files "
                "may be silently unanalysed (tool limit)"
            )
        masked, kinds = mask_text(summary[:MAX_TEXT])
        evidence.append(
            {
                "id": eid,
                "kind": "runtime",
                "method": req["adapter"],
                "method_status": "ok" if ok else "failed",
                "checks": [cid],
                "paths": c["targets"],
                "lines": None,
                "summary": masked,
                "stored": stored,
                "stored_bytes": (len(manifest_bytes) + len(output_bytes)) if ci == 0 and stored else 0,
                "masked": bool(kinds),
                "masked_types": kinds,
                "adapter_run": n,
            }
        )
        for f in own:
            m += 1
            findings.append(
                {
                    "id": f"{prefix}-f{m}",
                    "rule": c["check_def"]["rule"],
                    "check": cid,
                    "location": {
                        "path": f["path"],
                        "line": f["line"] if isinstance(f["line"], int) and f["line"] > 0 else None,
                    },
                    "cwe": f["cwe"],
                    "title": f["rule_id"],
                    "description": _text(f["message"]),
                    "source": req["adapter"],
                    "severity": f["severity"],
                    "evidence": [eid],
                    "disputed": False,
                    "related": [],
                    "merged_from": [],
                    "merge_evidence": [],
                    "merged_into": None,
                    "tool": {
                        "adapter": req["adapter"],
                        "run": n,
                        "rule_id": f["rule_id"],
                        "rule_file": f["rule_file"],
                        "tool_severity": f["tool_severity"],
                        "end_line": f["end_line"],
                        "fingerprint": f["fingerprint"],
                    },
                }
            )
        summary_checks[cid] = {
            "status": status,
            "method_status": "ok" if ok else "failed",
            "gaps": gaps[:20],
            "findings": [x["id"] for x in findings if x["check"] == cid],
        }
    run_entry = {
        "n": n,
        "adapter": req["adapter"],
        **out["build"],
        "include_ignored": req["include_ignored"],
        "time_limit": req["time_limit"],
        "rules": [
            {
                "check": c["check"],
                "path": f["path"],
                "digest": "sha256:" + hashlib.sha256(f["data"]).hexdigest(),
                "ids": [r["id"] for r in f["rules"]],
                "config_digests": {
                    r["rule_id"]: r["config_digest"]
                    for r in out["per_check"][c["check"]]["rules"]
                    if r["rule_file"] == f["path"]
                },
            }
            for c in req["checks"]
            for f in c["rule_files"]
        ],
        "staged_digests": out["staged_digests"],
        "checks": {
            cid: {
                "status": s["status"],
                "method_status": s["method_status"],
                "exit": [r.get("exit") for r in out["per_check"][cid]["rules"]],
                "seconds": round(sum(r.get("seconds") or 0 for r in out["per_check"][cid]["rules"]), 2),
                "counts": {
                    k: len((out["per_check"][cid]["acc"] or {}).get(k, []))
                    for k in ("scanned", "skipped", "unaccounted")
                },
                "gaps": s["gaps"],
            }
            for cid, s in summary_checks.items()
        },
        "manifest": {"path": manifest_rel, "digest": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()}
        if manifest_rel
        else None,
        "gap": {"code": gap.code, "reason": gap.reason} if gap else None,
    }
    new["evidence"] += evidence
    new["findings"] += findings
    new.setdefault("adapter_runs", []).append(run_entry)
    new["next_adapter_run"] = n + 1
    return {"state": new, "problems": problems, "checks": summary_checks, "gap": gap}


# --------------------------------------------------------------------------- command
def run_tool(project: str | None, run_id: str, request: str) -> Result:
    """Run an Adapter for planned checks of an open verification and record per-check runtime evidence."""
    command = "guard tool"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_TOOL, "TOOL_REQUEST_INVALID", STEP)
        vid = runs.check_id(run_id)
        seen: dict[str, Any] = {}
        try:
            with service._locked(root):
                state = runs.read_state(root, vid)
                seen["state"] = state
                runs.refuse_closed(root, vid)
                if state["status"] != "open":
                    raise GuardError(
                        "RUN_FINISHED",
                        f"Verification {vid} is already concluded",
                        "Start a new verification with secure-code guard open",
                    )
                if state["plan"] is None:
                    raise GuardError(
                        "PLAN_REQUIRED",
                        "No check plan was recorded yet",
                        f"Record the plan first: secure-code guard plan --run {vid}",
                    )
                req = _validate(root, state, doc)
                _sweep(root, vid, state, req["adapter"])
                attempt = _start_attempt(root, vid, state, req)
                req["should_stop"] = lambda: runs.cancel_marker(root, vid) is not None
                runs.write_run_json(
                    root,
                    vid,
                    "tool-active.json",
                    {"pid": os.getpid(), "attempt": attempt["id"], "at": attempt["started_at"]},
                )
                try:
                    try:
                        out = _execute(root, vid, state, req)
                    except ToolCancelled as exc:
                        detail = (
                            "tool processes stopped" if exc.confirmed else "tool process group still present"
                        )
                        _ack(root, vid, exc.confirmed, detail)
                        raise _cancelled_error(vid, exc.confirmed, detail) from None
                    recorded = _record(root, vid, state, req, out)
                    new = recorded["state"]
                    done = next(a for a in new["attempts"] if a["id"] == attempt["id"])
                    done.update(status="finished", finished_at=service.now()[0], tool_run=out["n"])
                    done["overrun_seconds"] = round(
                        max(0.0, service.consumed(root, new) - done["deadline_consumed"]), 1
                    )
                    entry = new["adapter_runs"][-1]
                    entry["requested_time_limit"] = req["requested_time_limit"]
                    entry["time_limit_capped"] = req["time_limit"] < req["requested_time_limit"]
                    try:
                        runs.commit_state(root, new, expected_revision=state["revision"])
                    except GuardError as exc:
                        # never keep output of a commit that lost; only the exact files _record wrote
                        runs.remove_evidence_files(
                            root, vid, [f"{out['prefix']}-manifest.json", f"{out['prefix']}-output.json"]
                        )
                        if exc.code == "RUN_CANCELLED":
                            gone = req.get("groups_gone", True)
                            _ack(root, vid, gone, "tool had finished; results not recorded")
                            raise _cancelled_error(
                                vid, gone, "tool had finished; results not recorded"
                            ) from None
                        raise
                finally:
                    runs.remove_run_file(root, vid, "tool-active.json")
        except GuardError as exc:
            if "state" in seen:  # every run-bound refusal carries the budget status (AC-002C-01b)
                try:
                    exc.data.setdefault(
                        "budget", budget.status(seen["state"], service.consumed(root, seen["state"]))
                    )
                except (GuardError, OSError, KeyError, ValueError):
                    pass
            raise
        gap = recorded["gap"]
        data = {
            "verification_id": vid,
            "run": out["n"],
            "adapter": req["adapter"],
            "status": "precheck_failed"
            if gap
            else _worst(
                [c["status"] for c in recorded["checks"].values() if c["status"] in STATUS_ORDER]
                or ["precheck_failed"]
            ),
            "checks": recorded["checks"],
            "attempt": attempt["id"],
            "time_limit": req["time_limit"],
            "time_limit_capped": req["time_limit"] < req["requested_time_limit"],
            "budget": budget.status(new, service.consumed(root, new)),
        }
        problems = list(recorded["problems"])
        steps = []
        if gap:
            problems.insert(0, Problem(gap.code, gap.reason))
            steps.append(gap.next_step)
        steps.append(
            f"Record ledger states referencing the {req['adapter']}-{out['n']}-… evidence; ask the Reviewer "
            "to re-check verdict-affecting tool findings"
        )
        return Result(command, True, data, problems, steps)

    return service._call(command, project, body)
