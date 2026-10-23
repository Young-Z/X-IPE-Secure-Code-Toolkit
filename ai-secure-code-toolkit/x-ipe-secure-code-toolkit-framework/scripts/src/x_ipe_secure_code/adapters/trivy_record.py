"""Recording of a Trivy run (FEATURE-002-D, AC-002D-05b/05d/05e): per-check `runtime` evidence, findings,
sanitized shared output, accounting manifest and the run entry, committed once by `guard tool`.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

from ..atomic import dumps_json
from ..guard.mask import mask_text
from ..guard.model import MAX_EVIDENCE_TOTAL, MAX_TEXT
from ..knowledge import store
from ..results import Problem

SUMMARY_GAPS = 20


def _counts(accounting: list[dict[str, Any]]) -> dict[str, int]:
    scanned = sum(len(a["analysed"]) for a in accounting)
    skipped = sum(
        len(a["skipped"]) + len(a["unrecognized"]) + len(a["unsupported"]) + len(a["skipped_packages"])
        for a in accounting
    )
    return {
        "scanned": scanned,
        "skipped": skipped,
        "unaccounted": sum(len(a["unaccounted"]) for a in accounting),
    }


def _component_text(name: str, st: dict[str, Any]) -> str:
    if st.get("state") != "present":
        return f"{name} {st.get('state')}"
    meta = st.get("metadata") or {}
    base = f"{name} {st.get('repository')}:{st.get('tag')} ({st.get('registry')}, {st.get('content_digest')}"
    if name == "checks_bundle":
        return base + f", MajorVersion {meta.get('MajorVersion')}, Digest {meta.get('Digest')})"
    return base + f", Version {meta.get('Version')}, UpdatedAt {meta.get('UpdatedAt')}, age {st.get('age')})"


def _finding(f: dict[str, Any], fid: str, c: dict[str, Any], eid: str, n: int) -> dict[str, Any]:
    tool = {"adapter": "trivy", "run": n}
    for key in (
        "scanner",
        "rule_id",
        "tool_severity",
        "end_line",
        "package",
        "pkg_path",
        "layer",
        "target",
        "cwe_ids",
        "fingerprint",
        "data_source",
        "component",
        "type",
        "resolution",
        "category",
        "secret",
    ):
        if key in f:
            tool[key] = f[key]
    return {
        "id": fid,
        "rule": c["check_def"]["rule"],
        "check": c["check"],
        "location": {"path": f["path"], "line": f["line"]},
        "cwe": f.get("cwe"),
        "title": mask_text(f["title"])[0][:MAX_TEXT],
        "description": mask_text(f["description"])[0][:MAX_TEXT],
        "source": "trivy",
        "severity": f["severity"],
        "evidence": [eid],
        "disputed": False,
        "related": [],
        "merged_from": [],
        "merge_evidence": [],
        "merged_into": None,
        "tool": tool,
    }


def record(
    root: Path,
    vid: str,
    state: dict[str, Any],
    req: dict[str, Any],
    out: dict[str, Any],
    global_gaps: list[str],
    problems: list[Problem],
) -> dict[str, Any]:
    from ..guard.toolrun import _write_private

    new = copy.deepcopy(state)
    prefix, n, gap = out["prefix"], out["n"], out["gap"]
    if out.get("stage_gap"):
        global_gaps.append(out["stage_gap"])
    if out.get("staging_left") and "staging not removed after the run" not in global_gaps:
        global_gaps.append("staging not removed after the run")
    for p in out.get("problems", []):
        problems.append(Problem(p["code"], mask_text(p["message"])[0]))
    checks_out = {
        cid: {
            "status": pc["status"],
            "scanners": pc["scanners"],
            "mode": pc["mode"],
            "config_types": pc["config_types"],
            "processes": pc["processes"],
            "accounting": pc["accounting"],
            "components_used": pc["components_used"],
            "gaps": pc["gaps"],
        }
        for cid, pc in out["per_check"].items()
    }
    manifest = {
        "adapter": "trivy",
        "run": n,
        "archives": out["archives"],
        "components": out["components"],
        "rehash": out["rehash"],
        "checks": checks_out,
    }
    manifest_bytes, output_bytes = dumps_json(manifest), dumps_json(out["outputs"])
    used = sum(e.get("stored_bytes", 0) for e in state["evidence"])
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
    build = out["build"]
    evidence, findings, summary_checks, entry_checks = [], [], {}, {}
    m = 0
    for ci, c in enumerate(req["checks"]):
        cid = c["check"]
        pc = out["per_check"][cid]
        gaps = global_gaps + pc["gaps"]
        status = "precheck_failed" if gap is not None else (pc["status"] or "failed")
        ok = gap is None and status == "completed" and not gaps and stored is not None
        eid = f"{prefix}-{ci + 1}"
        counts = _counts(pc["accounting"])
        total = counts["scanned"] + counts["skipped"] + counts["unaccounted"]
        used_text = "; ".join(
            _component_text(name, out["components"].get(name, {})) for name in pc["components_used"]
        )
        summary = (
            f"trivy {build.get('version', '?')} {status} ({', '.join(c['scanners'])}, {c['mode']}; platform "
            f"validated: {'yes' if build.get('platform_validated') else 'no'}): {counts['scanned']}/{total} "
            f"analysed, {counts['skipped']} skipped, {counts['unaccounted']} unaccounted, "
            f"{len(pc['found'])} findings"
        )
        if used_text:
            summary += f"; components: {used_text}"
        if pc["components_used"] and out["rehash"]:
            summary += "; re-hash: " + ", ".join(
                f"{k} {out['rehash'].get(k, '?')}" for k in pc["components_used"]
            )
        if gaps:
            summary += "; gaps: " + "; ".join(gaps[:SUMMARY_GAPS])
        masked, kinds = mask_text(summary[:MAX_TEXT])
        evidence.append(
            {
                "id": eid,
                "kind": "runtime",
                "method": "trivy",
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
        own = []
        for f in pc["found"]:
            m += 1
            own.append(f"{prefix}-f{m}")
            findings.append(_finding(f, own[-1], c, eid, n))
        summary_checks[cid] = {
            "status": status,
            "method_status": "ok" if ok else "failed",
            "gaps": gaps[:20],
            "findings": own,
        }
        entry_checks[cid] = {
            **checks_out[cid],
            "status": status,
            "method_status": "ok" if ok else "failed",
            "counts": counts,
            "gaps": gaps[:50],
        }
    run_entry = {
        "n": n,
        "adapter": "trivy",
        **build,
        "time_limit": req["time_limit"],
        "staged_digests": out["staged_digests"],
        "archives": out["archives"],
        "components": out["components"],
        "rehash": out["rehash"],
        "checks": entry_checks,
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
