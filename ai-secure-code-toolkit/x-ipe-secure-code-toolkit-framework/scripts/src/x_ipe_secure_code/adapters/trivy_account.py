"""Per-check × scanner coverage accounting from the tool's own statements.

FEATURE-002-D, AC-002D-05a/05h/05i.

An object file counts as analysed only when the tool says so: a `lang-pkgs` result (vuln, filesystem), a
`config` result with a valid `MisconfSummary` (misconfig), a streaming-scanner debug line (secret) or the
detected image OS (vuln, image_archive). Everything else is a named gap.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .trivy_log import LogFacts

COMPOSE = re.compile(r"^(compose|docker-compose[^/]*)\.ya?ml$")
JAVA_ARCHIVE = (".jar", ".war", ".ear")
UNSUPPORTED_COMPOSE = "configuration type not supported by Trivy v0.76.1"
COMPOSE_STEP = "use another method such as Guard semantic review"
FALLBACK_GAP = "checks bundle missing / embedded-checks fallback — provision the checks bundle"
TRANSITIVE = "transitive dependencies not listed in the manifest are not analysed offline"
SHOWN = 10


def _summary(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    s, f = value.get("Successes"), value.get("Failures")
    ok = all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (s, f))
    return {"successes": s, "failures": f} if ok else None


def _names(items: list) -> str:
    paths = [i["path"] if isinstance(i, dict) else i for i in items]
    more = f" (+{len(paths) - SHOWN} more)" if len(paths) > SHOWN else ""
    return ", ".join(paths[:SHOWN]) + more


def _under(path: str, roots: dict[str, str]) -> str | None:
    for root, reason in roots.items():
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return reason
    return None


def account(
    *,
    scanner: str,
    mode: str,
    files: list[str],
    doc: dict[str, Any] | None,
    facts: LogFacts,
    bundle_linked: bool = True,
    archive: str | None = None,
) -> dict[str, Any]:
    """Accounting of one scanner over one check's object files (`files` are project-relative)."""
    acc: dict[str, Any] = {
        "scanner": scanner,
        "mode": mode,
        "analysed": [],
        "skipped": [],
        "unrecognized": [],
        "unsupported": [],
        "unaccounted": [],
        "packages": {},
        "skipped_packages": [],
        "misconf": {},
        "checks_source": None,
        "image": None,
        "diagnostics": [],
        "notes": [],
        "gaps": [],
    }
    results = (doc or {}).get("Results") or []
    gaps = acc["gaps"]
    if scanner == "vuln" and mode == "image_archive":
        os_info = ((doc or {}).get("Metadata") or {}).get("OS")
        types = sorted(
            {r.get("Type") for r in results if r.get("Class") in ("os-pkgs", "lang-pkgs") and r.get("Type")}
        )
        detected = isinstance(os_info, dict) and os_info.get("Family") and not facts.os_not_detected
        acc["image"] = {
            "archive": archive,
            "os": os_info if detected else "OS not detected",
            "package_types": types,
        }
        if detected:
            acc["analysed"].append(archive)
        else:
            acc["unaccounted"].append({"path": archive, "reason": "OS not detected"})
            gaps.append(f"vuln: {archive}: OS not detected; OS packages not analysed")
    elif scanner == "vuln":
        recognized = {r["Target"]: r for r in results if r.get("Class") == "lang-pkgs"}
        for path in files:
            if path in recognized:
                acc["analysed"].append(path)
                acc["packages"][path] = len(recognized[path].get("Packages") or [])
                if recognized[path].get("Type") == "pom":
                    if TRANSITIVE not in acc["notes"]:
                        acc["notes"].append(TRANSITIVE)
            elif path.endswith(JAVA_ARCHIVE):
                acc["unsupported"].append(
                    {
                        "path": path,
                        "reason": "Java archives are analysed only in image_archive mode (v0.76.1)",
                    }
                )
            else:
                acc["unrecognized"].append(
                    {"path": path, "reason": "not recognized as a dependency manifest or lockfile"}
                )
        count = facts.counts.get("language_files")
        if count is not None and count != len(recognized):
            gaps.append(
                f"vuln: the tool counted {count} language-specific file(s) but reported {len(recognized)}"
            )
    elif scanner == "misconfig":
        recognized = {
            r["Target"]: _summary(r.get("MisconfSummary")) for r in results if r.get("Class") == "config"
        }
        debug_only = set(facts.config_scanned)
        acc["diagnostics"] = [f"Scanned config file {p}" for p in facts.config_scanned[:100]]
        for path in files:
            if recognized.get(path) is not None:
                acc["analysed"].append(path)
                acc["misconf"][path] = recognized[path]
            elif COMPOSE.match(PurePosixPath(path).name):
                acc["unsupported"].append({"path": path, "reason": UNSUPPORTED_COMPOSE})
            elif path in debug_only:
                acc["unaccounted"].append(
                    {"path": path, "reason": "reported only in the debug log; no per-file result"}
                )
            else:
                acc["unrecognized"].append(
                    {
                        "path": path,
                        "reason": "not recognized as a configuration file (a "
                        "configuration-type override may apply)",
                    }
                )
        provisioned = bundle_linked and not facts.embedded_fallback
        acc["checks_source"] = "provisioned" if provisioned else "embedded fallback"
        if not provisioned:
            gaps.append(f"misconfig: {FALLBACK_GAP}")
        if acc["unsupported"]:
            gaps.append(
                f"misconfig: {UNSUPPORTED_COMPOSE}: {_names(acc['unsupported'])}; next step: {COMPOSE_STEP}"
            )
    elif scanner == "secret":
        scanned = set(facts.secret_scanned)
        for path in files:
            if path in scanned:
                acc["analysed"].append(path)
                continue
            reason = _under(path, facts.skipped_paths)
            if reason:
                acc["skipped"].append({"path": path, "reason": reason})
            else:
                acc["unaccounted"].append(
                    {
                        "path": path,
                        "reason": "not reported as scanned by the secret scanner "
                        "(built-in skip rules; the tool gives no reason)",
                    }
                )
        if facts.paths_truncated:
            gaps.append("secret: more scanned files than the parser keeps; coverage cannot be established")
    if scanner == "vuln" and facts.skipped_packages:
        acc["skipped_packages"] = list(facts.skipped_packages)
        names = ", ".join(p["name"] for p in facts.skipped_packages[:SHOWN])
        gaps.append(
            f"vuln: {len(facts.skipped_packages)} package(s) skipped by the tool (no version detected "
            f"offline): {names}; {TRANSITIVE}"
        )
    for key, label in (
        ("skipped", "skipped by the tool"),
        ("unrecognized", ""),
        ("unsupported", ""),
        ("unaccounted", ""),
    ):
        items = acc[key]
        if not items or (key == "unsupported" and scanner == "misconfig"):
            continue
        if scanner == "vuln" and mode == "image_archive" and key == "unaccounted":
            continue
        reason = label or items[0]["reason"]
        gaps.append(f"{scanner}: {len(items)} object file(s) {reason}: {_names(items)}")
    return acc
