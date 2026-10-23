"""Trivy v0.76.1 Adapter core (FEATURE-002-D): pinned constants, validated argv, output parsing,
sanitizing (secret values never kept) and normalization into Guard findings.

Observed tool facts come from the tool-level validation (x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/
tool-validation/README.md); a new tool version needs a new validation before these constants are trusted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..guard.mask import mask_text
from . import process

VERSION = "0.76.1"
SCANNERS = ("vuln", "misconfig", "secret")
MODES = ("filesystem", "image_archive")
COMPONENTS = ("vulnerability_db", "java_db", "checks_bundle")
SUBTREE = {"vulnerability_db": "db", "java_db": "java-db", "checks_bundle": "policy"}
# Misconfiguration types accepted by `--file-patterns`: exactly the `--misconfig-scanners` default list of
# the real v0.76.1 `trivy fs|config|image --help` (acceptance FF-01, acceptance/tool-level/ff-help-tf.jsonl;
# Bug Fix TASK-059). Compose is not one. A new tool version needs this list re-validated.
CONFIG_TYPES = (
    "azure-arm",
    "cloudformation",
    "dockerfile",
    "helm",
    "kubernetes",
    "terraform",
    "terraformplan-json",
    "terraformplan-snapshot",
    "ansible",
)
REPOSITORIES = {
    "mirror.gcr.io": {
        "vulnerability_db": "mirror.gcr.io/aquasec/trivy-db:2",
        "java_db": "mirror.gcr.io/aquasec/trivy-java-db:1",
        "checks_bundle": "mirror.gcr.io/aquasec/trivy-checks:2",
    },
    "ghcr.io": {
        "vulnerability_db": "ghcr.io/aquasecurity/trivy-db:2",
        "java_db": "ghcr.io/aquasecurity/trivy-java-db:1",
        "checks_bundle": "ghcr.io/aquasecurity/trivy-checks:2",
    },
}
# Hosts each provisioning operation is known to contact (tool-level validation, DAO-001).
KNOWN_HOSTS = {
    (VERSION, "mirror.gcr.io"): ("mirror.gcr.io",),
    (VERSION, "ghcr.io"): ("ghcr.io", "pkg-containers.githubusercontent.com"),
}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "unknown"}
OFFLINE = [
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
    "--offline-scan",
    "--skip-version-check",
    "--disable-telemetry",
]
COMMON = [
    "--no-progress",
    "--format",
    "json",
    "--debug",
    "--config",
    "",
    "--ignorefile",
    "",
    "--secret-config",
    "",
]
RESULT_CLASSES = ("lang-pkgs", "os-pkgs", "config", "secret")
MAX_DESCRIPTION = 8 * 1024
LIMIT = (
    "The repository and its known hosts (v0.76.1 tool-level validation) are a configuration-level "
    "expectation "
    "of the launched tool, not network enforcement; requests and redirects are not individually gated and "
    "contacts outside the known-host list cannot be detected at runtime. Registries are not interchangeable: "
    "the repository, tag and digest actually used are recorded."
)


def needed_components(scanner: str, mode: str) -> list[str]:
    if scanner == "vuln":
        return ["vulnerability_db", "java_db"] if mode == "image_archive" else ["vulnerability_db"]
    return ["checks_bundle"] if scanner == "misconfig" else []


def tool_env(stage: Path, home: Path) -> dict[str, str]:
    """Environment of every Trivy process: the shared minimal one plus `TZ=UTC`.

    Trivy formats log times and the checks-bundle `DownloadedAt` in the process's local zone; UTC keeps
    them in the recorded `Z` form on any host (offsets are still accepted when parsing).
    """
    return {**process.minimal_env(stage, home), "TZ": "UTC"}


def provision_step(component: str, registry: str = "mirror.gcr.io", vid: str = "<vid>") -> str:
    hosts = ", ".join(KNOWN_HOSTS[(VERSION, registry)])
    return (
        "Ask the user for tool_update grants covering every known host of "
        f"{REPOSITORIES[registry][component]} "
        f"({hosts}), then a Maintainer runs secure-code tools provision --tool trivy --run {vid} "
        f"--component {component}"
    )


def scan_argv(
    binary: Path,
    scanner: str,
    mode: str,
    root_or_archive: Path,
    scan_folder: Path,
    timeout_s: int,
    patterns=(),
) -> list[str]:
    """Exact scan argv validated for v0.76.1 (every update, lookup, check and project configuration off)."""
    sub = ["fs"] if mode == "filesystem" else ["image", "--input", str(root_or_archive)]
    argv = [
        str(binary),
        *sub,
        "--scanners",
        scanner,
        *OFFLINE,
        *COMMON,
        "--cache-dir",
        str(scan_folder),
        "--timeout",
        f"{timeout_s}s",
    ]
    if scanner == "vuln":
        argv.append("--list-all-pkgs")
    if mode == "image_archive":
        argv += ["--cache-backend", "memory"]
    for p in patterns:
        argv += ["--file-patterns", f"{p.type}:{re.escape(p.path)}"]
    return argv + ([str(root_or_archive)] if mode == "filesystem" else [])


def provision_argv(binary: Path, component: str, repo: str, op: Path, timeout_s: int) -> list[str]:
    """Exact provisioning argv validated for v0.76.1: one repository, no fallback list, no project input."""
    tail = [
        "--skip-version-check",
        "--disable-telemetry",
        "--no-progress",
        "--cache-dir",
        str(op / "cache"),
        "--timeout",
        f"{timeout_s}s",
    ]
    if component == "vulnerability_db":
        return [str(binary), "image", "--download-db-only", "--db-repository", repo, *tail]
    if component == "java_db":
        return [str(binary), "image", "--download-java-db-only", "--java-db-repository", repo, *tail]
    return [
        str(binary),
        "fs",
        "--scanners",
        "misconfig",
        "--checks-bundle-repository",
        repo,
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-version-check",
        "--disable-telemetry",
        "--no-progress",
        "--format",
        "json",
        "--cache-dir",
        str(op / "cache"),
        "--timeout",
        f"{timeout_s}s",
        str(op / "empty"),
    ]


def guard_severity(value: Any) -> str:
    return SEVERITY.get(value, "unknown") if isinstance(value, str) else "unknown"


def parse_output(raw: bytes | None) -> dict[str, Any] | None:
    """The tool's JSON document if well-formed for v0.76.1, else None."""
    if not raw:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("SchemaVersion"), int):
        return None
    if not isinstance(doc.get("ArtifactName"), str) or not isinstance(doc.get("ArtifactType"), str):
        return None
    results = doc.get("Results", [])
    if not isinstance(results, list) or ("Metadata" in doc and not isinstance(doc["Metadata"], dict)):
        return None
    for r in results:
        if (
            not isinstance(r, dict)
            or not isinstance(r.get("Target"), str)
            or r.get("Class") not in RESULT_CLASSES
        ):
            return None
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets", "Packages"):
            if key in r and (not isinstance(r[key], list) or not all(isinstance(x, dict) for x in r[key])):
                return None
    return doc


def _masked_length(match: Any) -> int:
    runs = re.findall(r"\*+", match) if isinstance(match, str) else []
    return max((len(r) for r in runs), default=0)


def _clean(value: Any, prefix: str) -> Any:
    if isinstance(value, dict):
        return {k: _clean(v, prefix) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v, prefix) for v in value]
    if isinstance(value, str):
        if prefix:
            value = value.replace(prefix + "/", "").replace(prefix, "")
        return mask_text(value)[0]
    return value


def sanitize(doc: dict[str, Any], stage_prefix: str) -> dict[str, Any]:
    """Drop secret values and context lines (Match, Code, Offset, CauseMetadata.Code) before anything is kept;
    strip the private stage path and mask every remaining string."""
    out = dict(doc)
    results = []
    for r in doc.get("Results") or []:
        r = dict(r)
        if "Secrets" in r:
            secrets_ = []
            for s in r["Secrets"]:
                kept = {k: v for k, v in s.items() if k not in ("Match", "Code", "Offset")}
                kept["MaskedLength"] = _masked_length(s.get("Match"))
                secrets_.append(kept)
            r["Secrets"] = secrets_
        if "Misconfigurations" in r:
            mis = []
            for m in r["Misconfigurations"]:
                m = dict(m)
                if isinstance(m.get("CauseMetadata"), dict):
                    m["CauseMetadata"] = {k: v for k, v in m["CauseMetadata"].items() if k != "Code"}
                mis.append(m)
            r["Misconfigurations"] = mis
        results.append(r)
    if "Results" in doc:
        out["Results"] = results
    return _clean(out, stage_prefix.rstrip("/"))


def _line(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _text(value: Any, limit: int = MAX_DESCRIPTION) -> str:
    return mask_text(str(value or ""))[0][:limit]


def normalize(
    clean: dict[str, Any],
    *,
    scanner: str,
    mode: str,
    archive: str | None = None,
    component: dict | None = None,
) -> list[dict[str, Any]]:
    """Findings (tool fields only; ids, check and rule are added when recording) from a sanitized document."""
    found: list[dict[str, Any]] = []
    for r in clean.get("Results") or []:
        target = r["Target"]
        path = archive if mode == "image_archive" else target
        if scanner == "vuln":
            locations = {p.get("Name"): (p.get("Locations") or [{}])[0] for p in r.get("Packages") or []}
            for v in r.get("Vulnerabilities") or []:
                loc = locations.get(v.get("PkgName")) or {}
                vid = str(v.get("VulnerabilityID") or "unknown")
                found.append(
                    {
                        "scanner": "vuln",
                        "rule_id": vid,
                        "path": path,
                        "line": _line(loc.get("StartLine")),
                        "end_line": _line(loc.get("EndLine")),
                        "title": f"{vid}: {_text(v.get('Title'), 500)}",
                        "description": _text(v.get("Description")),
                        "tool_severity": v.get("Severity"),
                        "severity": guard_severity(v.get("Severity")),
                        "cwe": (v.get("CweIDs") or [None])[0],
                        "cwe_ids": v.get("CweIDs") or [],
                        "package": {
                            "name": v.get("PkgName"),
                            "installed": v.get("InstalledVersion"),
                            "fixed": v.get("FixedVersion"),
                        },
                        "pkg_path": v.get("PkgPath"),
                        "layer": (v.get("Layer") or {}).get("DiffID"),
                        "target": target,
                        "fingerprint": v.get("Fingerprint"),
                        "data_source": (v.get("DataSource") or {}).get("ID"),
                        "component": component,
                    }
                )
        elif scanner == "misconfig":
            for m in r.get("Misconfigurations") or []:
                if m.get("Status") != "FAIL":
                    continue
                cause = m.get("CauseMetadata") or {}
                mid = str(m.get("ID") or "unknown")
                found.append(
                    {
                        "scanner": "misconfig",
                        "rule_id": mid,
                        "path": path,
                        "line": _line(cause.get("StartLine")),
                        "end_line": _line(cause.get("EndLine")),
                        "title": f"{mid}: {_text(m.get('Title'), 500)}",
                        "description": _text(m.get("Message")),
                        "tool_severity": m.get("Severity"),
                        "severity": guard_severity(m.get("Severity")),
                        "cwe": None,
                        "type": m.get("Type"),
                        "resolution": _text(m.get("Resolution"), 2000),
                        "target": target,
                        "component": component,
                    }
                )
        elif scanner == "secret":
            for s in r.get("Secrets") or []:
                rid = str(s.get("RuleID") or "unknown")
                n = s.get("MaskedLength", 0)
                found.append(
                    {
                        "scanner": "secret",
                        "rule_id": rid,
                        "path": path,
                        "line": _line(s.get("StartLine")),
                        "end_line": _line(s.get("EndLine")),
                        "title": f"{rid}: {_text(s.get('Title'), 500)}",
                        "description": (
                            f"{_text(s.get('Category'), 100)} secret (value masked, {n} characters)"
                        ),
                        "tool_severity": s.get("Severity"),
                        "severity": guard_severity(s.get("Severity")),
                        "cwe": None,
                        "category": s.get("Category"),
                        "secret": {"representation": "masked", "length": n},
                        "target": target,
                    }
                )
    return sorted(found, key=_order)


def _order(f: dict[str, Any]) -> tuple:
    return (
        f["scanner"],
        f["path"] or "",
        f["rule_id"],
        str((f.get("package") or {}).get("name")),
        f["line"] or 0,
    )
