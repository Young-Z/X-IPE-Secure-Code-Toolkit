"""Shared fixtures for the FEATURE-002-G comparison tests (result builders, writers, recorders, clock).

Fixture writers only: the code under test never uses these helpers.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import importlib
import io
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
import write_audit

from x_ipe_secure_code import cli
from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.guard import model as guard_model
from x_ipe_secure_code.guard import report


class Lazy:
    """A module imported on first attribute access (a missing module fails the test, not collection)."""

    def __init__(self, name: str) -> None:
        self._name = f"x_ipe_secure_code.guard.{name}"

    def __getattr__(self, attr: str) -> Any:
        return getattr(importlib.import_module(self._name), attr)

    @property
    def module(self) -> Any:
        return importlib.import_module(self._name)


compare = Lazy("compare")
compare_bounds = Lazy("compare_bounds")
compare_cover = Lazy("compare_cover")
compare_io = Lazy("compare_io")
compare_match = Lazy("compare_match")
compare_render = Lazy("compare_render")
compare_validate = Lazy("compare_validate")

REPORTS = "x-ipe-docs/secure-code/reports/guard"
COMPARISONS = f"{REPORTS}/comparisons"
GUARD = ".x-ipe/private/secure-code/guard"
E_ID = "gv-20261020T101500Z-1a2b3c4d"
L_ID = "gv-20261023T091200Z-9f8e7d6c"
X_ID = "gv-20261001T080000Z-0a0b0c0d"
R1 = "CWE/4.14/CWE-79"
R2 = "CWE/4.14/CWE-89"
CANARY = "sk-proj-" + "A" * 24
ORIGINAL_UTC_NOW = guard_model.utc_now

READ = {"name": "semantic-review", "kind": "reading", "required": True}
OG_METHOD = {"name": "opengrep", "kind": "runtime", "required": True}
TV_METHOD = {"name": "trivy", "kind": "runtime", "required": True}


def dg(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


# ------------------------------------------------------------------------------------------ builders
def target(
    path="src", *, kind="dir", change="modified", old_path=None, digest=None, concl="same", incomplete=False
):
    if change == "deleted":
        kind, digest = None, None
        concl = None if concl == "same" else concl
    else:
        digest = digest or dg(f"content:{path}")
        concl = digest if concl == "same" else concl
    return {
        "path": path,
        "kind": kind,
        "change": change,
        "old_path": old_path,
        "digest_at_open": digest,
        "digest_at_conclusion": concl,
        "changed": digest != concl,
        "incomplete": incomplete,
        "not_followed": [],
        "unreadable": [],
    }


def check(cid="C1", rule=R1, obj=("src",), methods=(READ,)):
    return {
        "id": cid,
        "rule": rule,
        "object": list(obj),
        "object_part": None,
        "methods": [dict(m) for m in methods],
        "minimum_evidence": sorted({m["kind"] for m in methods}),
    }


def row(cid, rule, state="met", reason=None, findings=()):
    return {
        "check": cid,
        "rule": rule,
        "object": [],
        "object_part": None,
        "minimum_evidence": [],
        "recorded_state": state,
        "state": state,
        "reason": reason,
        "evidence_by_kind": {},
        "findings": list(findings),
        "substitution": [],
        "superseded": 0,
    }


def evidence(
    eid="E1", checks=("C1", "C2"), paths=("src",), kind="reading", method="semantic-review", status="ok"
):
    return {
        "id": eid,
        "kind": kind,
        "method": method,
        "method_status": status,
        "checks": list(checks),
        "paths": list(paths),
        "lines": None,
        "summary": "read the code",
        "stored": None,
        "masked": False,
        "masked_types": [],
    }


def finding(
    fid,
    *,
    rule=R1,
    check="C1",
    path="src/a.py",
    line=None,
    cwe="CWE-79",
    source="semantic",
    title="Unescaped input reaches HTML",
    description=None,
    severity="high",
    review="confirmed",
    final=None,
    tool=None,
):
    f = {
        "id": fid,
        "rule": rule,
        "check": check,
        "location": {"path": path, "line": line},
        "cwe": cwe,
        "title": title,
        "description": description,
        "source": source,
        "evidence": [],
        "disputed": False,
        "related": [],
        "merged_from": [],
        "merge_evidence": [],
        "merged_into": None,
        "original_severity": severity,
        "severity_opinion": None,
        "final_severity": final or severity,
        "severity_conflict": False,
        "requires_review": True,
        "review": review,
        "review_disagreement": False,
        "review_basis": [],
        "review_records": [],
    }
    if tool is not None:
        f["tool"] = tool
    return f


def og(
    fid, *, run=1, rule_id="py-xss", path="src/a.py", line=None, fingerprint=None, check="C1", rule=R1, **over
):
    tool = {
        "adapter": "opengrep",
        "run": run,
        "rule_id": rule_id,
        "rule_file": "x-ipe-docs/rules/py.yaml",
        "tool_severity": "ERROR",
        "end_line": line,
        "fingerprint": fingerprint,
    }
    return finding(
        fid, rule=rule, check=check, path=path, line=line, source="opengrep", title=rule_id, tool=tool, **over
    )


def tv(
    fid,
    *,
    scanner="vuln",
    run=1,
    rule_id="CVE-2024-0001",
    path="src/pom.xml",
    line=None,
    check="C1",
    rule=R1,
    pkg="log4j-core",
    installed="2.14.0",
    pkg_path=None,
    secret=None,
    **over,
):
    tool = {
        "adapter": "trivy",
        "run": run,
        "scanner": scanner,
        "rule_id": rule_id,
        "tool_severity": "HIGH",
        "end_line": None,
    }
    if scanner == "vuln":
        tool.update(
            package={"name": pkg, "installed": installed, "fixed": "2.17.1"},
            pkg_path=pkg_path,
            fingerprint=None,
        )
    if scanner == "secret":
        tool["secret"] = secret if secret is not None else {"representation": "masked", "length": 12}
    return finding(
        fid,
        rule=rule,
        check=check,
        path=path,
        line=line,
        source="trivy",
        cwe=None,
        title=f"{rule_id}: issue",
        tool=tool,
        **over,
    )


def og_run(
    n=1,
    checks=("C1",),
    *,
    version="1.31.0",
    binary=None,
    include_ignored=False,
    configs=None,
    status="ok",
    counts=(3, 0, 0),
    gaps=(),
    gap=None,
):
    return {
        "n": n,
        "adapter": "opengrep",
        "version": version,
        "asset": "fake",
        "platform_validated": False,
        "platform": {"os": "linux", "arch": "x86_64", "libc": "glibc"},
        "binary_digest": binary or dg("opengrep-binary"),
        "include_ignored": include_ignored,
        "time_limit": 60,
        "rules": [
            {
                "check": c,
                "path": "x-ipe-docs/rules/py.yaml",
                "digest": dg("rules"),
                "ids": ["py-xss"],
                "config_digests": dict(configs or {"py-xss": dg("py-xss-config")}),
            }
            for c in checks
        ],
        "staged_digests": {},
        "checks": {
            c: {
                "status": "completed",
                "method_status": status,
                "exit": [0],
                "seconds": 1.0,
                "counts": {"scanned": counts[0], "skipped": counts[1], "unaccounted": counts[2]},
                "gaps": list(gaps),
            }
            for c in checks
        },
        "manifest": None,
        "gap": gap,
    }


def components(**over):
    comps = {
        "vulnerability_db": {
            "state": "present",
            "repository": "aquasec/trivy-db",
            "tag": "2",
            "registry": "mirror.gcr.io",
            "content_digest": dg("db"),
            "age": "1 day",
            "metadata": {"Version": 2, "UpdatedAt": "2026-10-20T00:00:00Z"},
        },
        "java_db": {
            "state": "present",
            "repository": "aquasec/trivy-java-db",
            "tag": "1",
            "registry": "mirror.gcr.io",
            "content_digest": dg("jdb"),
            "age": "1 day",
            "metadata": {"Version": 1, "UpdatedAt": "2026-10-20T00:00:00Z"},
        },
        "checks_bundle": {
            "state": "present",
            "repository": "aquasec/trivy-checks",
            "tag": "1",
            "registry": "mirror.gcr.io",
            "content_digest": dg("cb"),
            "age": "1 day",
            "metadata": {"MajorVersion": 1, "Digest": dg("bundle")},
        },
    }
    for name, fields in over.items():
        comps[name] = {**comps[name], **fields}
    return comps


def tv_run(
    n=1,
    checks=("C1",),
    *,
    version="0.76.1",
    binary=None,
    comps=None,
    used=("vulnerability_db",),
    scanners=("vuln",),
    mode="filesystem",
    status="ok",
    counts=(3, 0, 0),
    gaps=(),
    gap=None,
):
    return {
        "n": n,
        "adapter": "trivy",
        "version": version,
        "asset": "fake",
        "platform_validated": True,
        "platform": {"os": "linux", "arch": "x86_64", "libc": "glibc"},
        "binary_digest": binary or dg("trivy-binary"),
        "time_limit": 60,
        "staged_digests": {},
        "archives": [],
        "components": comps or components(),
        "rehash": {},
        "checks": {
            c: {
                "status": "completed",
                "scanners": list(scanners),
                "mode": mode,
                "config_types": [],
                "processes": [],
                "accounting": [],
                "components_used": list(used),
                "gaps": list(gaps),
                "method_status": status,
                "counts": {"scanned": counts[0], "skipped": counts[1], "unaccounted": counts[2]},
            }
            for c in checks
        },
        "manifest": None,
        "gap": gap,
    }


def result(
    vid=E_ID,
    *,
    opened=None,
    ended=None,
    targets=None,
    checks=None,
    ledger=None,
    ev=None,
    findings=(),
    runs=None,
    verdict="cannot_confirm_pass",
    na=(),
    exclusions=(),
    cancellation=None,
    whole_project=False,
    context=(),
    suggested=(),
    copilot=(),
    risk=(),
    adopted=None,
    plan="default",
):
    """A strictly valid guard-result/v1 document shaped like `engine.conclude` output."""
    stamp = vid[3:18]
    day = f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z"
    opened = opened or day
    ended = ended or (guard_model.parse_time(opened) + dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    checks = checks if checks is not None else [check("C1", R1), check("C2", R2)]
    if plan is None:
        plan_doc, rows = None, []
    else:
        plan_doc = {
            "checks": checks,
            "not_applicable": [{"rule": r, "reason": "no database"} for r in na],
            "exclusions": [dict(e) for e in exclusions],
        }
        excluded = {e["check"] for e in exclusions if e.get("check")}
        rows = (
            ledger
            if ledger is not None
            else [row(c["id"], c["rule"], "excluded" if c["id"] in excluded else "met") for c in checks]
        )
        rows = rows + [row(f"policy:{r}", r, "n/a", "no database") for r in na if ledger is None]
        rows = rows + [
            row(f"rule:{e['rule']}", e["rule"], "excluded", "user scope exclusion: out of scope")
            for e in exclusions
            if e.get("rule") and ledger is None
        ]
    doc = {
        "schema": guard_model.SCHEMA_RESULT,
        "verification_id": vid,
        "opened_at": opened,
        "ended_at": ended,
        "request": "verify the login change",
        "baseline": None,
        "verdict": verdict,
        "reasons": [{"code": "CHECK_UNCONFIRMED", "subject": "C1", "detail": "example reason"}],
        "other_blockers": [],
        "scope": {
            "scope_id": "sc-1",
            "mode": "clues",
            "adopted": adopted
            or [
                {"rule": r, "state_digest": dg(f"policy:{r}"), "at_conclusion": "unchanged"} for r in (R1, R2)
            ],
        },
        "artifact": {
            "whole_project": whole_project,
            "targets": targets or [target()],
            "context": [{"path": p, "kind": "file", "digest": dg(p)} for p in context],
            "suggested": [{"path": p, "reason": "related"} for p in suggested],
            "copilot_reports": [{"path": p, "kind": "file", "digest": dg(p)} for p in copilot],
            "not_verified": "read-only context, suggested files and Copilot reports are not verified",
        },
        "plan": plan_doc,
        "ledger": rows,
        "evidence": ev if ev is not None else ([evidence()] if plan is not None else []),
        "findings": [copy.deepcopy(f) for f in findings],
        "reviews": [],
        "conflicts": [],
        "risk_acceptances": [
            {"finding": f, "reason": "accepted for the release", "role": "user", "recorded_at": ended}
            for f in risk
        ],
        "adapter_runs": runs if runs is not None else [],
        "evidence_retention": {
            "location": f"{GUARD}/{vid}/",
            "days_after_end": 30,
            "removal": "only by the explicit command secure-code guard cleanup",
        },
        "limits": ["example limit"],
        "budget": None,
        "attempts": [],
        "egress": {"grants": [], "declarations": []},
        "cancellation": cancellation,
    }
    return doc


def pair(e_over=None, l_over=None, **common):
    return result(E_ID, **{**common, **(e_over or {})}), result(L_ID, **{**common, **(l_over or {})})


def facts(**over):
    base = {
        role: {
            "state": "consistent",
            "failed_checks": [],
            "markdown_present": True,
            "statement": None,
            "result_sha256": "0" * 64,
            "raw_evidence": "available",
        }
        for role in ("earlier", "later")
    }
    for role, fields in over.items():
        base[role].update(fields)
    return base


def build(e, lv, **over):
    return compare_match.build(e, lv, facts(**over))


def entries(cmp, cls=None):
    return [x for x in cmp["entries"] if cls is None or x["class"] == cls]


def entry_of(cmp, fid, role="earlier"):
    found = [x for x in cmp["entries"] if (x[role] or {}).get("finding") == fid]
    assert len(found) == 1, (fid, role, found)
    return found[0]


def codes(entry):
    return sorted({r["code"] for r in entry["reasons"]})


# ------------------------------------------------------------------------------------------ project files
def make_project(tmp_path, name="proj"):
    root = tmp_path / name
    (root / REPORTS).mkdir(parents=True)
    (root / GUARD).mkdir(parents=True)
    return root


def put(root, doc, md="render", *, canonical=True, run_folder=True):
    """Write `<id>.json` (+ Markdown twin) into reports/guard/ exactly as a fixture."""
    vid = doc["verification_id"]
    raw = dumps_json(doc) if canonical else (json.dumps(doc, indent=1) + "\n").encode()
    (root / REPORTS / f"{vid}.json").write_bytes(raw)
    if md == "render":
        md = report.render(json.loads(raw)).encode()
    if md is not None:
        (root / REPORTS / f"{vid}.md").write_bytes(md)
    if run_folder:
        (root / GUARD / vid).mkdir(parents=True, exist_ok=True)
    return raw


def put_pair(root, e=None, lv=None, **kw):
    e, lv = e or result(E_ID), lv or result(L_ID)
    put(root, e, **kw)
    put(root, lv, **kw)
    return e, lv


def run_compare(root, earlier=(E_ID,), later=(L_ID,)):
    """In-process `secure-code guard compare --json`; returns (envelope, exit code)."""
    args = ["guard", "compare", "--project", str(root)]
    for value in [earlier] if isinstance(earlier, str) else earlier:
        args += ["--earlier", value]
    for value in [later] if isinstance(later, str) else later:
        args += ["--later", value]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main([*args, "--json"])
    return json.loads(buf.getvalue()), code


def comparison_files(root):
    folder = root / COMPARISONS
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else None


def load_comparison(root, env):
    data = json.loads((root / env["data"]["files"]["structured"]).read_text(encoding="utf-8"))
    md = (root / env["data"]["files"]["markdown"]).read_text(encoding="utf-8")
    return data, md


def manifest(root, exclude=None):
    """(relative path, type, SHA-256 or link target) of every entry under root; links never followed."""
    out = []
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if exclude and (rel_dir == exclude or rel_dir.startswith(exclude + os.sep)):
            dirnames[:] = []
            continue
        for name in sorted(dirnames + filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if exclude and rel == exclude:
                continue
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                out.append((rel, "link", os.readlink(path)))
            elif stat.S_ISDIR(info.st_mode):
                out.append((rel, "dir", ""))
            elif stat.S_ISREG(info.st_mode):
                try:
                    out.append((rel, "file", hashlib.sha256(Path(path).read_bytes()).hexdigest()))
                except PermissionError:
                    out.append((rel, "file", "unreadable"))
            else:
                out.append((rel, "special", ""))
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return sorted(out)


# ------------------------------------------------------------------------------------------ clock
_CLOCK: dict[str, Any] = {}


class _Frozen(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        instant = _CLOCK["instant"]
        return instant if tz is not None else instant.replace(tzinfo=None)


def _frozen_utc_now() -> str:
    return _CLOCK["text"]


def freeze_clock(monkeypatch, text):
    """Freeze every module-level clock binding of the toolkit (test-side patching only, DAO-012).

    Calling it again moves the frozen instant.
    """
    for name in (
        "cli",
        "guard.service",
        "guard.retention",
        "guard.cancel",
        "guard.control",
        "guard.budget",
        "status",
        "guard.model",
        "guard.compare",
        "project_init",
    ):
        importlib.import_module(f"x_ipe_secure_code.{name}")
    _CLOCK.update(text=text, instant=guard_model.parse_time(text))
    for mod_name, mod in list(sys.modules.items()):
        if mod is None or not (mod_name == "x_ipe_secure_code" or mod_name.startswith("x_ipe_secure_code.")):
            continue
        if getattr(mod, "utc_now", None) is ORIGINAL_UTC_NOW:
            monkeypatch.setattr(mod, "utc_now", _frozen_utc_now)
        if getattr(mod, "datetime", None) is dt.datetime:
            monkeypatch.setattr(mod, "datetime", _Frozen)
    from x_ipe_secure_code.guard import retention, service

    assert guard_model.utc_now() == text
    assert service.now()[0] == text
    assert retention.datetime.now(dt.UTC) == _CLOCK["instant"]
    return _CLOCK["instant"]


# ------------------------------------------------------------------------------------------ access recorder
_ACTIVE: list[AccessRecorder] = []
_WATCH = {
    "os.listdir",
    "os.scandir",
    "subprocess.Popen",
    "os.exec",
    "os.posix_spawn",
    "os.fork",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.__new__",
    "os.mkdir",
    "os.link",
    "os.remove",
    "os.rename",
    "os.rmdir",
    "os.system",
}
_HOOKED: list[bool] = []


def _audit(event, args):
    if _ACTIVE and event in _WATCH:
        _ACTIVE[-1].events.append((event, repr(args)[:300]))


class AccessRecorder:
    """Records os.open/os.stat (dir_fd resolved to a path) and selected audit events while active."""

    def __init__(self):
        self.opens: list[tuple[str, int]] = []
        self.stats: list[str] = []
        self.events: list[tuple[str, str]] = []
        self._patch = pytest.MonkeyPatch()

    @staticmethod
    def _resolve(path, dir_fd):
        raw = os.fsdecode(path) if not isinstance(path, int) else write_audit.fd_path(path) or ""
        if dir_fd is not None and not os.path.isabs(raw):
            raw = os.path.join(write_audit.fd_path(dir_fd) or "?", raw)
        return os.path.realpath(raw)

    def __enter__(self):
        if not _HOOKED:
            sys.addaudithook(_audit)
            _HOOKED.append(True)
        real_open, real_stat = os.open, os.stat

        def rec_open(path, flags, mode=0o777, *, dir_fd=None):
            self.opens.append((self._resolve(path, dir_fd), flags))
            return real_open(path, flags, mode, dir_fd=dir_fd)

        def rec_stat(path, *, dir_fd=None, follow_symlinks=True):
            self.stats.append(self._resolve(path, dir_fd))
            return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        self._patch.setattr(os, "open", rec_open)
        self._patch.setattr(os, "stat", rec_stat)
        _ACTIVE.append(self)
        return self

    def __exit__(self, *exc):
        _ACTIVE.remove(self)
        self._patch.undo()

    def content_opens(self, root):
        root = os.path.realpath(root)
        return sorted(
            {
                p
                for p, flags in self.opens
                if p.startswith(root + os.sep)
                and not flags & getattr(os, "O_DIRECTORY", 0)
                and not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
            }
        )

    def write_opens(self, root):
        root = os.path.realpath(root)
        return sorted(
            {
                p
                for p, flags in self.opens
                if p.startswith(root + os.sep) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
            }
        )

    def dir_opens(self, root):
        root = os.path.realpath(root)
        return sorted(
            {
                p
                for p, flags in self.opens
                if (p == root or p.startswith(root + os.sep)) and flags & getattr(os, "O_DIRECTORY", 0)
            }
        )

    def event_names(self):
        return sorted({e for e, _ in self.events})


# ------------------------------------------------------------------------------------------ rich fixture
R3 = "CWE/4.14/CWE-22"
R4 = "CWE/4.14/CWE-502"
R5 = "CWE/4.14/CWE-798"
FP_A = "a" * 32
FP_B = "b" * 32


def rich_pair():
    """Two results touching every source and branch the comparison reads (contract tests)."""
    adopted = [
        {"rule": r, "state_digest": dg(f"policy:{r}"), "at_conclusion": "unchanged"}
        for r in (R1, R2, R3, R4, R5)
    ]
    checks = [
        check("C1", R1, ("src", "old")),
        check("C2", R2, ("src",), (OG_METHOD,)),
        check("C3", R3, ("src",), (TV_METHOD,)),
        check("C4", R1, ("src",)),
    ]
    exclusions = [
        {"rule": None, "check": "C4", "reason": "user excluded C4"},
        {"rule": R5, "check": None, "reason": "out of scope"},
    ]
    ev = [
        evidence("E1", ("C1",), ("src", "old")),
        evidence("E2", ("C2",), ("src",), "runtime", "opengrep"),
        evidence("E3", ("C3",), ("src",), "runtime", "trivy"),
    ]

    def merged(fs):
        by = {f["id"]: f for f in fs}
        by["M2"]["merged_into"], by["M1"]["merged_from"] = "M1", ["M2"]
        by["M1"]["merged_into"], by["S1"]["merged_from"] = "S1", ["M1"]
        return fs

    e_find = merged(
        [
            finding("S1", path="src/a.py", line=3, description=f"token {CANARY}"),
            finding("M1", path="src/a.py", line=4),
            finding("M2", path="src/a.py", line=5),
            finding("S2", path="old/x.py", line=7),
            finding("S3", path="src/gone.py", line=1),
            finding("S4", rule=R1, check="C1", path="src/only_e.py", cwe="CWE-20"),
            og("OG1", path="src/a.py", line=10, fingerprint=FP_A, check="C2", rule=R2),
            og("OG2", path="src/c.py", line=2, check="C2", rule=R2),
            tv("TV1", run=2, check="C3", rule=R3, pkg_path="lib/x.jar"),
            tv("TV2", scanner="misconfig", run=2, check="C3", rule=R3, rule_id="DS002"),
            tv(
                "TV3",
                scanner="secret",
                run=2,
                check="C3",
                rule=R3,
                rule_id="aws-key",
                secret={"representation": "masked", "length": 20, "value": CANARY},
            ),
        ]
    )
    runs_e = [
        og_run(1, ("C2",)),
        tv_run(
            2,
            ("C3",),
            used=("vulnerability_db", "java_db", "checks_bundle"),
            scanners=("vuln", "misconfig", "secret"),
        ),
        og_run(
            3,
            ("C2",),
            status="failed",
            gap={"code": "TOOL_GAP", "reason": "binary missing"},
            gaps=("rule file unreadable",),
            counts=(1, 1, 1),
        ),
    ]
    e = result(
        E_ID,
        adopted=adopted,
        checks=checks,
        exclusions=exclusions,
        na=(R4,),
        ev=ev,
        targets=[target("src"), target("old"), target("lib/x.jar", kind="file")],
        findings=e_find,
        runs=runs_e,
        context=("README.md",),
        copilot=("cp.md",),
        suggested=("src/s.py",),
        risk=("S1",),
        cancellation={
            "requested_at": "2026-10-20T10:18:00Z",
            "reason": "user stopped",
            "consumed_at_request": 1.0,
            "tool_termination": {"tool": "none"},
            "agent_attempts": [],
            "agent_note": "n",
            "remote_note": "r",
        },
    )
    l_ledger = [
        row("C1", R1, "unconfirmed", "not executed"),
        row("C2", R2),
        row("C3", R3),
        row("C4", R1, "excluded", "user scope exclusion: user excluded C4"),
        row(f"policy:{R4}", R4, "n/a", "no database"),
        row(f"rule:{R5}", R5, "excluded", "x"),
    ]
    l_find = [
        finding("S1b", path="src/a.py", line=3, review="false_positive"),
        finding("S2b", path="new/x.py", line=9),
        finding("S5", path="src/new_l.py", cwe="CWE-20"),
        og("OG1b", run=4, path="src/a.py", line=12, fingerprint=FP_A, check="C2", rule=R2),
        og("OG3", run=4, path="src/d.py", line=2, check="C2", rule=R2),
        tv("TV1b", run=5, check="C3", rule=R3, pkg_path="lib/x.jar", installed="2.17.1"),
        tv("TV4", scanner="misconfig", run=5, check="C3", rule=R3, rule_id="DS099"),
    ]
    runs_l = [
        og_run(4, ("C2",), version="1.32.0", include_ignored=True, gaps=("partial",), counts=(1, 2, 0)),
        tv_run(
            5,
            ("C3",),
            comps=components(
                vulnerability_db={"metadata": {"Version": 2, "UpdatedAt": "2026-10-23T00:00:00Z"}}
            ),
            used=("vulnerability_db", "java_db", "checks_bundle"),
            scanners=("vuln", "misconfig"),
        ),
        og_run(6, ("C2",)),
    ]
    l_targets = [
        target("src", digest=dg("src2")),
        target("new", change="renamed", old_path="old"),
        target("src/gone.py", kind="file", change="deleted"),
    ]
    lv = result(
        L_ID,
        adopted=adopted,
        checks=[check("C1", R1, ("src", "new")), *checks[1:]],
        exclusions=exclusions,
        na=(R4,),
        ledger=l_ledger,
        ev=[evidence("E1", ("C1",), ("src", "new")), *ev[1:]],
        targets=l_targets,
        findings=l_find,
        runs=runs_l,
        context=("README.md",),
        copilot=("cp.md",),
        suggested=("src/s.py",),
    )
    e["ledger"][0]["findings"] = ["S1"]
    return e, lv
