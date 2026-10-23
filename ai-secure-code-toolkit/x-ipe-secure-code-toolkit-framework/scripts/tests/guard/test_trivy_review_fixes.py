"""Regression tests for the three FEATURE-002-D code-review defects (TASK-057, Stage B review).

1. Local-time timestamps: Trivy writes log timestamps and the checks-bundle `DownloadedAt` in the
   process's local zone (Go `time.Now()`); the toolkit runs every Trivy process with `TZ=UTC` and also
   accepts RFC 3339 `±hh:mm` offsets (AC-002D-05a/05h log accounting, AC-002D-02b/02d metadata).
2. Debug-format FATAL: with `--debug` Trivy prints `FATAL\tFatal error` without fields, followed by
   `  - %+v` continuation lines; the message, component errors and deadline detection must use them
   (AC-002D-05f, 02e, 04d).
3. An explicit image-archive file target inside a folder target staged by another check is staged once,
   within the archive maximum, not as part of the folder copy (AC-002D-03g).
"""

# ruff: noqa: F811
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import posix_only
from trivyhelp import (  # noqa: F401 - fixture reuse
    ALPINE,
    ALPINE_PKGS,
    POM_COMPLETE,
    calls,
    env,
    gaps_text,
    image,
    linux,
    planned,
    provisioned,
    run_entry,
    scan,
    set_cfg,
    tcheck,
    tev,
    trc,
    trivy,
    trivy_status,
    trivytar,
    write,
)

from x_ipe_secure_code.adapters import trivy_cache, trivy_log
from x_ipe_secure_code.guard import toolrun

pytestmark = posix_only
FRAMES = "/home/runner/work/trivy"


def feed(lines: list[str]) -> trivy_log.LogFacts:
    parser = trivy_log.LogParser()
    parser.feed(("\n".join(lines) + "\n").encode())
    return parser.finish()


# ======================================================================= 1. local-time timestamps
@pytest.mark.parametrize(
    "stamp",
    ["2026-10-23T01:07:50+08:00", "2026-10-22T12:07:50-05:00", "2026-10-22T17:07:50.123456+00:00"],
)
def test_log_parser_accepts_rfc3339_offsets(stamp):
    facts = feed(
        [
            f"{stamp}\tINFO\t[vuln] Vulnerability scanning is enabled",
            f'{stamp}\tDEBUG\t[secret] Using streaming scanner\tfile_path="app/settings.env"',
            f"{stamp}\tWARN\tDependency version cannot be determined",
        ]
    )
    assert facts.recognized and facts.anchors == {"vuln"} and facts.continuations == 0
    assert facts.secret_scanned == ["app/settings.env"]
    assert [m["kind"] for m in facts.messages] == ["degrading"]


@pytest.mark.parametrize(
    "stamp", ["2026-10-22T17:07:50+8:00", "2026-10-22T17:07:50", "2026-10-22T17:07:50+0800"]
)
def test_log_parser_still_rejects_malformed_zones(stamp):
    facts = feed([f"{stamp}\tINFO\t[vuln] Vulnerability scanning is enabled"])
    assert not facts.recognized and facts.continuations == 1


def test_parse_time_accepts_offsets_and_converts_to_utc():
    expected = datetime(2026, 10, 22, 17, 7, 50, 123456, tzinfo=UTC)
    assert trivy_cache.parse_time("2026-10-22T17:07:50.123456Z") == expected
    assert trivy_cache.parse_time("2026-10-23T01:07:50.123456789+08:00") == expected
    assert trivy_cache.parse_time("2026-10-22T12:07:50.123456-05:00") == expected
    assert trivy_cache.parse_time("2026-10-22T17:07:50.123456+00:00") == expected
    for bad in ("2026-10-22T17:07:50", "2026-10-22T17:07:50+8:00", "2026-10-22T17:07:50+25:00", 5, None):
        assert trivy_cache.parse_time(bad) is None, bad


def test_checks_bundle_metadata_with_local_downloaded_at_is_valid():
    meta = {
        "Digest": "sha256:" + "a" * 64,
        "DownloadedAt": "2026-10-23T01:07:50.661212345+08:00",
        "MajorVersion": 2,
    }
    assert trivy_cache.metadata_problem("checks_bundle", meta, "2") is None


def test_every_trivy_process_runs_with_tz_utc(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    assert scan(env, vid, [trc()]).ok
    launched = calls(trivy)
    assert {c["kind"] for c in launched} == {"provision", "scan"}
    assert all(c["tz"] == "UTC" for c in launched), [c["tz"] for c in launched]


@pytest.mark.parametrize("offset", ["+08:00", "-05:00"])
def test_non_utc_host_provisions_and_scans(env, trivy, offset):
    """A host whose local zone is not UTC: provisioning (incl. the checks bundle) and log accounting work."""
    set_cfg(trivy, tz_offset=offset)
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    assert trivy_status(env)["components"]["checks_bundle"]["state"] == "present"
    result = scan(env, vid, [trc()])
    assert result.ok and tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)


@pytest.mark.parametrize("offset", ["+08:00", "-05:30"])
def test_offset_timestamps_accepted_even_if_tz_is_ignored(env, trivy, offset):
    set_cfg(trivy, tz_offset=offset, force_offset=True)
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    downloaded = trivy_status(env)["components"]["checks_bundle"]["metadata"]["DownloadedAt"]
    assert downloaded.endswith(offset)
    result = scan(env, vid, [trc()])
    assert result.ok and tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)


# ======================================================================= 2. debug-format FATAL
def debug_fatal(chain: str, stamp: str = "2026-10-22T17:07:50Z") -> list[str]:
    parts = chain.split(": ")
    lines = [f"{stamp}\tFATAL\tFatal error"]
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        lines.append(f"  - {part}" + ("" if last else ":"))
        if not last:
            lines += [f"    github.com/aquasecurity/trivy/pkg/x.f{i}", f"        {FRAMES}/pkg/x/f.go:{i}"]
    return lines


@pytest.mark.parametrize(
    ("chain", "component", "state", "timed_out"),
    [
        (
            "run error: init error: DB error: error in vulnerability DB initialization: "
            "failed to open db: invalid database",
            "vulnerability_db",
            "unreadable",
            False,
        ),
        (
            "run error: init error: DB error: database error: --skip-db-update cannot be specified on the "
            "first run",
            "vulnerability_db",
            "missing",
            False,
        ),
        (
            "run error: image scan error: post analysis error: Unable to initialize the Java DB: "
            "'--skip-java-db-update' cannot be specified on the first run",
            "java_db",
            "missing",
            False,
        ),
        (
            "run error: fs scan error: scan error: scan failed: failed analysis: semaphore acquire: "
            "context deadline exceeded",
            None,
            None,
            True,
        ),
    ],
)
def test_log_parser_attaches_debug_fatal_continuations(chain, component, state, timed_out):
    facts = feed(
        [
            "2026-10-22T17:07:49Z\tINFO\t[vuln] Vulnerability scanning is enabled",
            *debug_fatal(chain),
        ]
    )
    assert facts.component_errors == ({component: state} if component else {})
    assert facts.timed_out is timed_out
    (fatal,) = [m for m in facts.messages if m["kind"] == "fatal"]
    assert fatal["text"].startswith("Fatal error: run error:") and FRAMES not in fatal["text"]
    assert chain.rsplit(": ", 1)[1][:40] in fatal["text"] or len(fatal["text"]) == trivy_log.MAX_TEXT


def test_debug_fatal_is_closed_by_the_next_record_and_masked_and_bounded():
    secret = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"
    facts = feed(
        [
            *debug_fatal(f"run error: token {secret} rejected: failed to open db: invalid database"),
            *[f"        {FRAMES}/pkg/x/deep.go:{n}" for n in range(5000)],
            "2026-10-22T17:07:51Z\tINFO\tNumber of language-specific files\tnum=1",
        ]
    )
    assert facts.component_errors == {"vulnerability_db": "unreadable"}
    assert facts.counts == {"language_files": 1}
    (fatal,) = facts.messages
    assert secret not in fatal["text"] and len(fatal["text"]) <= trivy_log.MAX_TEXT
    assert facts.continuations >= 5000


def test_field_fatal_and_field_less_fatal_without_continuations_unchanged():
    facts = feed(
        [
            "2026-10-22T17:07:50Z\tFATAL\tFatal error\trun error: init error: DB error: failed to open db: "
            "invalid database",
        ]
    )
    assert facts.component_errors == {"vulnerability_db": "unreadable"}
    assert facts.messages[0]["text"].startswith("Fatal error: run error")
    alone = feed(["2026-10-22T17:07:50Z\tFATAL\tFatal error"])
    assert alone.messages == [{"level": "FATAL", "text": "Fatal error", "kind": "fatal"}]


@pytest.mark.parametrize("mode", ["invalid-db", "first-run", "tool-deadline"])
def test_debug_format_fatal_through_guard_tool(env, trivy, mode):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    set_cfg(trivy, mode=mode, fatal_format="debug")
    result = scan(env, vid, [trc()])
    assert result.ok, result.to_text()
    text = gaps_text(result, env, vid)
    assert tev(env, vid)["method_status"] == "failed" and FRAMES not in text
    if mode == "invalid-db":
        assert "vulnerability_db unreadable (reported by the tool)" in text and "invalid database" in text
        assert trivy_status(env)["components"]["vulnerability_db"]["state"] == "unreadable"
    elif mode == "first-run":
        assert "vulnerability_db missing (reported by the tool)" in text
        assert "--skip-db-update cannot be specified on the first run" in text
    else:
        assert result.data["checks"]["C1"]["status"] == "timed_out"
        assert "context deadline exceeded" in text


# ======================================================================= 3. nested image archive
def test_archive_inside_folder_target_is_staged_once_within_the_archive_maximum(env, trivy, monkeypatch):
    """The 600 MiB case scaled down: the archive is larger than the non-archive staging limit."""
    padding = image(os_info=ALPINE, packages=ALPINE_PKGS, extra=(_pad(64 * 1024),))
    write(env, {"dist/app.tar": padding, "dist/notes.txt": "release notes\n"})
    vid = planned(
        env,
        [tcheck(obj=("dist/app.tar",)), tcheck("C2", obj=("dist",))],
        targets=("dist", "dist/app.tar"),
    )
    provisioned(env, vid)
    monkeypatch.setattr(toolrun, "MAX_STAGE_BYTES", 32 * 1024)  # 512 MiB scaled; archive is ~70 KiB
    result = scan(
        env,
        vid,
        [
            trc(mode="image_archive", targets=("dist/app.tar",)),
            trc("C2", scanners=("secret",), targets=("dist",)),
        ],
    )
    assert result.ok and result.data["status"] != "precheck_failed", result.to_text()
    assert tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)
    entry = run_entry(env, vid)
    assert entry["checks"]["C2"]["status"] != "precheck_failed"
    assert set(entry["staged_digests"]) == {"dist", "dist/app.tar"}
    c2 = gaps_text(result, env, vid, "C2")
    assert "changed" not in c2 and "too large" not in c2.lower(), c2


def test_folder_limit_still_counts_ordinary_tar_files_in_the_folder(env, trivy, monkeypatch):
    """A `.tar` that is not an explicit archive target stays an ordinary folder file (AC-002D-03i)."""
    write(env, {"dist/app.tar": image(extra=(_pad(64 * 1024),)), "dist/notes.txt": "release notes\n"})
    vid = planned(env, [tcheck(obj=("dist",))], targets=("dist",))
    provisioned(env, vid)
    monkeypatch.setattr(toolrun, "MAX_STAGE_BYTES", 32 * 1024)
    result = scan(env, vid, [trc(scanners=("secret",), targets=("dist",))])
    assert result.data["status"] == "precheck_failed" and result.problems[0].code == "STAGE_TOO_LARGE"


def _pad(size: int) -> bytes:
    return trivytar.member("pad.bin", b"\0" * size)
