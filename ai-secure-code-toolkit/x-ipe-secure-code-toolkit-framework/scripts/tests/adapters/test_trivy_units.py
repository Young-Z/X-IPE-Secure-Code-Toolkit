"""Unit tests for the Trivy Adapter (FEATURE-002-D) and its additive FEATURE-002-B/002-C/002-A extensions.

Test-side interface names chosen within the technical design (the design fixes the behaviour, not every
Python name): `trivy.scan_argv/OFFLINE/COMMON/REPOSITORIES/KNOWN_HOSTS/CONFIG_TYPES/SEVERITY/guard_severity/
sanitize`, `trivy_log.LogParser.feed/finish` with the fact names of the design, `trivy_account.account(...)`
(keyword arguments) and `trivy_cache.component_state(root, name, now, pointer=None)`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import TOOLKIT_ROOT

from x_ipe_secure_code.adapters import (
    ADAPTERS,
    digests,
    process,
    provided,
    registry_store,
    reserved_id,
    reserved_name,
)

FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
LOGS = FIXTURES / "stderr"  # recorded stderr excerpts (test inputs)
VALIDATION = (
    TOOLKIT_ROOT.parent / "x-ipe-docs" / "requirements" / "EPIC-002" / "FEATURE-002-D" / "tool-validation"
)
ARM = "sha256:b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85"
X86 = "sha256:d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83"
ARCHIVES = {
    "trivy_0.76.1_Linux-ARM64.tar.gz": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    "trivy_0.76.1_Linux-64bit.tar.gz": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
}
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
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX execution only")


def trivy_entries() -> dict[str, digests.ToolBuild]:
    """Every Trivy entry of the toolkit's official-digest table, wherever the module keeps it."""
    out = {}
    for value in vars(digests).values():
        if isinstance(value, dict):
            out.update(
                {k: v for k, v in value.items() if isinstance(v, digests.ToolBuild) and v.tool == "trivy"}
            )
    return out


# ======================================================================= FEATURE-002-B contract extensions
def test_adapter_contract_trivy_provided_linux_only_no_scan_network():
    spec = ADAPTERS["trivy"]
    assert provided() == ["opengrep", "trivy"] and ADAPTERS["strix"] is None
    assert spec.name == "trivy" and spec.max_time_limit == 1800 and spec.network is None
    assert spec.platforms == (("linux", "x86"), ("linux", "aarch64"))
    assert (
        spec.platform_gap
        == "Trivy execution is supported only on Linux x86-64 and Linux arm64 in this version"
    )
    assert ADAPTERS["opengrep"].platforms is None  # Opengrep unchanged
    assert reserved_name("Trivy") and reserved_id("trivy-1-2") and reserved_id("trivy-3-f1")


@pytest.mark.parametrize(
    ("tool", "host", "gap"),
    [
        ("trivy", {"os": "linux", "arch": "aarch64", "libc": "musl"}, False),
        ("trivy", {"os": "linux", "arch": "x86", "libc": "glibc"}, False),
        ("trivy", {"os": "linux", "arch": "riscv64", "libc": "glibc"}, True),
        ("trivy", {"os": "macos", "arch": "aarch64", "libc": None}, True),
        ("trivy", {"os": "windows", "arch": "x86", "libc": None}, True),
        ("opengrep", {"os": "macos", "arch": "aarch64", "libc": None}, False),
        ("opengrep", {"os": "windows", "arch": "x86", "libc": None}, True),
    ],
)
def test_platform_gap_per_adapter(tool, host, gap):
    out = registry_store.platform_gap(tool, host)
    if not gap:
        assert out is None
        return
    assert out.code == "ADAPTER_PLATFORM_UNSUPPORTED" and out.next_step
    if tool == "trivy":
        assert out.reason == ADAPTERS["trivy"].platform_gap
        assert out.next_step == "Run on a Linux x86-64 or arm64 host, or use another method for these checks"


def test_register_step_names_the_tool_and_keeps_the_constant():
    assert "secure-code tools register --tool trivy --path PATH" in registry_store.register_step("trivy")
    assert "--tool opengrep" in registry_store.register_step("opengrep")
    assert registry_store.REGISTER_STEP == (
        "A Maintainer registers the official binary: secure-code tools register --tool opengrep --path PATH"
    )


def test_01f_static_build_matches_any_libc_opengrep_exact():
    static = digests.ToolBuild(
        "trivy", "0.76.1", "linux", "aarch64", None, "trivy_0.76.1_Linux-ARM64.tar.gz", True
    )
    for libc in ("glibc", "musl", None):
        assert digests.matches(static, {"os": "linux", "arch": "aarch64", "libc": libc})
    assert not digests.matches(static, {"os": "linux", "arch": "x86", "libc": "glibc"})
    assert not digests.matches(static, {"os": "macos", "arch": "aarch64", "libc": None})
    glibc = digests.lookup("sha256:2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d")
    musl = digests.lookup("sha256:b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9")
    assert digests.matches(glibc, {"os": "linux", "arch": "aarch64", "libc": "glibc"})
    assert not digests.matches(glibc, {"os": "linux", "arch": "aarch64", "libc": "musl"})
    assert not digests.matches(musl, {"os": "linux", "arch": "aarch64", "libc": "glibc"})
    assert {b.libc for b in digests.TABLE.values() if b.tool == "opengrep" and b.os == "linux"} == {
        "glibc",
        "musl",
    }


def test_07b_trivy_table_matches_validation_record():
    entries = trivy_entries()
    assert set(entries) == {ARM, X86}
    for digest, build in entries.items():
        assert digests.lookup(digest) == build
        assert build.version == "0.76.1" and build.os == "linux" and build.libc is None
    assert (entries[ARM].arch, entries[ARM].asset, entries[ARM].validated) == (
        "aarch64",
        "trivy_0.76.1_Linux-ARM64.tar.gz",
        True,
    )
    assert (entries[X86].arch, entries[X86].asset, entries[X86].validated) == (
        "x86",
        "trivy_0.76.1_Linux-64bit.tar.gz",
        False,
    )
    assert {
        asset: digest.removeprefix("sha256:") for asset, digest in digests.TRIVY_ARCHIVES.items()
    } == ARCHIVES
    if VALIDATION.exists():
        readme = (VALIDATION / "README.md").read_text(encoding="utf-8")
        for value in (
            *ARCHIVES.values(),
            ARM.removeprefix("sha256:"),
            X86.removeprefix("sha256:"),
            *ARCHIVES,
        ):
            assert value in readme, value
    docs = [
        Path(digests.__file__).read_text(encoding="utf-8"),
        (TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-guard" / "references" / "guard-records.md").read_text(
            "utf-8"
        ),
    ]
    assert any("AC-28" in d and "FEATURE-003-C" in d and "pending" in d for d in docs)


def test_07a_validation_record_complete_and_bound_to_driver():
    if not VALIDATION.exists():
        pytest.skip("x-ipe-docs is not part of this checkout; mandatory in acceptance")
    readme = (VALIDATION / "README.md").read_text(encoding="utf-8")
    driver = hashlib.sha256((VALIDATION / "validate.py").read_bytes()).hexdigest()
    lines = (VALIDATION / "results-linux-aarch64.jsonl").read_text(encoding="utf-8").splitlines()
    meta = json.loads(lines[0])
    assert meta["case"] == "meta" and meta["driver_sha256"] == driver and driver in readme
    assert "All phases ran with this one committed driver revision" in readme
    for needed in (
        "v0.76.1",
        "checksums.txt",
        "sigstore",
        "not verified",
        "Environment",
        "mirror.gcr.io/aquasec/trivy-db:2",
        "mirror.gcr.io/aquasec/trivy-java-db:1",
        "mirror.gcr.io/aquasec/trivy-checks:2",
        "UpdatedAt",
        "WebGoat",
        "shanghai-marathon-registration",
        "Fixtures",
        "Image archives",
        "Known Issues",
        "Exit",
        "Time",
    ):
        assert needed in readme, needed
    date = re.search(r"Date: (\d{4}-\d{2}-\d{2})", readme).group(1)
    assert date <= time.strftime("%Y-%m-%d")
    cases = {json.loads(x)["case"] for x in lines}
    assert {
        "webgoat-all-scanners",
        "marathon-all-scanners",
        "fixture-misconfig",
        "image-redis-alpine",
        "provision-vulnerability_db-mirror.gcr.io",
        "version",
    } <= cases


# ======================================================================= process extensions (002-B)
@posix_only
def test_process_run_in_memory_stdout_cap_and_stderr_sink(tmp_path):
    code = (
        "import sys\nsys.stderr.write('e' * 10000)\nsys.stderr.flush()\nsys.stdout.write('{\"ok\": true}')\n"
    )
    chunks: list[bytes] = []
    out = process.run(
        [sys.executable, "-c", code],
        tmp_path,
        {"PATH": os.defpath},
        time.monotonic() + 30,
        None,
        1024 * 1024,
        None,
        chunks.append,
    )
    assert out.exit == 0 and out.stdout == b'{"ok": true}' and not out.oversized
    assert b"".join(chunks) == b"e" * 10000 and len(out.stderr_tail) <= process.STDERR_TAIL
    assert list(tmp_path.iterdir()) == []  # nothing written to disk
    big = "import sys\nsys.stdout.write('x' * (3 * 1024 * 1024))\n"
    out = process.run(
        [sys.executable, "-c", big], tmp_path, {"PATH": os.defpath}, time.monotonic() + 30, None, 1024 * 1024
    )
    assert (
        out.oversized and out.exit is None and (out.stdout is None or len(out.stdout) <= 1024 * 1024 + 65536)
    )


def test_minimal_env_matches_the_former_toolrun_environment(tmp_path):
    stage, home = tmp_path / "stage", tmp_path / "home"
    home.mkdir()
    env = process.minimal_env(stage, home)
    assert env == {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "TMPDIR": str(stage / "tmp"),
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
    }
    assert (stage / "tmp").is_dir() and (stage / "work").is_dir() and (home / ".cache").is_dir()


# ======================================================================= trivy.py constants and argv
def test_scan_argv_exact_offline_flags():
    from x_ipe_secure_code.adapters import trivy

    assert trivy.OFFLINE == OFFLINE and trivy.COMMON == COMMON
    b, root, cache = Path("/s/bin/trivy"), Path("/s/c1/root"), Path("/s/c1/cache")
    assert trivy.scan_argv(b, "vuln", "filesystem", root, cache, 660) == [
        str(b),
        "fs",
        "--scanners",
        "vuln",
        *OFFLINE,
        *COMMON,
        "--cache-dir",
        str(cache),
        "--timeout",
        "660s",
        "--list-all-pkgs",
        str(root),
    ]
    assert trivy.scan_argv(b, "secret", "filesystem", root, cache, 61) == [
        str(b),
        "fs",
        "--scanners",
        "secret",
        *OFFLINE,
        *COMMON,
        "--cache-dir",
        str(cache),
        "--timeout",
        "61s",
        str(root),
    ]
    pattern = SimpleNamespace(type="dockerfile", path="Dockerfile_desktop.v1")
    assert trivy.scan_argv(b, "misconfig", "filesystem", root, cache, 61, [pattern]) == [
        str(b),
        "fs",
        "--scanners",
        "misconfig",
        *OFFLINE,
        *COMMON,
        "--cache-dir",
        str(cache),
        "--timeout",
        "61s",
        "--file-patterns",
        "dockerfile:" + re.escape("Dockerfile_desktop.v1"),
        str(root),
    ]
    archive = Path("/s/src/dist/app.tar")
    assert trivy.scan_argv(b, "vuln", "image_archive", archive, cache, 99) == [
        str(b),
        "image",
        "--input",
        str(archive),
        "--scanners",
        "vuln",
        *OFFLINE,
        *COMMON,
        "--cache-dir",
        str(cache),
        "--timeout",
        "99s",
        "--list-all-pkgs",
        "--cache-backend",
        "memory",
    ]
    for scanner, mode in (
        ("vuln", "filesystem"),
        ("misconfig", "filesystem"),
        ("secret", "filesystem"),
        ("vuln", "image_archive"),
    ):
        argv = trivy.scan_argv(b, scanner, mode, root, cache, 61)
        for forbidden in (
            "--exit-code",
            "--severity",
            "--ignore-unfixed",
            "--skip-files",
            "--skip-dirs",
            "--vex",
            "--compliance",
            "--server",
            "--db-repository",
            "--java-db-repository",
            "--checks-bundle-repository",
            "--include-non-failures",
        ):
            assert forbidden not in argv


def test_repositories_and_known_hosts_pinned_to_v0761():
    from x_ipe_secure_code.adapters import trivy

    assert trivy.REPOSITORIES == {
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
    assert trivy.KNOWN_HOSTS == {
        ("0.76.1", "mirror.gcr.io"): ("mirror.gcr.io",),
        ("0.76.1", "ghcr.io"): ("ghcr.io", "pkg-containers.githubusercontent.com"),
    }


def test_config_types_pinned_without_compose():
    from x_ipe_secure_code.adapters import trivy

    types = set(trivy.CONFIG_TYPES)
    assert {"dockerfile", "kubernetes", "terraform"} <= types  # Type values observed in the validation
    assert not {t for t in types if "compose" in t} and all(t == t.lower() for t in types)


def test_severity_mapping_unknown_fallback():
    from x_ipe_secure_code.adapters import trivy

    assert trivy.SEVERITY == {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "UNKNOWN": "unknown",
    }
    for raw, expected in (
        ("CRITICAL", "critical"),
        ("LOW", "low"),
        ("UNKNOWN", "unknown"),
        ("WEIRD", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
        ("high", "unknown"),
    ):
        assert trivy.guard_severity(raw) == expected, raw


def test_secret_sanitize_drops_match_code_offset():
    from x_ipe_secure_code.adapters import trivy

    key = "AKIA" + hashlib.sha256(os.urandom(8)).hexdigest()[:16].upper()
    context = "region-" + hashlib.sha256(key.encode()).hexdigest()[:10]
    stage = "/p/.x-ipe/private/secure-code/adapter-stage/trivy/stage-0123456789abcdef/c1/root"
    doc = {
        "SchemaVersion": 2,
        "ArtifactName": stage,
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "app/settings.env",
                "Class": "secret",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key ID",
                        "StartLine": 2,
                        "EndLine": 2,
                        "Offset": 40,
                        "Match": "aws_key = " + "*" * len(key),
                        "Code": {
                            "Lines": [
                                {"Number": 1, "Content": context},
                                {"Number": 2, "Content": "aws_key = " + key},
                            ]
                        },
                    }
                ],
            },
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "MisconfSummary": {"Successes": 26, "Failures": 1},
                "Misconfigurations": [
                    {
                        "ID": "DS-0002",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "Message": "root",
                        "CauseMetadata": {
                            "StartLine": 1,
                            "EndLine": 1,
                            "Code": {"Lines": [{"Number": 1, "Content": context}]},
                        },
                    }
                ],
            },
        ],
    }
    clean = trivy.sanitize(doc, stage)
    text = json.dumps(clean)
    assert key not in text and context not in text and stage not in text
    (secret,) = clean["Results"][0]["Secrets"]
    assert not {"Match", "Code", "Offset"} & set(secret) and secret["MaskedLength"] == len(key)
    assert "Code" not in clean["Results"][1]["Misconfigurations"][0]["CauseMetadata"]
    assert clean["Results"][1]["MisconfSummary"] == {"Successes": 26, "Failures": 1}


# ======================================================================= trivy_log.py
def _facts(*names: str, chunk: int | None = None):
    from x_ipe_secure_code.adapters import trivy_log

    parser = trivy_log.LogParser()
    data = b"".join((LOGS / n).read_bytes() for n in names)
    step = chunk or len(data) or 1
    for i in range(0, len(data), step):
        parser.feed(data[i : i + step])
    return parser.finish()


def _paths(value) -> set[str]:
    if isinstance(value, dict):
        return set(value)
    return {v["path"] if isinstance(v, dict) else v for v in value}


def test_log_parser_v0761_lines():
    from x_ipe_secure_code.adapters import trivy_log

    f = _facts("webgoat-all-scanners-debug-excerpt.txt")
    assert f.recognized and set(f.anchors) == {"vuln", "misconfig", "secret"}
    assert {".dockerignore", ".editorconfig", ".github/FUNDING.yml"} <= _paths(f.secret_scanned)
    assert {"analyzer": "pom", "name": "com.fasterxml.jackson.core:jackson-databind"} in [
        {"analyzer": p["analyzer"], "name": p["name"]} for p in f.skipped_packages
    ]
    assert f.remote_pom_skipped == 4 and list(f.config_scanned) == ["Dockerfile"]
    assert f.counts["language_files"] == 1 and f.counts["config_files"] == 1
    degrading = [m for m in f.messages if m["kind"] == "degrading"]
    assert any("Dependency version cannot be determined" in m["text"] for m in degrading)
    assert not f.embedded_fallback and not f.os_not_detected and not f.timed_out
    # chunk boundaries never change the facts (streaming parser)
    g = _facts("webgoat-all-scanners-debug-excerpt.txt", chunk=7)
    assert (
        _paths(g.secret_scanned) == _paths(f.secret_scanned) and g.remote_pom_skipped == f.remote_pom_skipped
    )

    s = _facts("secret-coverage-debug-excerpt.txt")
    assert ".git" in _paths(s.skipped_paths) and "src/big.txt" in _paths(s.secret_scanned)
    too_large = [m for m in s.messages if "too large" in m["text"]]
    assert too_large and all(m["kind"] == "benign" for m in too_large)  # still scanned (observed)

    assert _facts("no-checks-bundle-misconfig.txt").embedded_fallback
    assert _facts("corrupted-db.txt").component_errors == {"vulnerability_db": "unreadable"}
    assert _facts("no-db-vuln.txt").component_errors == {"vulnerability_db": "missing"}
    assert _facts("no-java-db-image-with-jar.txt").component_errors == {"java_db": "missing"}
    assert _facts("tool-timeout-1ms.txt").timed_out
    hello = _facts("image-hello-world-debug.txt")
    assert hello.os_not_detected and hello.continuations >= 1  # the truncated first line is a continuation
    redis = _facts("image-redis-alpine-tail.txt")  # truncated tail of one WARN record: a continuation
    assert redis.continuations == 1 and "/home/runner" not in json.dumps(redis.messages)
    p = trivy_log.LogParser()
    p.feed(
        b"2026-10-22T17:07:49Z\tWARN\tUnable to get vulnerability details (CVE may be rejected)\t"
        b'err="failed to get vulnerability\\n  --- at /home/runner/work/trivy/x.go:37"\n'
    )
    warn = p.finish().messages
    assert [m["kind"] for m in warn] == ["benign"]
    assert not _facts("checks-bundle-denied.txt").anchors - {"misconfig"}


def test_log_parser_unrecognized_format_and_bounds():
    from x_ipe_secure_code.adapters import trivy_log

    p = trivy_log.LogParser()
    p.feed(b'{"level":"info","msg":"scan started"}\n{"level":"info","msg":"done"}\n')
    f = p.finish()
    assert not f.recognized and not f.anchors
    p = trivy_log.LogParser()
    line = '2026-10-22T17:07:46Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="f{}"\n'
    p.feed(b"2026-10-22T17:07:46Z\tINFO\t[secret] Secret scanning is enabled\n")
    p.feed("".join(line.format(i) for i in range(60_000)).encode())
    p.feed(b"2026-10-22T17:07:46Z\tWARN\t" + b"w" * (70 * 1024) + b"\n")
    for i in range(300):
        p.feed(f"2026-10-22T17:07:46Z\tWARN\tmessage {i}\n".encode())
    f = p.finish()
    assert len(_paths(f.secret_scanned)) <= 50_000 and len(f.messages) <= 200
    assert all(len(m["text"]) <= 300 for m in f.messages)


# ======================================================================= trivy_account.py
def test_account_misconfig_requires_json_summary():
    from x_ipe_secure_code.adapters import trivy_account, trivy_log

    parser = trivy_log.LogParser()
    parser.feed(
        b"2026-10-22T17:07:46Z\tINFO\t[misconfig] Misconfiguration scanning is enabled\n"
        b'2026-10-22T17:07:46Z\tDEBUG\tScanned config file\tfile_path="app/Dockerfile_desktop"\n'
    )
    facts = parser.finish()
    doc = {
        "SchemaVersion": 2,
        "ArtifactName": "root",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "MisconfSummary": {"Successes": 27, "Failures": 0},
            },
            {
                "Target": "k8s/deploy.yaml",
                "Class": "config",
                "Type": "kubernetes",
                "MisconfSummary": {"Successes": -1, "Failures": 0},
            },
            {
                "Target": ".",
                "Class": "config",
                "Type": "terraform",
                "MisconfSummary": {"Successes": 69, "Failures": 0},
            },
        ],
    }
    files = [
        "Dockerfile",
        "k8s/deploy.yaml",
        "app/Dockerfile_desktop",
        "docker-compose.yml",
        "notes.txt",
        "main.tf",
    ]
    acc = trivy_account.account(
        scanner="misconfig", mode="filesystem", files=files, doc=doc, facts=facts, bundle_linked=True
    )
    assert acc["analysed"] == ["Dockerfile"] and acc["misconf"]["Dockerfile"] == {
        "successes": 27,
        "failures": 0,
    }
    text = json.dumps(acc)
    assert "configuration type not supported by Trivy v0.76.1" in text and "docker-compose.yml" in text
    assert "reported only in the debug log; no per-file result" in text and "app/Dockerfile_desktop" in text
    assert (
        "not recognized as a configuration file" in text and "main.tf" in text and "k8s/deploy.yaml" in text
    )
    assert acc["checks_source"] == "provisioned"
    missing = trivy_account.account(
        scanner="misconfig",
        mode="filesystem",
        files=["Dockerfile"],
        doc=doc,
        facts=facts,
        bundle_linked=False,
    )
    assert missing["checks_source"] != "provisioned"
    assert "checks bundle missing / embedded-checks fallback" in json.dumps(missing)


# ======================================================================= trivy_cache.py
def _cache(root: Path, components: dict) -> Path:
    cache = root / ".x-ipe/private/secure-code/tools/trivy-cache"
    entries = {}
    for name, (sub, files, metadata, tag, repo) in components.items():
        gen = "20261023T010203Z-1f2e3d4c"
        base = cache / "gen" / name / gen
        records = {}
        for rel, data in {**files, f"{sub}/metadata.json": json.dumps(metadata).encode()}.items():
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_bytes(data)
            records[rel] = {"sha256": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}
        lines = "".join(f"{r}\0{v['sha256']}\n" for r, v in sorted(records.items()))
        entries[name] = {
            "generation": gen,
            "registry": "mirror.gcr.io",
            "repository": repo,
            "tag": tag,
            "provisioned_at": "2026-10-23T01:02:03Z",
            "verification_id": "gv-20261023T010000Z-1a2b3c4d",
            "provisioning": 1,
            "grants": ["g-1"],
            "size_bytes": sum(v["size"] for v in records.values()),
            "disk_bytes": 0,
            "content_digest": "sha256:" + hashlib.sha256(lines.encode()).hexdigest(),
            "files": records,
            "metadata": metadata,
            "invalid": None,
        }
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "components.json").write_text(
        json.dumps(
            {
                "schema": "ai-secure-code-toolkit/trivy-cache/v1",
                "tool_version": "0.76.1",
                "revision": 1,
                "components": entries,
            }
        )
    )
    return cache


DB_META = {
    "Version": 2,
    "UpdatedAt": "2026-10-22T13:15:26.425424764Z",
    "NextUpdate": "2026-10-23T13:15:26.425424534Z",
    "DownloadedAt": "2026-10-22T16:53:21.885330596Z",
}
BUNDLE_META = {
    "MajorVersion": 2,
    "Digest": "sha256:b591e9190cff4aa4e385b1a25bccfd9ecf178d3c77fd194e1410b7ce7e1df058",
    "DownloadedAt": "2026-10-22T16:59:54.243964763Z",
}


def test_age_and_metadata_schema_split(tmp_path):
    from x_ipe_secure_code.adapters import trivy_cache

    _cache(
        tmp_path,
        {
            "vulnerability_db": (
                "db",
                {"db/trivy.db": b"d" * 4096},
                DB_META,
                "2",
                "mirror.gcr.io/aquasec/trivy-db",
            ),
            "checks_bundle": (
                "policy",
                {"policy/content/a.rego": b"package a\n"},
                BUNDLE_META,
                "2",
                "mirror.gcr.io/aquasec/trivy-checks",
            ),
        },
    )
    now = datetime(2026, 10, 23, 15, 15, 26, 425425, tzinfo=UTC)
    db = trivy_cache.component_state(tmp_path, "vulnerability_db", now)
    assert db["state"] == "present" and db["metadata"]["Version"] == 2
    assert db["age_seconds"] == 93600 and db["age"] == "1 d 2 h"
    assert (
        db["repository"] == "mirror.gcr.io/aquasec/trivy-db"
        and db["tag"] == "2"
        and db["registry"] == "mirror.gcr.io"
    )
    bundle = trivy_cache.component_state(tmp_path, "checks_bundle", now)
    assert bundle["state"] == "present" and set(bundle["metadata"]) == {
        "MajorVersion",
        "Digest",
        "DownloadedAt",
    }
    assert "age_seconds" not in bundle and "age" not in bundle
    assert trivy_cache.component_state(tmp_path, "java_db", now)["state"] == "missing"
    later = trivy_cache.component_state(tmp_path, "vulnerability_db", now + timedelta(days=400))
    assert later["state"] == "present" and later["age_seconds"] == 93600 + 400 * 86400  # no threshold
    assert "stale" not in json.dumps(later).lower()


@pytest.mark.parametrize(
    "damage",
    [
        "version-not-tag",
        "bundle-digest-format",
        "missing-file",
        "size",
        "extra-file",
        "hard-link",
        "symlink",
        "invalid-mark",
        "metadata-hash",
        "generation-missing",
    ],
)
def test_component_state_unreadable_cases(tmp_path, damage):
    from x_ipe_secure_code.adapters import trivy_cache

    meta = dict(DB_META, Version=1) if damage == "version-not-tag" else DB_META
    bmeta = dict(BUNDLE_META, Digest="md5:abc") if damage == "bundle-digest-format" else BUNDLE_META
    cache = _cache(
        tmp_path,
        {
            "vulnerability_db": (
                "db",
                {"db/trivy.db": b"d" * 4096},
                meta,
                "2",
                "mirror.gcr.io/aquasec/trivy-db",
            ),
            "checks_bundle": (
                "policy",
                {"policy/content/a.rego": b"package a\n"},
                bmeta,
                "2",
                "mirror.gcr.io/aquasec/trivy-checks",
            ),
        },
    )
    name = "checks_bundle" if damage == "bundle-digest-format" else "vulnerability_db"
    base = cache / "gen" / "vulnerability_db" / "20261023T010203Z-1f2e3d4c"
    if damage == "missing-file":
        (base / "db/trivy.db").unlink()
    elif damage == "size":
        (base / "db/trivy.db").write_bytes(b"d" * 10)
    elif damage == "extra-file":
        (base / "db/extra").write_bytes(b"x")
    elif damage == "hard-link":
        os.link(base / "db/trivy.db", tmp_path / "outside-link")
    elif damage == "symlink":
        (base / "db/trivy.db").unlink()
        os.symlink(tmp_path / "elsewhere", base / "db/trivy.db")
    elif damage == "invalid-mark":
        p = json.loads((cache / "components.json").read_text())
        p["components"]["vulnerability_db"]["invalid"] = {
            "reason": "db/trivy.db changed since provisioning",
            "detected_at": "t",
            "verification_id": "v",
            "run": 1,
        }
        (cache / "components.json").write_text(json.dumps(p))
    elif damage == "metadata-hash":
        data = (base / "db/metadata.json").read_bytes()
        (base / "db/metadata.json").write_bytes(data.replace(b"2026-10-22", b"2026-10-21"))
    elif damage == "generation-missing":
        os.rename(base, base.with_name("moved"))
    out = trivy_cache.component_state(tmp_path, name, datetime(2026, 10, 23, tzinfo=UTC))
    assert out["state"] == "unreadable" and out["reason"], out
    if damage == "invalid-mark":
        assert out["reason"].startswith("invalid: ") and out["reason"].endswith("re-provision")


# ======================================================================= FEATURE-002-C / 002-A hooks
def test_budget_internal_tool_update_attempt():
    from x_ipe_secure_code.guard import budget
    from x_ipe_secure_code.guard.model import GuardError

    s = {
        "opened_at": "2026-10-20T10:00:00Z",
        "plan": {"checks": [{"id": "C1", "methods": []}], "not_applicable": [], "method_changes": []},
        "evidence": [],
        "findings": [],
        "reviews": [],
        "budget": budget.initial(None),
        "attempts": [],
    }
    budget.set_planned(s)
    a = budget.register(
        s,
        "tool_update",
        {"components": ["vulnerability_db", "java_db"]},
        0,
        "2026-10-20T10:00:00Z",
        internal=True,
    )
    assert a["kind"] == "tool_update" and a["extra"] == 0 and a["status"] == "unfinished"
    assert a["covers"] == {
        "pairs": [],
        "findings": [],
        "na": [],
        "components": ["vulnerability_db", "java_db"],
    }
    with pytest.raises(GuardError) as exc:
        budget.register(s, "tool_update", {"components": ["vulnerability_db"]}, 0, "2026-10-20T10:00:00Z")
    assert exc.value.code == "ATTEMPT_INVALID"


def test_commit_state_on_commit_runs_inside_the_barrier(tmp_path):
    from x_ipe_secure_code.guard import runs
    from x_ipe_secure_code.guard.model import SCHEMA_RUN, GuardError

    vid = "gv-20261020T100000Z-0000abcd"
    (tmp_path / runs.run_rel(vid)).mkdir(parents=True)
    runs.write_state(tmp_path, {"schema": SCHEMA_RUN, "verification_id": vid, "revision": 3})
    seen = []
    state = runs.read_state(tmp_path, vid)
    runs.commit_state(
        tmp_path,
        state,
        expected_revision=3,
        on_commit=lambda: seen.append(runs.read_state(tmp_path, vid)["revision"]),
    )
    assert seen == [3] and runs.read_state(tmp_path, vid)["revision"] == 4
    with pytest.raises(GuardError):
        runs.commit_state(
            tmp_path,
            runs.read_state(tmp_path, vid),
            expected_revision=3,
            on_commit=lambda: seen.append("stale"),
        )
    runs.create_marker(tmp_path, vid, {"requested_at": "t", "reason": None, "consumed_at_request": 1.0})
    with pytest.raises(GuardError) as exc:
        runs.commit_state(
            tmp_path,
            runs.read_state(tmp_path, vid),
            expected_revision=4,
            on_commit=lambda: seen.append("cancelled"),
        )
    assert exc.value.code == "RUN_CANCELLED" and seen == [3]


def test_limits_text_names_trivy_limits():
    from x_ipe_secure_code.guard import engine

    assert (
        "Adapters: Opengrep and Trivy run only as the registered official binaries on staged copies; their "
        "file-system and network access are not OS-enforced; Trivy runs on Linux x86-64/arm64 only, scans "
        "offline, reads the provisioned components in place (changes are detected by re-hashing after each "
        "scan, not prevented) and its provisioning hosts are a configuration-level expectation; Strix is not "
        "available yet"
    ) in engine.LIMITS
