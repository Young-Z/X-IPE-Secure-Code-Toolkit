"""Integration tests for FEATURE-002-D: Trivy registration, pre-check, offline scans, accounting, evidence.

The fake binary (`tests/adapters/fake_trivy.py`) reproduces the recorded Trivy v0.76.1 behaviour of the
tool-level validation; the host is patched to Linux so the suite runs on the macOS dev host and Linux CI.
"""

# ruff: noqa: F811
from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import posix_only, tree_hashes
from test_guard import with_attempt  # noqa: E402,I001
from trivyhelp import (  # noqa: F401 - fixture reuse
    ALL,
    ALPINE,
    ALPINE_PKGS,
    CACHE,
    COMPOSE,
    DEPLOYMENT,
    DOCKERFILE,
    GUARD,
    MAIN_TF,
    OFFLINE,
    PLATFORM_GAP,
    POM,
    POM_COMPLETE,
    PRIVATE,
    R1,
    READ_METHOD,
    RECORD,
    REPORTS,
    STAGE_ROOT,
    TRIVY_METHOD,
    calls,
    cancel_when_called,
    clock,
    conclude_report,
    env,
    fake_aws_key,
    fake_github_token,
    flag_value,
    gaps_text,
    gen_dir,
    grant,
    grant_for,
    image,
    install_fake,
    linux,
    nothing_recorded,
    opened,
    plan,
    planned,
    pointer,
    private_tree,
    provision,
    provisioned,
    req,
    run_entry,
    scan,
    set_cfg,
    set_host,
    state,
    tamper,
    tcheck,
    tev,
    trc,
    trivy,
    trivy_status,
    trivytar,
    write,
)

from x_ipe_secure_code import tools_service
from x_ipe_secure_code.adapters import ADAPTERS, process
from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust
from x_ipe_secure_code.guard import egress, engine, toolrun
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.guard.targets import file_digest

pytestmark = posix_only
MAC_ENV = {"__CF_USER_TEXT_ENCODING"}  # injected by macOS into every process, not passed by the Adapter
MINIMAL_ENV = {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "PATH", "LANG", "TZ"}


def scans(fake):
    return calls(fake, "scan")


def accounting(check_entry, scanner):
    """The per-scanner accounting of one check (a list of per-scanner entries or a mapping by scanner)."""
    acc = check_entry["accounting"]
    if isinstance(acc, dict) and scanner in acc:
        return acc[scanner]
    return next(a for a in acc if a["scanner"] == scanner)


# ======================================================================= AC-002D-01 registration, pre-check
def test_01a_register_trivy_records_asset_without_executing(env, linux, monkeypatch):
    fake = install_fake(env, monkeypatch, linux, register=False)
    result = tools_service.register(
        str(env["project"]), "trivy", str(fake["binary"]), trust_paths=env["paths"]
    )
    assert result.ok, result.to_text()
    data = result.data
    assert data["tool"] == "trivy" and data["version"] == "0.76.1" and data["asset"] == "fake-asset"
    assert data["platform"] == {"os": "linux", "arch": linux["arch"], "libc": None}
    assert data["platform_validated"] is False and data["digest"] == file_digest(fake["binary"])
    record = json.loads((env["project"] / RECORD).read_text())
    for key in ("path", "digest", "version", "asset", "platform", "platform_validated"):
        assert record[key] == (str(fake["binary"]) if key == "path" else data[key]), key
    assert calls(fake) == []  # compared before (and without) any execution


@pytest.mark.parametrize(
    "case", ["no-maintainer", "unknown-digest", "release-archive", "symlink", "missing", "folder"]
)
def test_01b_register_refusals_execute_nothing(env, linux, monkeypatch, case):
    fake = install_fake(env, monkeypatch, linux, register=False)
    paths, target = env["paths"], fake["binary"]
    if case == "no-maintainer":
        paths = resolve_trust(env["tmp"] / "no-trust")
    elif case == "unknown-digest":
        target = env["tmp"] / "trivy-custom"
        target.write_bytes(fake["binary"].read_bytes() + b"\n# rebuilt\n")
        target.chmod(0o755)
    elif case == "release-archive":
        target = env["tmp"] / "trivy_0.76.1_Linux-ARM64.tar.gz"
        with tarfile.open(target, "w:gz") as tar:
            tar.add(fake["binary"], arcname="trivy")
    elif case == "symlink":
        target = env["tmp"] / "trivy-link"
        os.symlink(fake["binary"], target)
    elif case == "missing":
        target = env["tmp"] / "nope" / "trivy"
    else:
        target = env["tmp"] / "a-folder"
        target.mkdir()
    result = tools_service.register(str(env["project"]), "trivy", str(target), trust_paths=paths)
    expected = {
        "no-maintainer": "NOT_AUTHORIZED",
        "unknown-digest": "TOOL_DIGEST_UNKNOWN",
        "release-archive": "TOOL_DIGEST_UNKNOWN",
        "symlink": "TOOL_PATH_INVALID",
        "missing": "TOOL_PATH_INVALID",
        "folder": "TOOL_PATH_INVALID",
    }[case]
    assert not result.ok and result.problems[0].code == expected, result.to_text()
    assert result.problems[0].message and result.next_steps
    assert calls(fake) == [] and not (env["project"] / RECORD).exists()


@pytest.mark.parametrize(("os_", "arch"), [("macos", "aarch64"), ("windows", "x86"), ("linux", "riscv64")])
def test_01c_non_linux_register_provision_refused_run_precheck_failed(env, trivy, monkeypatch, os_, arch):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    grant_for(env, vid)
    record_before = (env["project"] / RECORD).read_bytes()
    set_host(monkeypatch, os_, arch)
    reg = tools_service.register(str(env["project"]), "trivy", str(trivy["binary"]), trust_paths=env["paths"])
    assert not reg.ok and reg.problems[0].code == "ADAPTER_PLATFORM_UNSUPPORTED"
    assert PLATFORM_GAP in reg.problems[0].message and reg.next_steps
    assert (env["project"] / RECORD).read_bytes() == record_before
    before = state(env, vid)
    prov = provision(env, vid, ["vulnerability_db"])
    assert not prov.ok and prov.problems[0].code == "ADAPTER_PLATFORM_UNSUPPORTED"
    assert PLATFORM_GAP in prov.problems[0].message and prov.next_steps
    after = state(env, vid)
    assert after["egress"]["declarations"] == before["egress"]["declarations"]  # nothing recorded
    assert after["attempts"] == before["attempts"] and after["revision"] == before["revision"]
    result = scan(env, vid, [trc()])
    assert result.ok and result.data["status"] == "precheck_failed"
    ev = tev(env, vid)
    assert ev["method_status"] == "failed" and PLATFORM_GAP in ev["summary"]
    assert calls(trivy) == []


@pytest.mark.parametrize("problem", ["unregistered", "binary-changed", "stage-unsafe", "component-missing"])
def test_01d_precheck_failures_recorded_per_check(env, trivy, problem):
    write(env, {"pom.xml": POM_COMPLETE, "app/settings.env": "debug=false\n", "other.xml": "<x/>\n"})
    checks = [tcheck(), tcheck("C2", obj=("app/settings.env",))]
    vid = planned(env, checks, targets=("pom.xml", "app/settings.env"))
    if problem != "component-missing":
        provisioned(env, vid)
    if problem == "unregistered":
        (env["project"] / RECORD).unlink()
    elif problem == "binary-changed":
        trivy["binary"].write_text(trivy["binary"].read_text() + "\n# swapped\n")
    elif problem == "stage-unsafe":
        (env["project"] / "pom.xml").unlink()
        os.symlink(env["project"] / "other.xml", env["project"] / "pom.xml")
    before = len(scans(trivy))
    result = scan(env, vid, [trc(), trc("C2", ("secret",), targets=("app/settings.env",))])
    assert result.ok, result.to_text()
    if problem == "component-missing":
        assert tev(env, vid)["method_status"] == "failed"
        assert "vulnerability_db" in gaps_text(result, env, vid) and "missing" in gaps_text(result, env, vid)
        assert tev(env, vid, "C2")["method_status"] == "ok", gaps_text(result, env, vid, "C2")
        assert [c["argv"][c["argv"].index("--scanners") + 1] for c in scans(trivy)] == ["secret"]
        return
    assert result.data["status"] == "precheck_failed"
    code = {
        "unregistered": "TOOL_NOT_REGISTERED",
        "binary-changed": "TOOL_DIGEST_MISMATCH",
        "stage-unsafe": "STAGE_UNSAFE",
    }[problem]
    assert result.problems[0].code == code and result.next_steps
    for cid in ("C1", "C2"):
        assert tev(env, vid, cid)["method_status"] == "failed"
        assert result.data["checks"][cid]["status"] == "precheck_failed"
    assert len(scans(trivy)) == before


def test_01e_no_automatic_action_and_maintainer_next_steps(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    result = scan(env, vid, [trc()])
    text = gaps_text(result, env, vid)
    assert "secure-code tools provision --tool trivy" in text and "tool_update" in text
    assert "vulnerability_db" in text
    assert calls(trivy, "provision") == [] and not (env["project"] / CACHE / "gen").exists()
    (env["project"] / RECORD).unlink()
    result = scan(env, vid, [trc()])
    assert result.data["status"] == "precheck_failed"
    assert any("tools register --tool trivy" in s for s in result.next_steps)
    assert not (env["project"] / RECORD).exists()  # never re-registered automatically
    assert calls(trivy) == []
    for text in (result.to_text().lower(), json.dumps(result.data).lower()):
        assert "security pass" not in text and '"verdict"' not in text


def test_01f_trivy_build_matches_host_of_any_libc(env, linux, monkeypatch):
    """Registration of the static (libc-independent) Trivy entry on a musl host (AC-002D-01f, integration)."""
    fake = install_fake(env, monkeypatch, linux, register=False)
    set_host(monkeypatch, "linux", linux["arch"], "musl")
    assert tools_service.register(
        str(env["project"]), "trivy", str(fake["binary"]), trust_paths=env["paths"]
    ).ok


# ======================================================================= AC-002D-02 offline scans, components
def test_02d_scans_offline_without_egress_even_with_tool_update_grant(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE, "Dockerfile": DOCKERFILE, "app/settings.env": "a=1\n"})
    checks = [tcheck(), tcheck("C2", obj=("Dockerfile",)), tcheck("C3", obj=("app/settings.env",))]
    vid = planned(env, checks, targets=("pom.xml", "Dockerfile", "app/settings.env"))
    provisioned(env, vid)
    assert ADAPTERS["trivy"].network is None
    assert egress.adapter_network_check(state(env, vid), "trivy", []).mode == "none"
    declarations = state(env, vid)["egress"]["declarations"]
    result = scan(
        env,
        vid,
        [
            trc(),
            trc("C2", ("misconfig",), targets=("Dockerfile",)),
            trc("C3", ("secret",), targets=("app/settings.env",)),
        ],
    )
    assert result.ok, result.to_text()
    assert len(scans(trivy)) == 3
    for call in scans(trivy):
        assert call["network_attempts"] == [] and all(f in call["argv"] for f in OFFLINE)
        for forbidden in (
            "--db-repository",
            "--java-db-repository",
            "--checks-bundle-repository",
            "--download-db-only",
            "--download-java-db-only",
            "--server",
        ):
            assert forbidden not in call["argv"]
    assert state(env, vid)["egress"]["declarations"] == declarations


@pytest.mark.parametrize(
    "variant",
    [
        "vuln-db-missing",
        "java-db-missing-image",
        "checks-bundle-missing",
        "invalid-mark",
        "metadata-changed",
        "tool-invalid-database",
    ],
)
def test_02e_missing_component_fails_only_needing_checks(env, trivy, variant):
    write(
        env,
        {
            "pom.xml": POM_COMPLETE,
            "Dockerfile": DOCKERFILE,
            "app/settings.env": "a=1\n",
            "dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS, jar=True),
        },
    )
    if variant == "java-db-missing-image":
        target, req_c1, need = "dist/app.tar", trc(mode="image_archive", targets=("dist/app.tar",)), "java_db"
        components = ("vulnerability_db", "checks_bundle")
    elif variant == "checks-bundle-missing":
        target, req_c1, need = (
            "Dockerfile",
            trc(scanners=("misconfig",), targets=("Dockerfile",)),
            "checks_bundle",
        )
        components = ("vulnerability_db", "java_db")
    else:
        target, req_c1, need = "pom.xml", trc(), "vulnerability_db"
        components = ALL if variant != "vuln-db-missing" else ("java_db", "checks_bundle")
    vid = planned(
        env,
        [tcheck(obj=(target,)), tcheck("C2", obj=("app/settings.env",))],
        targets=(target, "app/settings.env"),
    )
    provisioned(env, vid, components)
    if variant == "invalid-mark":
        set_cfg(trivy, mode="write-component")
        scan(env, vid, [req_c1])
        set_cfg(trivy, mode="normal")
    elif variant == "metadata-changed":
        tamper(gen_dir(env, "vulnerability_db") / "db" / "metadata.json", same_size=True)
    elif variant == "tool-invalid-database":
        set_cfg(trivy, mode="invalid-db")
    provisions = len(calls(trivy, "provision"))
    result = scan(env, vid, [req_c1, trc("C2", ("secret",), targets=("app/settings.env",))])
    assert result.ok, result.to_text()
    text = gaps_text(result, env, vid)
    assert tev(env, vid)["method_status"] == "failed" and need in text
    assert "secure-code tools provision --tool trivy" in text and f"--component {need}" in text
    expected_state = (
        "missing" if variant.endswith("missing") or variant == "java-db-missing-image" else "unreadable"
    )
    assert expected_state in text
    assert tev(env, vid, "C2")["method_status"] == "ok", gaps_text(result, env, vid, "C2")
    assert len(calls(trivy, "provision")) == provisions  # nothing downloaded
    if variant == "tool-invalid-database":
        assert trivy_status(env)["components"]["vulnerability_db"]["state"] == "unreadable"


def test_02f_component_state_and_age_in_evidence_no_threshold(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE, "Dockerfile": DOCKERFILE})
    vid = planned(env, [tcheck(), tcheck("C2", obj=("Dockerfile",))], targets=("pom.xml", "Dockerfile"))
    provisioned(env, vid)
    started = time.time()
    result = scan(env, vid, [trc(), trc("C2", ("misconfig",), targets=("Dockerfile",))])
    assert result.ok, result.to_text()
    entry = run_entry(env, vid)
    db = entry["components"]["vulnerability_db"]
    assert db["state"] == "present" and db["registry"] == "mirror.gcr.io"
    assert db["repository"] == "mirror.gcr.io/aquasec/trivy-db" and db["tag"] == "2"
    assert db["content_digest"] == pointer(env)["components"]["vulnerability_db"]["content_digest"]
    assert set(db["metadata"]) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
    updated = datetime.fromisoformat(db["metadata"]["UpdatedAt"][:19]).replace(tzinfo=UTC).timestamp()
    assert abs(db["age_seconds"] - (started - updated)) < 120 and db["age"]
    bundle = entry["components"]["checks_bundle"]
    assert set(bundle["metadata"]) >= {"MajorVersion", "Digest", "DownloadedAt"}
    assert bundle["repository"] == "mirror.gcr.io/aquasec/trivy-checks" and bundle["tag"] == "2"
    assert "age_seconds" not in bundle and "UpdatedAt" not in bundle["metadata"]
    summary = tev(env, vid)["summary"]
    assert "mirror.gcr.io/aquasec/trivy-db:2" in summary and db["content_digest"][:19] in summary
    assert "stale" not in json.dumps(state(env, vid)).lower()
    assert calls(trivy, "provision") and len(calls(trivy, "provision")) == 3  # never refreshed by a scan


def test_02g_rehash_detects_change_marks_invalid_until_reprovisioned(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    set_cfg(trivy, mode="write-component")
    result = scan(env, vid, [trc()])
    text = gaps_text(result, env, vid)
    assert tev(env, vid)["method_status"] == "failed"
    assert "vulnerability_db changed since provisioning" in text and "re-provision" in text
    assert run_entry(env, vid)["rehash"]["vulnerability_db"] != "unchanged"
    invalid = pointer(env)["components"]["vulnerability_db"]["invalid"]
    assert invalid and invalid["verification_id"] == vid
    status = trivy_status(env)["components"]["vulnerability_db"]
    assert status["state"] == "unreadable" and status["reason"].startswith("invalid:")
    set_cfg(trivy, mode="normal")
    again = scan(env, vid, [trc()])
    assert tev(env, vid)["method_status"] == "failed" and "unreadable" in gaps_text(again, env, vid)
    assert provision(env, vid, ["vulnerability_db"]).ok
    assert trivy_status(env)["components"]["vulnerability_db"]["state"] == "present"
    assert pointer(env)["components"]["vulnerability_db"]["invalid"] is None
    scan(env, vid, [trc()])
    assert tev(env, vid)["method_status"] == "ok"


def test_02g_components_read_in_place_unchanged_after_scans(env, trivy):
    write(
        env,
        {
            "pom.xml": POM_COMPLETE,
            "Dockerfile": DOCKERFILE,
            "dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS, jar=True),
        },
    )
    checks = [tcheck(), tcheck("C2", obj=("Dockerfile",)), tcheck("C3", obj=("dist/app.tar",))]
    vid = planned(env, checks, targets=("pom.xml", "Dockerfile", "dist/app.tar"))
    provisioned(env, vid)
    result = scan(
        env,
        vid,
        [
            trc(),
            trc("C2", ("misconfig",), targets=("Dockerfile",)),
            trc("C3", mode="image_archive", targets=("dist/app.tar",)),
        ],
    )
    assert result.ok, result.to_text()
    cache_root = (env["project"] / CACHE / "gen").resolve()
    for call in scans(trivy):
        assert call["resolved"], call
        for path in call["resolved"].values():
            assert Path(path).is_relative_to(cache_root), path
        assert all(
            v["kind"] == "link" for k, v in call["cache_listing"].items() if k in ("db", "java-db", "policy")
        )
    for name, entry in pointer(env)["components"].items():
        base = gen_dir(env, name)
        for rel, rec in entry["files"].items():
            assert "sha256:" + hashlib.sha256((base / rel).read_bytes()).hexdigest() == rec["sha256"], rel
    assert set(run_entry(env, vid)["rehash"].values()) == {"unchanged"}
    report = conclude_report(env, vid)
    assert "detected by re-hashing after each scan, not prevented" in report


@pytest.mark.parametrize("ending", ["cancel", "timeout", "error"])
def test_02g_rehash_runs_in_finally_on_cancel_timeout_and_error(env, trivy, ending):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    set_cfg(trivy, mode="write-component", then="exit1" if ending == "error" else "sleep")
    if ending == "cancel":
        thread, box = cancel_when_called(env, vid, trivy)
        result = scan(env, vid, [trc()])
        thread.join(60)
        assert result.problems[0].code == "RUN_CANCELLED"
        assert state(env, vid).get("adapter_runs", []) == [] and not [
            e for e in state(env, vid)["evidence"] if e["method"] == "trivy"
        ]
    else:
        result = scan(env, vid, [trc()], time_limit_seconds=3 if ending == "timeout" else 120)
        assert result.ok and tev(env, vid)["method_status"] == "failed"
        assert result.data["checks"]["C1"]["status"] == ("timed_out" if ending == "timeout" else "failed")
        assert run_entry(env, vid)["rehash"]["vulnerability_db"] != "unchanged"
    assert pointer(env)["components"]["vulnerability_db"]["invalid"] is not None
    assert trivy_status(env)["components"]["vulnerability_db"]["state"] == "unreadable"


# ======================================================================= AC-002D-03 named parameters
@pytest.mark.parametrize(
    "over",
    [
        {"surprise": 1},
        {"include_ignored": False},
        {"time_limit_seconds": ...},
        {"checks": ...},
        {"checks": [{"check": "C1", "mode": "filesystem", "targets": ["pom.xml"]}]},
        {"checks": [{"check": "C1", "scanners": ["vuln"], "targets": ["pom.xml"]}]},
        {"checks": [trc(scanners=[])]},
        {"checks": [{**trc(), "scanners": "vuln"}]},
        {"checks": [trc(scanners=["license"])]},
        {"checks": [trc(scanners=["vuln", "vuln"])]},
        {"checks": [trc(scanners=["vuln --severity HIGH"])]},
        {"checks": [trc(mode="rootfs")]},
        {"checks": [{**trc(), "severity": ["HIGH", "CRITICAL"]}]},
        {"checks": [{**trc(), "ignorefile": ".trivyignore"}]},
        {"checks": [{**trc(), "ignore_policy": "p.rego"}]},
        {"checks": [{**trc(), "vex": "vex.json"}]},
        {"checks": [{**trc(), "skip_files": ["pom.xml"]}]},
        {"checks": [{**trc(), "argv": ["--exit-code", "1"]}]},
        {"checks": [trc(targets=["pom.xml; rm -rf /"])]},
        {"checks": [trc(), trc()]},
        {"checks": [{**trc(), "targets": "pom.xml"}]},
    ],
)
def test_03a_request_schema_refusals(env, trivy, over):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    before = state(env, vid)
    result = scan(env, vid, over.pop("checks", [trc()]), **over)
    assert not result.ok and result.problems[0].code in ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH"), (
        result.to_text()
    )
    assert result.next_steps
    nothing_recorded(env, vid, before)
    assert calls(trivy) == []


def test_03a_license_scanner_refusal_names_scope(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    result = scan(env, vid, [trc(scanners=["license"])])
    assert result.problems[0].code == "TOOL_REQUEST_INVALID" and "license" in result.problems[0].message


@pytest.mark.parametrize(
    "targets",
    [["pom.xml"], ["README.md"], ["notes.txt"], ["other.xml"], ["pom.xml", "requirements.txt", "x.txt"]],
)
def test_03b_targets_cover_object_and_roles(env, trivy, targets):
    write(
        env,
        {
            "pom.xml": POM_COMPLETE,
            "requirements.txt": "requests==2.31.0\n",
            "notes.txt": "n\n",
            "other.xml": "<x/>\n",
            "x.txt": "x\n",
        },
    )
    vid = opened(
        env, targets=("pom.xml", "requirements.txt"), suggested=[{"path": "notes.txt", "reason": "r"}]
    )
    plan(env, vid, [tcheck(obj=("pom.xml", "requirements.txt"))])
    before = state(env, vid)
    result = scan(env, vid, [trc(targets=targets)])
    assert not result.ok and result.problems[0].code in ("TARGETS_MISMATCH", "TOOL_REQUEST_INVALID")
    nothing_recorded(env, vid, before)
    assert calls(trivy) == []


def test_03b_target_inside_folder_target_accepted(env, trivy):
    write(env, {"app/requirements.txt": "requests==2.31.0\n", "app/main.py": "print(1)\n"})
    vid = planned(env, [tcheck(obj=("app/requirements.txt",))], targets=("app",))
    provisioned(env, vid)
    result = scan(env, vid, [trc(targets=("app/requirements.txt",))])
    assert result.ok and tev(env, vid)["method_status"] == "ok", result.to_text()


@pytest.mark.parametrize(
    ("check_req", "codes"),
    [
        (trc(scanners=["secret"], mode="image_archive", targets=["dist/app.tar"]), ("TOOL_REQUEST_INVALID",)),
        (
            trc(scanners=["vuln", "misconfig"], mode="image_archive", targets=["dist/app.tar"]),
            ("TOOL_REQUEST_INVALID",),
        ),
        (trc(mode="image_archive", targets=["dist/oci.tar"]), ("IMAGE_ARCHIVE_INVALID",)),
        (trc(mode="image_archive", targets=["images"]), ("TOOL_REQUEST_INVALID",)),
        (trc(mode="image_archive", targets=["dist/app.img"]), ("TOOL_REQUEST_INVALID",)),
        (trc(mode="image_archive", targets=["redis:6-alpine"]), ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH")),
        (
            trc(mode="image_archive", targets=["redis@sha256:" + "a" * 64]),
            ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH"),
        ),
        (
            trc(mode="image_archive", targets=["docker://redis:6-alpine"]),
            ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH"),
        ),
        (
            trc(mode="image_archive", targets=["unix:///var/run/docker.sock"]),
            ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH"),
        ),
        (
            trc(mode="image_archive", targets=["/var/run/docker.sock"]),
            ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH"),
        ),
        (
            trc(mode="image_archive", targets=["https://registry.example/redis.tar"]),
            ("TOOL_REQUEST_INVALID", "TARGETS_MISMATCH"),
        ),
    ],
)
def test_03c_image_archive_mode_rules(env, trivy, check_req, codes):
    write(
        env,
        {
            "dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS),
            "dist/oci.tar": trivytar.oci_only(),
            "dist/app.img": image(os_info=ALPINE),
            "images/a.tar": image(os_info=ALPINE),
        },
    )
    obj = (
        tuple(check_req["targets"])
        if check_req["targets"][0].startswith(("dist/", "images"))
        else ("dist/app.tar",)
    )
    vid = planned(env, [tcheck(obj=obj)], targets=("dist/app.tar", "dist/oci.tar", "dist/app.img", "images"))
    provisioned(env, vid)
    before = state(env, vid)
    result = scan(env, vid, [check_req])
    assert not result.ok and result.problems[0].code in codes, result.to_text()
    nothing_recorded(env, vid, before)
    assert scans(trivy) == []


def test_03c_valid_archive_scanned_from_staged_copy_with_memory_cache(env, trivy):
    write(env, {"dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS)})
    vid = planned(env, [tcheck(obj=("dist/app.tar",))], targets=("dist/app.tar",))
    provisioned(env, vid)
    result = scan(env, vid, [trc(mode="image_archive", targets=("dist/app.tar",))])
    assert result.ok, result.to_text()
    (call,) = scans(trivy)
    assert call["argv"][1] == "image" and flag_value(call["argv"], "--cache-backend") == ["memory"]
    (archive,) = flag_value(call["argv"], "--input")
    assert str(env["project"] / STAGE_ROOT) in archive and archive != str(env["project"] / "dist/app.tar")


@pytest.mark.parametrize(
    "config_types",
    [
        [{"path": "Dockerfile", "type": "dockerfile"}],  # not a file of this check's object
        [{"path": "Dockerfile_desktop", "type": "compose"}],
        [{"path": "Dockerfile_desktop", "type": "docker-compose"}],
        [{"path": "Dockerfile_desktop", "type": "no-such-type"}],
        [
            {"path": "Dockerfile_desktop", "type": "dockerfile"},
            {"path": "Dockerfile_desktop", "type": "dockerfile"},
        ],
        [{"path": "Dockerfile_desktop", "type": "dockerfile", "extra": 1}],
        [{"path": "Dockerfile_desktop"}],
        "dockerfile:Dockerfile_desktop",
    ],
)
def test_03d_config_type_override_rules(env, trivy, config_types):
    write(env, {"Dockerfile_desktop": DOCKERFILE, "Dockerfile": DOCKERFILE})
    vid = planned(env, [tcheck(obj=("Dockerfile_desktop",))], targets=("Dockerfile_desktop", "Dockerfile"))
    before = state(env, vid)
    result = scan(
        env, vid, [trc(scanners=("misconfig",), targets=("Dockerfile_desktop",), config_types=config_types)]
    )
    assert not result.ok and result.problems[0].code == "TOOL_REQUEST_INVALID", result.to_text()
    nothing_recorded(env, vid, before)


def test_03d_override_needs_misconfig_scanner_and_reaches_argv(env, trivy):
    write(env, {"Dockerfile_desktop": DOCKERFILE})
    vid = planned(env, [tcheck(obj=("Dockerfile_desktop",))], targets=("Dockerfile_desktop",))
    provisioned(env, vid)
    override = [{"path": "Dockerfile_desktop", "type": "dockerfile"}]
    refused = scan(
        env, vid, [trc(scanners=("secret",), targets=("Dockerfile_desktop",), config_types=override)]
    )
    assert refused.problems[0].code == "TOOL_REQUEST_INVALID"
    result = scan(
        env, vid, [trc(scanners=("misconfig",), targets=("Dockerfile_desktop",), config_types=override)]
    )
    assert result.ok, result.to_text()
    (call,) = scans(trivy)
    assert flag_value(call["argv"], "--file-patterns") == [f"dockerfile:{re.escape('Dockerfile_desktop')}"]
    assert tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)
    assert run_entry(env, vid)["checks"]["C1"]["config_types"] == override


@pytest.mark.parametrize("limit", [0, -1, 1801, "60", 1.5, True, None])
def test_03e_time_limit_bounds(env, trivy, limit):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    before = state(env, vid)
    result = scan(env, vid, [trc()], time_limit_seconds=limit)
    assert result.problems[0].code == "TOOL_REQUEST_INVALID", result.to_text()
    nothing_recorded(env, vid, before)


def test_03e_time_limit_capped_by_remaining_budget(env, trivy, clock):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    clock.at(env, vid, 3550)
    result = scan(env, vid, [trc()], time_limit_seconds=600)
    assert result.ok, result.to_text()
    assert result.data["time_limit"] <= 50 and result.data["time_limit_capped"] is True
    entry = run_entry(env, vid)
    assert entry["requested_time_limit"] == 600 and entry["time_limit_capped"] is True


@pytest.mark.parametrize("case", ["concluded", "no-plan", "not-selected", "not-planned", "reading-kind"])
def test_03f_refusals_register_nothing(env, trivy, case):
    write(env, {"pom.xml": POM_COMPLETE})
    if case == "no-plan":
        vid = opened(env)
    elif case == "not-selected":
        vid = planned(
            env,
            [
                tcheck(
                    methods=(READ_METHOD, dict(TRIVY_METHOD, required=False)), selected=("semantic-review",)
                )
            ],
        )
    elif case == "not-planned":
        vid = planned(
            env, [tcheck(methods=(READ_METHOD,), selected=("semantic-review",), minimum=("reading",))]
        )
    elif case == "reading-kind":
        # a `trivy` method of another kind is refused when planned (Adapter names are runtime only)
        vid = opened(env)
        doc = {
            "schema": "ai-secure-code-toolkit/guard-plan/v1",
            "checks": [
                tcheck(
                    methods=({"name": "trivy", "kind": "reading", "required": True},), minimum=("reading",)
                )
            ],
            "not_applicable": [{"rule": "CWE/4.14/CWE-89", "reason": "n/a"}],
        }
        refused = guard.record_plan(str(env["project"]), vid, req(env, doc))
        assert refused.problems[0].code == "PLAN_INVALID" and "trivy" in refused.problems[0].message
        assert state(env, vid)["plan"] is None and calls(trivy) == []
        return
    else:
        vid = planned(env, [tcheck()])
        guard.conclude(str(env["project"]), vid)
    before = state(env, vid)
    result = scan(env, vid, [trc()])
    code = {
        "concluded": "RUN_FINISHED",
        "no-plan": "PLAN_REQUIRED",
        "not-selected": "METHOD_NOT_SELECTED",
        "not-planned": "METHOD_NOT_PLANNED",
    }[case]
    assert not result.ok and result.problems[0].code == code, result.to_text()
    assert result.next_steps
    nothing_recorded(env, vid, before)
    assert calls(trivy) == []


def test_03g_archive_size_bound_and_staging(env, trivy, monkeypatch):
    write(
        env,
        {
            "dist/big.tar": image(os_info=ALPINE),
            "dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS),
            "app/requirements.txt": "requests==2.31.0\n" + "#" * 9000 + "\n",
        },
    )
    vid = planned(
        env,
        [
            tcheck(obj=("dist/big.tar",)),
            tcheck("C2", obj=("dist/app.tar",)),
            tcheck("C3", obj=("app/requirements.txt",)),
        ],
        targets=("dist/big.tar", "dist/app.tar", "app/requirements.txt"),
    )
    provisioned(env, vid)
    with open(env["project"] / "dist/big.tar", "r+b") as handle:
        handle.truncate(8 * 1024**3 + 1)  # sparse: no disk use
    before = state(env, vid)
    refused = scan(env, vid, [trc(mode="image_archive", targets=("dist/big.tar",))])
    assert refused.problems[0].code == "IMAGE_ARCHIVE_TOO_LARGE"
    assert (
        "8589934593" in refused.problems[0].message.replace(",", "")
        and "8 GiB" in refused.problems[0].message
    )
    nothing_recorded(env, vid, before)
    assert toolrun.MAX_STAGE_BYTES == 512 * 1024 * 1024  # the non-archive bound is unchanged
    monkeypatch.setattr(toolrun, "MAX_STAGE_BYTES", 4096)
    archive = scan(env, vid, [trc("C2", mode="image_archive", targets=("dist/app.tar",))])
    assert archive.ok and tev(env, vid, "C2")["method_status"] == "ok", gaps_text(archive, env, vid, "C2")
    files = scan(env, vid, [trc("C3", targets=("app/requirements.txt",))])
    assert files.data["status"] == "precheck_failed" and files.problems[0].code == "STAGE_TOO_LARGE"


@pytest.mark.parametrize(
    ("data", "violation"),
    [
        (
            trivytar.archive(
                trivytar.member("a", b"x"), trivytar.member("l", typeflag=b"2", linkname="/etc/passwd")
            ),
            "link",
        ),
        (trivytar.archive(trivytar.member("../evil", b"x")), ".."),
        (trivytar.archive(trivytar.member("/abs", b"x")), "absolute"),
        (trivytar.docker_save(extra=(trivytar.member("manifest.json", b"[]"),)), "duplicate"),
        (
            trivytar.docker_save(manifest_override=[{"Config": "missing.json", "Layers": ["x/layer.tar"]}]),
            "Config",
        ),
        (b"\x1f\x8b\x08\x00" + b"\0" * 2048, "compressed"),
        (trivytar.docker_save()[:1536], "truncated"),
        (trivytar.oci_only(), "docker save"),
    ],
)
def test_03h_archive_structure_refusals(env, trivy, data, violation):
    write(env, {"dist/app.tar": data})
    vid = planned(env, [tcheck(obj=("dist/app.tar",))], targets=("dist/app.tar",))
    before = state(env, vid)
    result = scan(env, vid, [trc(mode="image_archive", targets=("dist/app.tar",))])
    assert result.problems[0].code == "IMAGE_ARCHIVE_INVALID", result.to_text()
    assert violation.lower() in result.problems[0].message.lower()
    nothing_recorded(env, vid, before)
    assert scans(trivy) == []


def test_03h_docker25_archive_with_oci_members_accepted(env, trivy):
    write(env, {"dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS, docker25=True)})
    vid = planned(env, [tcheck(obj=("dist/app.tar",))], targets=("dist/app.tar",))
    provisioned(env, vid)
    result = scan(env, vid, [trc(mode="image_archive", targets=("dist/app.tar",))])
    assert result.ok and tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)
    info = run_entry(env, vid)["archives"]["dist/app.tar"]
    assert info["manifest_entries"] == 1 and info["layers"] == 1


def test_03i_archive_only_as_explicit_file_target(env, trivy):
    write(env, {"images/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS), "images/notes.txt": "n\n"})
    vid = planned(env, [tcheck(obj=("images/app.tar",)), tcheck("C2", obj=("images",))], targets=("images",))
    provisioned(env, vid)
    before = state(env, vid)
    refused = scan(env, vid, [trc(mode="image_archive", targets=("images/app.tar",))])
    assert (
        refused.problems[0].code == "TOOL_REQUEST_INVALID"
        and "explicit" in refused.problems[0].message.lower()
    )
    nothing_recorded(env, vid, before)
    result = scan(env, vid, [trc("C2", ("secret",), targets=("images",))])
    assert result.ok, result.to_text()
    assert all(c["argv"][1] == "fs" and "--input" not in c["argv"] for c in scans(trivy))
    assert "images/app.tar" in gaps_text(result, env, vid, "C2")  # an ordinary (binary) file, not an image


# ================================================================== AC-002D-04 protected offline execution
def test_04a_staged_paths_disposable_dirs_project_config_ignored(env, trivy):
    configs = {
        "trivy.yaml": "severity: CRITICAL\n",
        ".trivyignore": "CVE-2013-7285\n",
        "trivy-secret.yaml": "disable-rules: [aws-access-key-id]\n",
    }
    write(
        env,
        {
            **configs,
            **{f"app/{k}": v for k, v in configs.items()},
            "app/pom.xml": POM_COMPLETE,
            "app/Dockerfile": DOCKERFILE,
            "app/conf/settings.env": "a=1\n",
        },
    )
    project = env["project"]
    vid = planned(env, [tcheck(obj=("app",))], targets=("app",))
    provisioned(env, vid)
    before = tree_hashes(project / "app", project / "README.md", *(project / k for k in configs))
    result = scan(env, vid, [trc(scanners=("vuln", "misconfig", "secret"), targets=("app",))])
    assert result.ok, result.to_text()
    stage_root = project / STAGE_ROOT
    for call in scans(trivy):
        argv = call["argv"]
        assert argv[0].startswith(str(stage_root)), argv[0]
        assert Path(call["cwd"]).resolve().is_relative_to(stage_root.resolve()) and call["cwd_listing"] == []
        assert call["loaded_project_config"] == []
        for flag in ("--config", "--ignorefile", "--secret-config"):
            assert flag_value(argv, flag) == [""], flag
        assert set(call["env"]) - MAC_ENV == MINIMAL_ENV
        assert Path(call["home"]).is_relative_to(stage_root) and Path(call["tmpdir"]).is_relative_to(
            stage_root
        )
        assert argv[-1].startswith(str(stage_root)) and flag_value(argv, "--cache-dir")[0].startswith(
            str(stage_root)
        )
        for path in call["resolved"].values():
            assert Path(path).is_relative_to((project / CACHE / "gen").resolve())
    assert not stage_root.exists() or not [p for p in stage_root.iterdir() if p.name.startswith("stage-")]
    run_dir = project / GUARD / vid
    assert not [p for p in run_dir.rglob("*") if p.name in ("pom.xml", "Dockerfile", "settings.env")]
    assert tree_hashes(project / "app", project / "README.md", *(project / k for k in configs)) == before
    for name in ALL:
        assert not (gen_dir(env, name) / "fanal").exists()


def test_04a_staging_replaced_during_run_not_deleted(env, trivy, monkeypatch):
    """The leaf is renamed away and a decoy put at its name before cleanup: the decoy is never deleted."""
    write(env, {"pom.xml": POM_COMPLETE, "Dockerfile": DOCKERFILE})
    vid = planned(env, [tcheck(), tcheck("C2", obj=("Dockerfile",))], targets=("pom.xml", "Dockerfile"))
    provisioned(env, vid)
    stage_root = env["project"] / STAGE_ROOT
    real = process.run
    moved = {}

    def swap(argv, *args, **kwargs):
        out = real(argv, *args, **kwargs)
        if not moved:
            (leaf,) = [p for p in stage_root.iterdir() if p.name.startswith("stage-")]
            moved["to"] = stage_root.parent / "moved-away"
            os.rename(leaf, moved["to"])
            write(env, {f"{STAGE_ROOT}/{leaf.name}/marker.txt": "decoy"})
            moved["decoy"] = leaf / "marker.txt"
        return out

    monkeypatch.setattr(process, "run", swap)
    result = scan(env, vid, [trc(), trc("C2", ("misconfig",), targets=("Dockerfile",))])
    assert result.ok, result.to_text()
    assert moved["decoy"].read_text() == "decoy"
    assert not [p for p in moved["to"].rglob("*") if p.is_file()]  # snapshots removed through the descriptor
    for cid in ("C1", "C2"):
        assert tev(env, vid, cid)["method_status"] == "failed"
        assert "staging location changed during the run" in gaps_text(result, env, vid, cid)
    assert "STAGING_LEFTOVER" in [p.code for p in result.problems]


def test_04b_target_changed_since_open(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE, "requirements.txt": "requests==2.31.0\n"})
    vid = planned(
        env, [tcheck(), tcheck("C2", obj=("requirements.txt",))], targets=("pom.xml", "requirements.txt")
    )
    provisioned(env, vid)
    (env["project"] / "pom.xml").write_text(POM_COMPLETE + "<!-- changed -->\n")
    result = scan(env, vid, [trc(), trc("C2", targets=("requirements.txt",))])
    assert result.ok
    assert (
        tev(env, vid)["method_status"] == "failed"
        and "changed since the verification opened" in tev(env, vid)["summary"]
    )
    assert tev(env, vid, "C2")["method_status"] == "ok"
    assert all("pom.xml" not in json.dumps(c["argv"]) for c in scans(trivy))


def test_04c_outdated_db_runs_offline_reports_age(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    set_cfg(
        trivy,
        metadata={
            "vulnerability_db": {"UpdatedAt": "2019-01-01T00:00:00Z", "NextUpdate": "2019-01-02T00:00:00Z"}
        },
    )
    provisioned(env, vid)
    result = scan(env, vid, [trc()])
    assert result.ok and tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)
    (call,) = scans(trivy)
    assert all(f in call["argv"] for f in OFFLINE) and call["network_attempts"] == []
    db = run_entry(env, vid)["components"]["vulnerability_db"]
    assert db["metadata"]["UpdatedAt"].startswith("2019-01-01") and db["age_seconds"] > 6 * 365 * 86400
    assert len(calls(trivy, "provision")) == 3 and "stale" not in json.dumps(state(env, vid)).lower()


@pytest.mark.parametrize("kind", ["adapter-deadline", "tool-deadline"])
def test_04d_timeouts(env, trivy, kind):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    set_cfg(trivy, mode="sleep" if kind == "adapter-deadline" else "tool-deadline")
    start = time.monotonic()
    result = scan(env, vid, [trc()], time_limit_seconds=3)
    assert result.ok and result.data["checks"]["C1"]["status"] == "timed_out", result.to_text()
    assert tev(env, vid)["method_status"] == "failed" and time.monotonic() - start < 60
    (call,) = scans(trivy)
    timeout = int(flag_value(call["argv"], "--timeout")[0].rstrip("s"))
    assert timeout >= 3  # the tool's own deadline is never shorter than the effective limit
    assert run_entry(env, vid)["rehash"]["vulnerability_db"] == "unchanged"
    assert process._group_gone(call["pgid"], 10)  # the tool and its child processes were stopped


def test_04e_cancel_scan_records_nothing(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    set_cfg(trivy, mode="sleep")
    thread, box = cancel_when_called(env, vid, trivy)
    result = scan(env, vid, [trc()], time_limit_seconds=60)
    thread.join(60)
    assert result.problems[0].code == "RUN_CANCELLED" and box["result"].ok
    assert state(env, vid).get("adapter_runs", []) == []
    assert not [e for e in state(env, vid)["evidence"] if e["method"] == "trivy"]
    evidence = env["project"] / GUARD / vid / "evidence"
    assert not evidence.exists() or not [p for p in evidence.iterdir() if p.name.startswith("trivy-")]
    stage_root = env["project"] / STAGE_ROOT
    assert not stage_root.exists() or not [p for p in stage_root.iterdir() if p.name.startswith("stage-")]


# ======================================================================= AC-002D-05 accounting and results
@pytest.mark.parametrize(
    "case",
    [
        "secret-skip-rules",
        "unrecognized-manifest",
        "misconfig-debug-only",
        "skipped-packages",
        "java-archive-fs",
        "image-os",
        "image-no-os",
    ],
)
def test_05a_accounting_per_scanner(env, trivy, case):
    files = {
        "app/src/settings.env": "a=1\n",
        "app/tests/fixture.env": "a=1\n",
        "app/README.md": "# r\n",
        "app/blob.bin": b"\0\1\2binary",
        "build.gradle": "dependencies {}\n",
        "pom.xml": POM,
        "Dockerfile": DOCKERFILE,
        "lib/wrapper.jar": b"PK\3\4jar",
        "dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS),
        "dist/hello.tar": image(os_info=None),
    }
    write(env, files)
    spec = {
        "secret-skip-rules": (("app",), trc(scanners=("secret",), targets=("app",))),
        "unrecognized-manifest": (("build.gradle",), trc(targets=("build.gradle",))),
        "misconfig-debug-only": (("Dockerfile",), trc(scanners=("misconfig",), targets=("Dockerfile",))),
        "skipped-packages": (("pom.xml",), trc()),
        "java-archive-fs": (("lib/wrapper.jar",), trc(targets=("lib/wrapper.jar",))),
        "image-os": (("dist/app.tar",), trc(mode="image_archive", targets=("dist/app.tar",))),
        "image-no-os": (("dist/hello.tar",), trc(mode="image_archive", targets=("dist/hello.tar",))),
    }[case]
    obj, request = spec
    vid = planned(env, [tcheck(obj=obj)], targets=obj)
    provisioned(env, vid)
    if case == "misconfig-debug-only":
        set_cfg(trivy, mode="debug-only-config")
    result = scan(env, vid, [request])
    assert result.ok, result.to_text()
    acc = accounting(run_entry(env, vid)["checks"]["C1"], request["scanners"][0])
    text = gaps_text(result, env, vid)
    method = tev(env, vid)["method_status"]
    if case == "secret-skip-rules":
        assert acc["scanner"] == "secret" and "app/src/settings.env" in acc["analysed"]
        unaccounted = {u["path"] if isinstance(u, dict) else u for u in acc["unaccounted"]}
        assert {"app/tests/fixture.env", "app/README.md", "app/blob.bin"} <= unaccounted
        assert "not reported as scanned by the secret scanner" in text and method == "failed"
    elif case == "unrecognized-manifest":
        assert "not recognized as a dependency manifest or lockfile" in text and method == "failed"
    elif case == "misconfig-debug-only":
        assert "reported only in the debug log; no per-file result" in text and method == "failed"
        assert acc["diagnostics"]
    elif case == "skipped-packages":
        assert "pom.xml" in acc["analysed"] and acc["packages"]["pom.xml"] == 1
        assert acc["skipped_packages"][0]["name"] == "com.fasterxml.jackson.core:jackson-databind"
        assert "com.fasterxml.jackson.core:jackson-databind" in text and method == "failed"
        assert "transitive dependencies not listed in the manifest are not analysed offline" in text
    elif case == "java-archive-fs":
        assert "Java archives are analysed only in image_archive mode" in text and method == "failed"
    elif case == "image-os":
        assert acc["image"]["archive"] == "dist/app.tar" and "alpine" in json.dumps(acc["image"]["os"])
        assert "3.21.6" in json.dumps(acc["image"]["os"])
        assert "alpine" in acc["image"]["package_types"] and method == "ok", text
    else:
        assert "OS not detected" in text and method == "failed"


def test_05b_complete_ok_gap_fails_only_that_check(env, trivy):
    write(
        env, {"requirements.txt": "requests==2.31.0\n", "app/src/a.env": "a=1\n", "app/tests/b.env": "b=1\n"}
    )
    vid = planned(
        env,
        [tcheck(obj=("requirements.txt",)), tcheck("C2", obj=("app",))],
        targets=("requirements.txt", "app"),
    )
    provisioned(env, vid)
    result = scan(env, vid, [trc(targets=("requirements.txt",)), trc("C2", ("secret",), targets=("app",))])
    assert result.ok
    assert tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)
    c2 = tev(env, vid, "C2")
    assert (
        c2["method_status"] == "failed" and "app/tests/b.env" in c2["summary"] and "secret" in c2["summary"]
    )
    assert len([e for e in state(env, vid)["evidence"] if e["method"] == "trivy"]) == 2


def test_05c_secret_plaintext_never_stored(env, trivy, monkeypatch):
    key, token = fake_aws_key(), fake_github_token()
    marker = "context-marker-" + hashlib.sha256(key.encode()).hexdigest()[:12]
    write(env, {"app/settings.env": f"region = eu-west-1 {marker}\naws_key = {key}\ngh = {token}\nend = 1\n"})
    vid = planned(env, [tcheck(obj=("app",))], targets=("app",))
    provisioned(env, vid)
    real_run = process.run
    seen_paths = []

    def spy(argv, cwd, env_, deadline, stdout_path=None, *args, **kwargs):
        seen_paths.append(stdout_path)
        return real_run(argv, cwd, env_, deadline, stdout_path, *args, **kwargs)

    monkeypatch.setattr(process, "run", spy)
    result = scan(env, vid, [trc(scanners=("secret",), targets=("app",))])
    assert result.ok, result.to_text()
    assert seen_paths and all(p is None for p in seen_paths)  # stdout only in memory, never a file
    findings = [f for f in state(env, vid)["findings"] if f["source"] == "trivy"]
    aws = next(f for f in findings if f["tool"]["rule_id"] == "aws-access-key-id")
    assert aws["tool"]["secret"] == {"representation": "masked", "length": len(key)}
    assert aws["description"] == f"AWS secret (value masked, {len(key)} characters)"
    assert aws["location"] == {"path": "app/settings.env", "line": 2} and aws["tool"]["category"] == "AWS"
    conclude_report(env, vid)
    stored = private_tree(env)
    for value in (key, token, marker):
        assert value not in result.to_text() and value not in json.dumps(result.data)
        for path, data in stored.items():
            assert value.encode() not in data, (value, path)


def test_05d_findings_normalized_and_attributed(env, trivy):
    pom = POM_COMPLETE.replace(
        "</dependencies>",
        "<dependency><groupId>org.example</groupId><artifactId>rejected</artifactId><version>1.0</version>"
        "</dependency></dependencies>",
    )
    write(
        env,
        {
            "app/pom.xml": pom,
            "app/requirements.txt": "django==2.0\n",
            "Dockerfile": DOCKERFILE,
            "dist/app.tar": image(os_info=ALPINE, packages=ALPINE_PKGS),
        },
    )
    checks = [
        tcheck(obj=("app/pom.xml", "app/requirements.txt")),
        tcheck("C2", obj=("Dockerfile",)),
        tcheck("C3", obj=("dist/app.tar",)),
    ]
    vid = planned(env, checks, targets=("app", "Dockerfile", "dist/app.tar"))
    provisioned(env, vid)
    requests = [
        trc(targets=("app/pom.xml", "app/requirements.txt")),
        trc("C2", ("misconfig",), targets=("Dockerfile",)),
        trc("C3", mode="image_archive", targets=("dist/app.tar",)),
    ]
    assert scan(env, vid, requests).ok
    findings = [f for f in state(env, vid)["findings"] if f["source"] == "trivy"]
    by_rule = {f["tool"]["rule_id"]: f for f in findings}
    x = by_rule["CVE-2013-7285"]
    assert x["id"].startswith("trivy-1-f") and x["check"] == "C1" and x["rule"] == R1
    assert x["title"].startswith("CVE-2013-7285: ") and x["severity"] == "critical" and x["cwe"] == "CWE-78"
    assert x["location"]["path"] == "app/pom.xml" and isinstance(x["location"]["line"], int)
    assert x["tool"]["scanner"] == "vuln" and x["tool"]["tool_severity"] == "CRITICAL"
    assert x["tool"]["package"] == {
        "name": "com.thoughtworks.xstream:xstream",
        "installed": "1.4.5",
        "fixed": "1.4.7, 1.4.11",
    }
    assert x["evidence"] == [tev(env, vid)["id"]]
    assert (
        by_rule["CVE-2099-0001"]["severity"] == "unknown"
        and by_rule["CVE-2099-0002"]["severity"] == "unknown"
    )
    assert by_rule["CVE-2019-6975"]["location"]["path"] == "app/requirements.txt"
    ds = by_rule["DS-0002"]
    assert ds["check"] == "C2" and ds["title"].startswith("DS-0002: ") and ds["severity"] == "high"
    assert ds["location"]["path"] == "Dockerfile" and ds["tool"]["scanner"] == "misconfig"
    img = by_rule["CVE-2026-31789"]
    assert img["check"] == "C3" and img["location"]["path"] == "dist/app.tar"
    assert img["tool"]["layer"] == "sha256:" + "11" * 32 and STAGE_ROOT not in json.dumps(img)
    # determinism (NFR-002D-3): the same inputs normalize to the same findings
    assert scan(env, vid, requests).ok
    runs = {}
    for f in [f for f in state(env, vid)["findings"] if f["source"] == "trivy"]:
        key = f["tool"]["run"]
        clean = {k: v for k, v in f.items() if k not in ("id", "evidence")}
        clean["tool"] = {k: v for k, v in f["tool"].items() if k != "run"}
        runs.setdefault(key, []).append(clean)
    first, second = runs.values()
    assert first == second


def test_05e_evidence_provenance_and_shared_output(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE, "Dockerfile": DOCKERFILE})
    vid = planned(env, [tcheck(), tcheck("C2", obj=("Dockerfile",))], targets=("pom.xml", "Dockerfile"))
    provisioned(env, vid)
    assert scan(env, vid, [trc(), trc("C2", ("misconfig",), targets=("Dockerfile",))]).ok
    e1, e2 = tev(env, vid), tev(env, vid, "C2")
    assert e1["id"] == "trivy-1-1" and e2["id"] == "trivy-1-2" and e1["kind"] == "runtime"
    assert e1["stored"] == e2["stored"] == "evidence/trivy-1-output.json" and e1["adapter_run"] == 1
    for word in ("0.76.1", "vuln", "filesystem", "completed"):
        assert word in e1["summary"], word
    entry = run_entry(env, vid)
    record = json.loads((env["project"] / RECORD).read_text())
    assert entry["version"] == "0.76.1" and entry["binary_digest"] == record["digest"]
    assert entry["platform_validated"] is False and entry["asset"] == "fake-asset"
    targets = {t["path"]: t["digest"] for t in state(env, vid)["artifact"]["targets"]}
    assert entry["staged_digests"] == targets
    assert set(entry["components"]) >= {"vulnerability_db", "checks_bundle"}
    c1 = entry["checks"]["C1"]
    assert c1["scanners"] == ["vuln"] and c1["mode"] == "filesystem" and c1["status"] == "completed"
    assert c1["counts"] == {"scanned": 1, "skipped": 0, "unaccounted": 0}
    assert c1["processes"][0]["scanner"] == "vuln" and c1["processes"][0]["exit"] == 0
    assert "vulnerability_db" in c1["components_used"]
    run_dir = env["project"] / GUARD / vid
    output = (run_dir / "evidence/trivy-1-output.json").read_text()
    assert '"Match"' not in output and '"Code"' not in output
    manifest = run_dir / entry["manifest"]["path"]
    assert entry["manifest"]["digest"] == "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("mode", "status"),
    [
        ("exit1", "failed"),
        ("garbage", "failed"),
        ("empty", "failed"),
        ("huge", "failed"),
        ("warn", "completed_with_errors"),
        ("unanchored-log", None),
    ],
)
def test_05f_tool_errors_and_degrading_messages(env, trivy, mode, status):
    write(env, {"pom.xml": POM if mode == "warn" else POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    if mode != "warn":
        set_cfg(trivy, mode=mode)
    result = scan(env, vid, [trc()])
    assert result.ok, result.to_text()
    text = gaps_text(result, env, vid)
    assert tev(env, vid)["method_status"] == "failed"
    if status:
        assert result.data["checks"]["C1"]["status"] == status
    if mode == "warn":
        assert "Dependency version cannot be determined" in text
        assert any(
            f["tool"]["rule_id"] == "CVE-2013-7285" for f in state(env, vid)["findings"]
        )  # partial kept
    if mode == "unanchored-log":
        assert "tool log format not recognized for Trivy v0.76.1" in text
    if mode == "exit1":
        assert "unexpected failure" in text


def test_05g_clean_run_and_failed_method_rules(env, trivy):
    write(env, {"requirements.txt": "requests==2.31.0\n", "pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck(obj=("requirements.txt",))], targets=("requirements.txt",))
    provisioned(env, vid)
    assert scan(env, vid, [trc(targets=("requirements.txt",))]).ok
    assert tev(env, vid)["method_status"] == "ok" and state(env, vid)["findings"] == []
    out = guard.conclude(str(env["project"]), vid)
    assert out.data["verdict"] != "pass"  # zero findings alone never make Pass
    # a failed auxiliary trivy method may be substituted; a failed required one never satisfies the check
    aux = dict(TRIVY_METHOD, required=False)
    for required in (False, True):
        methods = (READ_METHOD, aux) if not required else (dict(READ_METHOD, required=False), TRIVY_METHOD)
        vid = planned(
            env,
            [tcheck(methods=methods, selected=("semantic-review", "trivy"), minimum=("reading", "runtime"))],
        )
        provisioned(env, vid)
        set_cfg(trivy, mode="exit1")
        assert scan(env, vid, [trc()]).ok
        set_cfg(trivy, mode="normal")
        rec = {
            "schema": "ai-secure-code-toolkit/guard-record/v1",
            "evidence": [
                {
                    "id": "E1",
                    "kind": "reading",
                    "method": "semantic-review",
                    "method_status": "ok",
                    "checks": ["C1"],
                    "paths": ["pom.xml"],
                    "summary": "read",
                }
            ],
            "ledger": [{"check": "C1", "state": "met", "evidence": ["E1", "trivy-1-1"]}],
        }
        guard.record(str(env["project"]), vid, req(env, with_attempt(env, vid, rec)))
        guard.conclude(str(env["project"]), vid)
        res = json.loads((env["project"] / REPORTS / f"{vid}.json").read_text())
        row = next(r for r in res["ledger"] if r["check"] == "C1")
        if required:
            assert row["state"] != "met" and res["verdict"] != "pass"
        else:
            assert row["state"] == "met" and row["substitution"] == [{"method": "trivy", "status": "failed"}]


def test_05h_compose_unsupported_in_misconfig_text_in_secret(env, trivy):
    key = fake_aws_key()
    write(env, {"deploy/Dockerfile": DOCKERFILE, "deploy/docker-compose.yml": COMPOSE + f"# key {key}\n"})
    vid = planned(env, [tcheck(obj=("deploy",)), tcheck("C2", obj=("deploy",))], targets=("deploy",))
    provisioned(env, vid)
    result = scan(
        env,
        vid,
        [trc(scanners=("misconfig",), targets=("deploy",)), trc("C2", ("secret",), targets=("deploy",))],
    )
    assert result.ok, result.to_text()
    text = gaps_text(result, env, vid)
    assert tev(env, vid)["method_status"] == "failed"
    assert "configuration type not supported by Trivy v0.76.1" in text and "deploy/docker-compose.yml" in text
    assert "use another method such as Guard semantic review" in text
    misconf = accounting(run_entry(env, vid)["checks"]["C1"], "misconfig")
    assert "deploy/Dockerfile" in misconf["analysed"]
    secret = accounting(run_entry(env, vid)["checks"]["C2"], "secret")
    assert "deploy/docker-compose.yml" in secret["analysed"]  # an ordinary text file for the secret scanner
    found = [f for f in state(env, vid)["findings"] if f["check"] == "C2"]
    assert [f["location"]["path"] for f in found] == ["deploy/docker-compose.yml"]


@pytest.mark.parametrize("case", ["missing", "invalid-mark", "fallback-line"])
def test_05i_embedded_checks_fallback_is_a_gap(env, trivy, case):
    write(env, {"Dockerfile": DOCKERFILE})
    vid = planned(env, [tcheck(obj=("Dockerfile",))], targets=("Dockerfile",))
    provisioned(env, vid, ALL if case != "missing" else ("vulnerability_db", "java_db"))
    if case == "invalid-mark":
        tamper(gen_dir(env, "checks_bundle") / "policy" / "metadata.json")
    if case == "fallback-line":
        set_cfg(trivy, mode="fallback")
    result = scan(env, vid, [trc(scanners=("misconfig",), targets=("Dockerfile",))])
    assert result.ok, result.to_text()
    text = gaps_text(result, env, vid)
    assert tev(env, vid)["method_status"] == "failed"
    assert "checks bundle" in text.lower().replace("_", " ") and "provision" in text
    if case == "fallback-line":
        assert "checks bundle missing / embedded-checks fallback" in text
        assert accounting(run_entry(env, vid)["checks"]["C1"], "misconfig")["checks_source"] != "provisioned"
        assert any(f["tool"]["rule_id"] == "DS-0002" for f in state(env, vid)["findings"])  # results kept
    else:
        assert scans(trivy) == []  # the component pre-check stops the misconfig scan


# ======================================================================= AC-002D-06 Guard integration
def test_06a_request_only_for_selected_trivy_runtime_method(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(
        env,
        [tcheck(methods=(READ_METHOD, dict(TRIVY_METHOD, required=False)), selected=("semantic-review",))],
    )
    provisioned(env, vid)
    assert scan(env, vid, [trc()]).problems[0].code == "METHOD_NOT_SELECTED"
    change = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "method_changes": [
            {
                "check": "C1",
                "change": "supplement",
                "method": {"name": "trivy", "kind": "runtime"},
                "reason": "dependency manifest needs a vulnerability database check",
            }
        ],
    }
    assert guard.record(str(env["project"]), vid, req(env, change)).ok
    result = scan(env, vid, [trc()])
    assert result.ok, result.to_text()
    c1 = run_entry(env, vid)["checks"]["C1"]
    assert c1["scanners"] == ["vuln"] and c1["mode"] == "filesystem"
    assert run_entry(env, vid)["time_limit"] == 120


def test_06b_trivy_findings_follow_review_rules_agent_cannot_alter(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    project = str(env["project"])
    for bad in (
        {
            "evidence": [
                {
                    "id": "E1",
                    "kind": "runtime",
                    "method": "Trivy",
                    "method_status": "ok",
                    "checks": ["C1"],
                    "paths": ["pom.xml"],
                    "summary": "ran it",
                }
            ]
        },
        {
            "evidence": [
                {
                    "id": "trivy-1-1",
                    "kind": "runtime",
                    "method": "trivy",
                    "method_status": "ok",
                    "checks": ["C1"],
                    "paths": ["pom.xml"],
                    "summary": "x",
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "trivy-9-f1",
                    "rule": R1,
                    "location": {"path": "pom.xml"},
                    "title": "t",
                    "source": "semantic",
                    "severity": "low",
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "F1",
                    "rule": R1,
                    "location": {"path": "pom.xml"},
                    "title": "t",
                    "source": "trivy",
                    "severity": "low",
                }
            ]
        },
    ):
        result = guard.record(
            project, vid, req(env, {"schema": "ai-secure-code-toolkit/guard-record/v1", **bad})
        )
        assert result.problems and result.problems[0].code == "RECORD_INVALID", bad
    provisioned(env, vid)
    assert scan(env, vid, [trc()]).ok
    fids = [f["id"] for f in state(env, vid)["findings"] if f["source"] == "trivy"]
    assert fids
    ledger = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "ledger": [{"check": "C1", "state": "not_met", "evidence": ["trivy-1-1"], "findings": fids}],
    }
    assert guard.record(project, vid, req(env, ledger)).ok
    out = guard.conclude(project, vid)
    assert out.data["verdict"] == "cannot_confirm_pass"
    assert "FINDING_UNCONFIRMED" in [r["code"] for r in out.data["reasons"]]


def test_06c_method_choice_and_changes_reported(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck(methods=(READ_METHOD,), selected=("semantic-review",), minimum=("reading",))])
    change = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "method_changes": [
            {
                "check": "C1",
                "change": "supplement",
                "method": {"name": "trivy", "kind": "runtime"},
                "reason": "add dependency vulnerability evidence",
            }
        ],
    }
    assert guard.record(str(env["project"]), vid, req(env, change)).ok
    provisioned(env, vid)
    assert scan(env, vid, [trc()]).ok
    text = conclude_report(env, vid)
    assert "## Method Choices and Changes" in text and "add dependency vulnerability evidence" in text
    assert "Trivy is the cheapest sufficient method" in text and "semantic-review" in text
    assert "## Adapter Runs" in text and "0.76.1" in text and "Scanners" in text and "Mode" in text


def test_report_trivy_sections_and_limits(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid)
    assert scan(env, vid, [trc()]).ok
    text = conclude_report(env, vid)
    assert "## Trivy Component State" in text and "mirror.gcr.io/aquasec/trivy-db:2" in text
    assert "No staleness threshold is applied" in text
    assert "the digest-verified binary is trusted not to write to them" in text
    assert "## Tool Provisioning" in text
    limits = " ".join(engine.LIMITS)
    assert "Strix is not available yet" in limits and "Trivy and Strix are not available yet" not in limits
    assert "Trivy runs on Linux x86-64/arm64 only, scans offline" in limits


# ======================================================================= AC-002D-08 status
@pytest.mark.parametrize("scenario", ["registered-present", "unregistered", "macos", "missing", "unreadable"])
def test_08a_status_reports_trivy_without_executing(env, trivy, monkeypatch, scenario):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    if scenario != "missing":
        provisioned(env, vid)
    if scenario == "unregistered":
        (env["project"] / RECORD).unlink()
    if scenario == "unreadable":
        tamper(gen_dir(env, "checks_bundle") / "policy" / "metadata.json")
    if scenario == "macos":
        set_host(monkeypatch, "macos", "aarch64")
    invoked = len(calls(trivy))
    before = tree_hashes(env["project"] / ".x-ipe")
    t = trivy_status(env)
    assert tree_hashes(env["project"] / ".x-ipe") == before and len(calls(trivy)) == invoked
    assert t["state"] == "provided" and set(t["components"]) == set(ALL)
    if scenario == "unregistered":
        assert t["registered"] is False and "tools register --tool trivy" in t["next_step"]
    else:
        assert t["registered"] is True and t["version"] == "0.76.1" and t["platform_validated"] is False
    if scenario == "macos":
        assert (
            t["execution"] == "not supported on this platform in this version" and PLATFORM_GAP in t["check"]
        )
    elif scenario != "unregistered":
        assert t["execution"] == "supported" and t["check"] == "ok"
    comps = t["components"]
    if scenario == "missing":
        for name in ALL:
            assert (
                comps[name]["state"] == "missing"
                and "tools provision --tool trivy" in comps[name]["next_step"]
            )
        return
    db, bundle = comps["vulnerability_db"], comps["checks_bundle"]
    assert db["state"] == "present" and set(db["metadata"]) >= {
        "Version",
        "UpdatedAt",
        "NextUpdate",
        "DownloadedAt",
    }
    assert (
        isinstance(db["age_seconds"], int)
        and db["age"]
        and db["repository"] == "mirror.gcr.io/aquasec/trivy-db"
    )
    if scenario == "unreadable":
        assert bundle["state"] == "unreadable" and bundle["reason"] and bundle["next_step"]
    else:
        assert bundle["state"] == "present" and set(bundle["metadata"]) >= {
            "MajorVersion",
            "Digest",
            "DownloadedAt",
        }
        assert bundle["source"] == "mirror.gcr.io/aquasec/trivy-checks:2" and "age_seconds" not in bundle
    assert t["recovery_pending"] is False


def test_08c_status_reports_component_disk_sizes(env, trivy):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    provisioned(env, vid, ("vulnerability_db", "checks_bundle"))
    tamper(gen_dir(env, "checks_bundle") / "policy" / "metadata.json")
    invoked = len(calls(trivy))
    t = trivy_status(env)
    total = 0
    for name in ("vulnerability_db", "checks_bundle"):
        base = gen_dir(env, name)
        expected = sum(p.lstat().st_blocks * 512 for p in [base, *base.rglob("*")])
        expected_below = expected - base.lstat().st_blocks * 512  # with or without the generation folder
        assert t["components"][name]["disk_bytes"] in (expected, expected_below) and expected > 0
        total += t["components"][name]["disk_bytes"]
    assert t["components"]["checks_bundle"]["state"] == "unreadable"
    assert "disk_bytes" not in t["components"]["java_db"] or not t["components"]["java_db"]["disk_bytes"]
    assert t["cache_disk_bytes_total"] == total and len(calls(trivy)) == invoked
