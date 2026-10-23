"""Self-check of the Trivy test double against the recorded v0.76.1 observations (no toolkit code involved).

These tests pass before the Adapter exists: they prove that the RED failures of the FEATURE-002-D suite come
from missing toolkit behaviour, not from the fixtures.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures" / "trivy"
_spec = importlib.util.spec_from_file_location("trivytar", HERE / "trivytar.py")
tt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tt)
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX executables")
OFFLINE = [
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
    "--offline-scan",
    "--skip-version-check",
    "--disable-telemetry",
]


@pytest.fixture
def fake(tmp_path):
    config = tmp_path / "config.json"
    binary = tmp_path / "bin" / "trivy"
    binary.parent.mkdir()
    binary.write_text(
        f"#!{sys.executable} -B\n"
        + (HERE / "fake_trivy.py")
        .read_text()
        .replace("__CONFIG__", str(config))
        .replace("__FIXTURES__", str(FIXTURES))
    )
    binary.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()

    def run(*args, cfg=None):
        if cfg is not None:
            config.write_text(json.dumps(cfg))
        out = subprocess.run(
            [str(binary), *args],
            cwd=work,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": os.defpath, "HOME": str(tmp_path)},
        )
        return out

    return {"run": run, "tmp": tmp_path, "log": tmp_path / "invocations.jsonl"}


def provision(fake, component, cache):
    if component == "checks_bundle":
        empty = fake["tmp"] / "empty"
        empty.mkdir(exist_ok=True)
        return fake["run"](
            "fs",
            "--scanners",
            "misconfig",
            "--checks-bundle-repository",
            "mirror.gcr.io/aquasec/trivy-checks:2",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--skip-version-check",
            "--disable-telemetry",
            "--no-progress",
            "--format",
            "json",
            "--cache-dir",
            str(cache),
            "--timeout",
            "60s",
            str(empty),
        )
    flag = "--download-db-only" if component == "vulnerability_db" else "--download-java-db-only"
    repo = "--db-repository" if component == "vulnerability_db" else "--java-db-repository"
    return fake["run"](
        "image",
        flag,
        repo,
        "x:1",
        "--skip-version-check",
        "--disable-telemetry",
        "--no-progress",
        "--cache-dir",
        str(cache),
        "--timeout",
        "60s",
    )


def test_fake_reproduces_recorded_component_errors_and_fallback(fake, tmp_path):
    cache, project = tmp_path / "cache", tmp_path / "p"
    project.mkdir()
    (project / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>a</groupId><artifactId>b"
        "</artifactId><version>1</version></dependency></dependencies></project>"
    )
    (project / "Dockerfile").write_text("FROM python:latest\n")
    out = fake["run"](
        "fs", "--scanners", "vuln", *OFFLINE, "--format", "json", "--cache-dir", str(cache), str(project)
    )
    assert out.returncode == 1 and out.stdout == "" and "cannot be specified on the first run" in out.stderr
    out = fake["run"](
        "fs", "--scanners", "misconfig", *OFFLINE, "--format", "json", "--cache-dir", str(cache), str(project)
    )
    assert out.returncode == 0 and "Falling back to embedded checks" in out.stderr
    assert json.loads(out.stdout)["Results"][0]["MisconfSummary"]["Failures"] >= 1
    for component in ("vulnerability_db", "java_db", "checks_bundle"):
        assert provision(fake, component, cache).returncode == 0
    meta = json.loads((cache / "db" / "metadata.json").read_text())
    recorded = json.loads((FIXTURES / "component-metadata.json").read_text())["vulnerability_db"]
    assert meta["Version"] == recorded["Version"] and meta["UpdatedAt"] == recorded["UpdatedAt"]
    assert sorted(p.name for p in cache.iterdir()) == ["db", "java-db", "policy"]
    out = fake["run"](
        "fs",
        "--scanners",
        "vuln,misconfig",
        *OFFLINE,
        "--format",
        "json",
        "--cache-dir",
        str(cache),
        str(project),
    )
    assert out.returncode == 0 and "Falling back" not in out.stderr
    (cache / "db" / "trivy.db").write_bytes(b"CORRUPT")
    out = fake["run"](
        "fs", "--scanners", "vuln", *OFFLINE, "--format", "json", "--cache-dir", str(cache), str(project)
    )
    assert out.returncode == 1 and "failed to open db: invalid database" in out.stderr


def test_fake_secret_masking_skip_rules_and_unknown_flags(fake, tmp_path):
    key = "AKIA" + "X" * 16
    project = tmp_path / "p"
    (project / "src").mkdir(parents=True)
    (project / "tests").mkdir()
    (project / "src" / "a.env").write_text(f"before\nkey = {key}\nafter\n")
    (project / "tests" / "b.env").write_text(f"key = {key}\n")
    (project / "README.md").write_text(f"{key}\n")
    out = fake["run"]("fs", "--scanners", "secret", *OFFLINE, "--format", "json", "--debug", str(project))
    assert out.returncode == 0 and key not in out.stderr
    (result,) = json.loads(out.stdout)["Results"]
    secret = result["Secrets"][0]
    assert (
        result["Target"] == "src/a.env"
        and secret["Match"] == "key = " + "*" * len(key)
        and key not in out.stdout
    )
    assert [line["Content"] for line in secret["Code"]["Lines"]][0] == "before"  # context in clear (recorded)
    assert (
        'file_path="src/a.env"' in out.stderr
        and "tests/b.env" not in out.stderr
        and "README.md" not in out.stderr
    )
    bad = fake["run"]("fs", "--bogus", str(project))
    assert bad.returncode == 1 and "Usage" in bad.stdout and "FATAL" in bad.stderr


def test_fake_image_archives_and_offline_flag_recording(fake, tmp_path):
    cache = tmp_path / "cache"
    for component in ("vulnerability_db", "java_db"):
        provision(fake, component, cache)
    alpine = tmp_path / "a.tar"
    alpine.write_bytes(
        tt.docker_save(
            os_info={"Family": "alpine", "Name": "3.21.6"},
            packages=[{"name": "musl", "version": "1", "vulns": [{"id": "CVE-1", "severity": "HIGH"}]}],
        )
    )
    out = fake["run"](
        "image",
        "--input",
        str(alpine),
        "--scanners",
        "vuln",
        *OFFLINE,
        "--format",
        "json",
        "--cache-backend",
        "memory",
        "--cache-dir",
        str(cache),
    )
    doc = json.loads(out.stdout)
    assert doc["Metadata"]["OS"] == {"Family": "alpine", "Name": "3.21.6"}
    assert doc["Results"][0]["Target"].endswith("(alpine 3.21.6)")
    hello = tmp_path / "h.tar"
    hello.write_bytes(tt.docker_save(docker25=True))
    out = fake["run"](
        "image",
        "--input",
        str(hello),
        "--scanners",
        "vuln",
        *OFFLINE,
        "--format",
        "json",
        "--debug",
        "--cache-backend",
        "memory",
        "--cache-dir",
        str(cache),
    )
    assert "Results" not in json.loads(out.stdout) and "OS is not detected." in out.stderr
    fake["run"]("fs", "--scanners", "secret", "--format", "json", str(tmp_path / "work"))
    last = json.loads(fake["log"].read_text().splitlines()[-1])
    assert set(last["network_attempts"]) == set(OFFLINE)


def test_trivytar_builds_readable_docker_save_archives(tmp_path):
    import tarfile

    for docker25 in (False, True):
        path = tmp_path / f"i{docker25}.tar"
        path.write_bytes(tt.docker_save(docker25=docker25))
        with tarfile.open(path) as tar:
            manifest = json.load(tar.extractfile("manifest.json"))
            names = tar.getnames()
        assert manifest[0]["Config"] in names and manifest[0]["Layers"][0] in names
        assert ("oci-layout" in names) is docker25
