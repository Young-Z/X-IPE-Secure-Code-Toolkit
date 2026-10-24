"""Real-runtime conformance and acceptance (AC-002F-04l, 11b; M5 P-13b; DAO-014 binding 3).

Runs only with SECURE_CODE_HELPER_REAL=1 and an image already present locally (checked read-only with
`image inspect`; never pulled). Otherwise every test is skipped and reported "not executed (no local
runtime/image)". Containers use `--network none`; nothing is downloaded.
"""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest
from helperhelp import (  # noqa: F401 - fixture reuse
    RULE,
    Flow,
    audited_child_header,
    env,
    helper_run,
    henv,
    mod,
    state_of,
)

IMAGE = os.environ.get("SECURE_CODE_HELPER_IMAGE", "python:3.12-slim")


def _local_image() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        out = subprocess.run(
            [docker, "image", "inspect", IMAGE], capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0


# The design's `real_runtime` marker is expressed as this module-level skip condition (registering a new
# marker would need a change of the delivered conftest.py).
pytestmark = pytest.mark.skipif(
    os.environ.get("SECURE_CODE_HELPER_REAL") != "1" or not _local_image(),
    reason="not executed (no local runtime/image): set SECURE_CODE_HELPER_REAL=1 with a local image",
)


@pytest.fixture
def real(henv, monkeypatch):  # noqa: F811
    """Registration through the Maintainer command on the real runtime (DAO-005: the public `GPG_KEY`
    fingerprint of the official images is no longer refused; no seeded record)."""
    real_cli = os.path.realpath(shutil.which("docker"))
    folder = henv["tmp"] / "realcli"
    folder.mkdir()
    wrapper = folder / "docker"  # joins the suite's write audit, then becomes the real CLI (exec)
    exec_line = f"import os, sys\nos.execv({real_cli!r}, [{real_cli!r}] + sys.argv[1:])\n"
    wrapper.write_text(f"#!{sys.executable}\n{audited_child_header()}{exec_line}")
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.defpath}")
    out = mod("registry").register_image(str(henv["project"]), IMAGE, trust_paths=henv["paths"])
    assert out.ok, out.to_text()
    print(json.dumps({"registered": out.data["image"], "env_labels": out.data["env_labels"]}))
    return henv


CACHE: dict = {}


def _conformance(env, *, cached=True):
    if cached and "probes" in CACHE:
        return CACHE["probes"]
    out = mod("conformance").run(str(env["project"]), env["paths"])
    assert out.ok, out.to_text()
    print(json.dumps(out.data["probes"], indent=1))
    CACHE["probes"] = out.data
    return out.data


def test_11b_suite_on_real_runtime(real):
    """Every probe runs on the real runtime and passes; the record binds the result and allows execution.
    P-01 proves "network disabled" per spec v1.3.3 (DAO-005): on Docker Desktop (LinuxKit) the kernel
    fallback tunnel devices exist but are down, address-less and route-less."""
    data = _conformance(real, cached=False)
    probes = {p["id"]: p for p in data["probes"]}
    failed = sorted(k for k, p in probes.items() if not p["pass"])
    assert failed == [] and data["passed"] is True, failed
    p01 = json.loads(probes["P-01"]["detail"])
    assert p01["connect"] not in ("connected", None) and p01["dns"] not in ("resolved", None)
    assert all(not int(flags, 16) & 1 for name, flags in p01["ifaces"].items() if name != "lo")
    assert p01["v4"] == p01["v6"] == p01["route4"] == p01["route6"] == []
    assert p01["CapEff"] == p01["CapBnd"] == "0000000000000000"
    p02 = json.loads(probes["P-02"]["detail"])
    assert p02["/dev/shm/x"] != "written"
    rt = mod("runtime").CliRuntime.discover()
    image = mod("registry").image(real["project"])["image"]
    assert mod("registry").conformance(real["project"], rt.identity(), image) is not None


def test_04l_limit_probes(real):
    probes = {p["id"]: p for p in _conformance(real)["probes"]}
    for pid in ("P-09", "P-10", "P-11", "P-12", "P-13", "P-14", "P-15", "P-17"):
        assert probes[pid]["pass"], probes[pid]


def test_m5_malicious_results_rejected(real):
    p13b = next(p for p in _conformance(real)["probes"] if p["id"] == "P-13b")
    assert p13b["pass"], p13b
    detail = json.loads(p13b["detail"])
    assert set(detail) == set(mod("conformance").P13B)
    assert not any(v == "accepted" for v in detail.values())


def test_real_helper_flow_with_real_conformance(real):
    """The full helper flow with real containers (compile probe, two samples, target run, collection) on the
    real registration and the real, passing conformance record (no seeded record, no test seam)."""
    from x_ipe_secure_code.guard import service as guard

    registry = mod("registry")
    root = real["project"]
    assert _conformance(real, cached=False)["passed"] is True
    rt = mod("runtime").CliRuntime.discover()
    identity, image = rt.identity(), registry.image(root)["image"]
    record = registry.conformance(root, identity, image)
    assert record is not None and record["passed"] is True and record["rendered"]
    assert all(p["pass"] and "test seam" not in p["detail"] for p in record["probes"])
    flow = Flow(real)
    vid = helper_run(real)
    out = flow.submit(vid)
    assert out.ok and out.data["checks"]["compile"]["outcome"] == "pass", out.to_text()
    hid = out.data["helper"]
    assert flow.review(vid, hid).ok and flow.grant(vid).ok
    ran = flow.run(vid, hid, flow.helper_attempt(vid))
    assert ran.ok and ran.data["outcome"] == "clean", ran.to_text()
    assert [s["outcome"] for s in ran.data["samples"]] == ["finding", "clean"]
    assert ran.data["uncovered_count"] == 0
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    ok = [e for e in state_of(real, vid)["evidence"] if e["method_status"] == "ok"]
    assert ok and ok[0]["helper"]["acceptance"] == "accepted_full"
    from helperhelp import raw_record

    assert raw_record(real, vid, ledger=[{"check": "C1", "state": "met", "evidence": [ok[0]["id"]]}]).ok
    bad = flow.submit(
        vid, flow.request(vid, flow.generation(vid), script_file=flow.file("bad.py", "x = (\n"))
    )
    assert bad.problems[0].code == "HELPER_CHECK_FAILED"
    assert "parse" in bad.problems[0].message or "syntax" in bad.problems[0].message
    concluded = guard.conclude(str(root), vid)
    assert {r["check"]: r["state"] for r in concluded.data["ledger"]}["C1"] == "met"
    leftovers = subprocess.run(
        [
            shutil.which("docker") or "docker",
            "ps",
            "-a",
            "--filter",
            f"label=x-ipe.secure-code.verification={vid}",
            "-q",
        ],
        capture_output=True,
        text=True,
    )
    assert leftovers.stdout.strip() == ""
    assert RULE
