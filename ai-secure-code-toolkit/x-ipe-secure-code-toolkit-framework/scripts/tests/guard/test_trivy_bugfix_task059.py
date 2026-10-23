"""Bug Fix TASK-059 regression tests (FEATURE-002-D acceptance findings F-1 and F-2).

F-1 (AC-002D-03d "types supported by the verified tool version"): real `trivy fs --help` of v0.76.1 lists
nine misconfiguration types including `ansible` (acceptance/tool-level/ff-help-tf.jsonl); an `ansible`
override must be accepted and reach the tool, compose stays refused.
F-2 (AC-002D-05b/05f): two WARNs observed on the real v0.76.1 binary do not reduce analysis coverage
(acceptance/evidence-container-linux.jsonl, tool-validation/results-linux-aarch64.jsonl): the pip
license-detection skip (license scanning is out of scope) and the informational vendor-severity notice.
Exactly these messages, only for v0.76.1, are not analysis-degrading; every other WARN/ERROR still is.
"""

# ruff: noqa: F811
from __future__ import annotations

import re

import pytest
from conftest import posix_only
from trivyhelp import (  # noqa: F401 - fixture reuse
    DOCKERFILE,
    calls,
    env,
    flag_value,
    gaps_text,
    install_fake,
    linux,
    planned,
    provisioned,
    run_entry,
    scan,
    set_cfg,
    state,
    tcheck,
    tev,
    trc,
    trivy,
    write,
)

from x_ipe_secure_code.adapters import trivy as trivy_mod
from x_ipe_secure_code.adapters import trivy_log

pytestmark = posix_only

HELP_TYPES = {  # `trivy fs --help` v0.76.1, --misconfig-scanners default (ff-help-tf.jsonl, FF-01)
    "azure-arm",
    "cloudformation",
    "dockerfile",
    "helm",
    "kubernetes",
    "terraform",
    "terraformplan-json",
    "terraformplan-snapshot",
    "ansible",
}
PIP_LICENSE = "[pip] Unable to find python `site-packages` directory. License detection is skipped."
VENDOR_SEVERITY = (
    "Using severities from other vendors for some vulnerabilities. Read "
    "https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity-selection for details."
)
OBSERVED = [
    {"msg": PIP_LICENSE, "fields": {"err": "unable to find path to Python executable"}},
    {"msg": VENDOR_SEVERITY},
]


def scans(fake):
    return calls(fake, "scan")


# ======================================================================= F-1 misconfiguration types
def test_config_types_are_exactly_the_v0761_help_list():
    assert set(trivy_mod.CONFIG_TYPES) == HELP_TYPES and len(trivy_mod.CONFIG_TYPES) == 9


def test_ansible_override_accepted_and_reaches_the_tool(env, trivy):
    write(env, {"deploy/site.yml": "- hosts: all\n  tasks:\n    - name: ping\n      ping:\n"})
    vid = planned(env, [tcheck(obj=("deploy/site.yml",))], targets=("deploy/site.yml",))
    provisioned(env, vid)
    override = [{"path": "deploy/site.yml", "type": "ansible"}]
    request = trc(scanners=("misconfig",), targets=("deploy/site.yml",), config_types=override)
    result = scan(env, vid, [request])
    assert result.ok, result.to_text()
    (call,) = scans(trivy)
    assert flag_value(call["argv"], "--file-patterns") == [f"ansible:{re.escape('deploy/site.yml')}"]
    assert run_entry(env, vid)["checks"]["C1"]["config_types"] == override


@pytest.mark.parametrize("ctype", ["compose", "docker-compose", "Ansible", "ansible-playbook"])
def test_compose_and_non_listed_types_still_refused(env, trivy, ctype):
    write(env, {"Dockerfile_desktop": DOCKERFILE})
    vid = planned(env, [tcheck(obj=("Dockerfile_desktop",))], targets=("Dockerfile_desktop",))
    before = len(state(env, vid)["evidence"])
    override = [{"path": "Dockerfile_desktop", "type": ctype}]
    result = scan(
        env, vid, [trc(scanners=("misconfig",), targets=("Dockerfile_desktop",), config_types=override)]
    )
    assert not result.ok and result.problems[0].code == "TOOL_REQUEST_INVALID", result.to_text()
    assert "compose is not supported" in result.problems[0].message
    assert len(state(env, vid)["evidence"]) == before and scans(trivy) == []


# ======================================================================= F-2 WARN classification
def _warn(msg: str, fields: str = "") -> bytes:
    return f"2026-10-22T17:07:48Z\tWARN\t{msg}{fields}\n".encode()


@pytest.mark.parametrize(
    "line",
    [_warn(PIP_LICENSE, '\terr="unable to find path to Python executable"'), _warn(VENDOR_SEVERITY)],
)
def test_parser_observed_warnings_not_degrading_for_v0761(line):
    parser = trivy_log.LogParser(version="0.76.1")
    parser.feed(line)
    (m,) = parser.finish().messages
    assert m["kind"] == "benign"


@pytest.mark.parametrize(
    ("line", "version"),
    [
        (_warn(PIP_LICENSE), "0.77.0"),
        (_warn(VENDOR_SEVERITY), None),
        (_warn(PIP_LICENSE + " Extra"), "0.76.1"),
        (_warn("[pip] Unable to find python `site-packages` directory."), "0.76.1"),
        (_warn("Using severities from other vendors for some vulnerabilities."), "0.76.1"),
        (f"2026-10-22T17:07:48Z\tERROR\t{PIP_LICENSE}\n".encode(), "0.76.1"),
        (_warn("[npm] Unable to find node_modules. License detection is skipped."), "0.76.1"),
    ],
)
def test_parser_other_warnings_or_versions_stay_degrading(line, version):
    parser = trivy_log.LogParser(version=version)
    parser.feed(line)
    (m,) = parser.finish().messages
    assert m["kind"] == "degrading"


def _pip_check(env):
    write(env, {"fixtures/req/requirements.txt": "six==1.17.0\n"})
    return planned(env, [tcheck(obj=("fixtures/req",))], targets=("fixtures/req",))


def test_observed_warnings_on_fully_analysed_check_succeed(env, trivy):
    vid = _pip_check(env)
    provisioned(env, vid)
    set_cfg(trivy, warnings=OBSERVED)
    result = scan(env, vid, [trc(scanners=("vuln", "secret"), targets=("fixtures/req",))])
    assert result.ok and result.data["checks"]["C1"]["status"] == "completed", result.to_text()
    assert tev(env, vid)["method_status"] == "ok", gaps_text(result, env, vid)
    text = gaps_text(result, env, vid)
    assert "License detection is skipped" in text  # still recorded as a tool message, not a gap


@pytest.mark.parametrize(
    "extra",
    [
        {"msg": "[pip] Unable to parse the requirements file"},
        {"msg": PIP_LICENSE + " (retrying)"},
    ],
)
def test_unlisted_warning_still_fails_the_method(env, trivy, extra):
    vid = _pip_check(env)
    provisioned(env, vid)
    set_cfg(trivy, warnings=[*OBSERVED, extra])
    result = scan(env, vid, [trc(scanners=("vuln", "secret"), targets=("fixtures/req",))])
    assert result.ok, result.to_text()
    assert result.data["checks"]["C1"]["status"] == "completed_with_errors"
    assert tev(env, vid)["method_status"] == "failed"
    assert f"tool WARN: {extra['msg']}" in gaps_text(result, env, vid)


def test_version_mismatch_disables_the_allow_list(env, trivy, linux, monkeypatch):
    vid = _pip_check(env)
    provisioned(env, vid)
    other = install_fake(env, monkeypatch, linux, version="0.77.0", name="trivy-next")
    set_cfg(other, warnings=OBSERVED)
    result = scan(env, vid, [trc(scanners=("vuln", "secret"), targets=("fixtures/req",))])
    assert result.ok, result.to_text()
    assert run_entry(env, vid)["version"] == "0.77.0"
    assert result.data["checks"]["C1"]["status"] == "completed_with_errors"
    assert tev(env, vid)["method_status"] == "failed"
    assert f"tool WARN: {PIP_LICENSE}" in gaps_text(result, env, vid)
