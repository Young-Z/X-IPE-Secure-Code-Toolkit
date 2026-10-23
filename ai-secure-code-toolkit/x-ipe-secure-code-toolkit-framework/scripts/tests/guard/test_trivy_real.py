"""Mandatory real-binary Trivy acceptance gate (FEATURE-002-D technical design, "Test Plan").

Marker `trivy_real`: deselected by default (tests/conftest.py); run only as
`uv run pytest -m trivy_real --require-real-trivy tests/guard/test_trivy_real.py` by the acceptance task.
With `--require-real-trivy` every missing prerequisite FAILS the gate (never a skip):

* `docker` CLI and a Linux arm64 (validated) or x86-64 Docker engine;
* `SECURE_CODE_TRIVY_BINARY`: the official Trivy v0.76.1 binary extracted from the release archive
  (its SHA-256 must be a table entry for the engine's architecture);
* `SECURE_CODE_TRIVY_IMAGE`: a local image with Python >= 3.11, `cryptography`, `pyyaml`, `iptables`,
  `getent` (no image is pulled by this gate);
* `SECURE_CODE_TRIVY_SAMPLES`: folder with `shanghai-marathon-registration/` and `test-projects/WebGoat/`;
* `SECURE_CODE_TRIVY_ARCHIVES`: folder with `redis-6-alpine.tar`, `hello-world.tar`, `jar-only.tar`
  (created locally with `docker save`);
* `SECURE_CODE_TRIVY_DOWNLOAD_AUTHORIZED=1`: the user's recorded authorization to download the Trivy
  components inside disposable containers (README header); without it the gate is blocked.

Topology: an `--internal` network whose only reachable peer is the observing container running
`tests/support/obs_relay.py` (DNS sinkhole + SNI-logging relay + catch-all + UDP counters); the toolkit
container is attached only to that network, uses the observer as DNS server with no search domains and
gets no proxy. Each provisioning operation and each scan has its own log window (`ctl reset` / `ctl dump`).
The toolkit folder is mounted read-only; projects live inside the disposable container.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from conftest import TOOLKIT_ROOT

pytestmark = pytest.mark.trivy_real
DIGESTS = {
    "aarch64": "b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85",
    "x86_64": "d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83",
}
KNOWN = {"mirror.gcr.io": {"mirror.gcr.io"}, "ghcr.io": {"ghcr.io", "pkg-containers.githubusercontent.com"}}
REPOS = {
    "mirror.gcr.io": {
        "vulnerability_db": "https://mirror.gcr.io/aquasec/trivy-db:2",
        "java_db": "https://mirror.gcr.io/aquasec/trivy-java-db:1",
        "checks_bundle": "https://mirror.gcr.io/aquasec/trivy-checks:2",
    },
    "ghcr.io": {
        "vulnerability_db": "https://ghcr.io/aquasecurity/trivy-db:2",
        "java_db": "https://ghcr.io/aquasecurity/trivy-java-db:1",
        "checks_bundle": "https://ghcr.io/aquasecurity/trivy-checks:2",
    },
}
SCRIPTS = "/toolkit/x-ipe-secure-code-toolkit-framework/scripts"
LAUNCHER = f"{SCRIPTS}/tests/support/launcher.py"
PROJECT = "/work/project"


def _need(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(f"real-binary gate prerequisite missing: {message}")


def _sh(*args: str, check: bool = True, timeout: int = 900, input_text: str | None = None) -> str:
    out = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, input=input_text)
    if check and out.returncode != 0:
        raise AssertionError(f"{shlex.join(args)} failed ({out.returncode}): {out.stdout}\n{out.stderr}")
    return out.stdout


class Gate:
    def __init__(self) -> None:
        tag = secrets.token_hex(3)
        self.net, self.obs, self.run = f"tvx-int-{tag}", f"tvx-obs-{tag}", f"tvx-run-{tag}"
        self.image = os.environ.get("SECURE_CODE_TRIVY_IMAGE", "")
        self.binary = Path(os.environ.get("SECURE_CODE_TRIVY_BINARY", "/nonexistent"))
        self.samples = Path(os.environ.get("SECURE_CODE_TRIVY_SAMPLES", "/nonexistent"))
        self.archives = Path(os.environ.get("SECURE_CODE_TRIVY_ARCHIVES", "/nonexistent"))
        self.obs_ip = ""
        self.vid = ""

    # ------------------------------------------------------------------ prerequisites and topology
    def check(self) -> None:
        _need(shutil.which("docker") is not None, "docker CLI")
        _need(
            os.environ.get("SECURE_CODE_TRIVY_DOWNLOAD_AUTHORIZED") == "1",
            "the user's recorded download authorization (SECURE_CODE_TRIVY_DOWNLOAD_AUTHORIZED=1)",
        )
        _need(
            bool(self.image)
            and subprocess.run(["docker", "image", "inspect", self.image], capture_output=True).returncode
            == 0,
            "SECURE_CODE_TRIVY_IMAGE (local image; nothing is pulled)",
        )
        arch = _sh("docker", "info", "--format", "{{.Architecture}}").strip()
        arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(arch, arch)
        _need(arch in DIGESTS, f"a Linux arm64 or x86-64 engine (found {arch})")
        _need(
            self.binary.is_file() and hashlib.sha256(self.binary.read_bytes()).hexdigest() == DIGESTS[arch],
            "SECURE_CODE_TRIVY_BINARY with the official v0.76.1 digest for this architecture",
        )
        _need(
            (self.samples / "test-projects" / "WebGoat").is_dir()
            and (self.samples / "shanghai-marathon-registration").is_dir(),
            "SECURE_CODE_TRIVY_SAMPLES",
        )
        for name in ("redis-6-alpine.tar", "hello-world.tar", "jar-only.tar"):
            _need((self.archives / name).is_file(), f"SECURE_CODE_TRIVY_ARCHIVES/{name}")
        self.arch = arch

    def up(self) -> None:
        _sh("docker", "network", "create", "--internal", self.net)
        support = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework" / "scripts" / "tests" / "support"
        _sh(
            "docker",
            "run",
            "-d",
            "--name",
            self.obs,
            "--cap-add",
            "NET_ADMIN",
            "-v",
            f"{support}:/obs:ro",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            self.image,
            "sleep",
            "infinity",
        )
        _sh("docker", "network", "connect", self.net, self.obs)
        fmt = '{{(index .NetworkSettings.Networks "' + self.net + '").IPAddress}}'
        self.obs_ip = _sh("docker", "inspect", "-f", fmt, self.obs).strip()
        iface = _sh(
            "docker",
            "exec",
            self.obs,
            "sh",
            "-c",
            f"ip -o -4 addr show | awk '$4 ~ /^{self.obs_ip}\\// {{print $2}}'",
        ).strip()
        subprocess.Popen(
            ["docker", "exec", self.obs, "python", "/obs/obs_relay.py", "serve", self.obs_ip, iface]
        )
        time.sleep(2)
        _sh(
            "docker",
            "run",
            "-d",
            "--name",
            self.run,
            "--network",
            self.net,
            "--dns",
            self.obs_ip,
            "--dns-search",
            ".",
            "--dns-option",
            "ndots:1",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-v",
            f"{TOOLKIT_ROOT}:/toolkit:ro",
            "-v",
            f"{self.binary}:/opt/trivy/trivy:ro",
            "-v",
            f"{self.samples}:/samples:ro",
            "-v",
            f"{self.archives}:/images:ro",
            self.image,
            "sleep",
            "infinity",
        )

    def down(self) -> None:
        for name in (self.run, self.obs):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "network", "rm", self.net], capture_output=True)

    # ------------------------------------------------------------------ commands
    def ctl(self, *args: str) -> dict:
        return json.loads(_sh("docker", "exec", self.obs, "python", "/obs/obs_relay.py", "ctl", *args))

    @contextmanager
    def window(self):
        self.ctl("reset")
        box: dict = {}
        yield box
        box.update(self.ctl("dump"))

    def exec(self, *args: str, check: bool = True, timeout: int = 1800) -> str:
        return _sh("docker", "exec", "-w", "/work", self.run, *args, check=check, timeout=timeout)

    def cli(self, *args: str, timeout: int = 1800) -> dict:
        out = self.exec(
            "python", LAUNCHER, "--test-trust-dir", "/trust", *args, "--json", check=False, timeout=timeout
        )
        return json.loads(out)

    def py(self, code: str) -> str:
        prelude = (
            f"import sys, json; sys.path[:0] = ['{SCRIPTS}/src', '{SCRIPTS}/tests'];"
            "from conftest import FakeInteraction, PASSPHRASE\n"
        )
        return self.exec("python", "-c", prelude + code)


@pytest.fixture(scope="module")
def gate():
    g = Gate()
    g.check()
    g.up()
    try:
        g.exec("mkdir", "-p", "/work")
        g.exec("cp", "-r", "/samples/test-projects/WebGoat", f"{PROJECT}")
        g.exec("cp", "-r", "/samples/shanghai-marathon-registration", f"{PROJECT}/marathon")
        g.exec("mkdir", "-p", f"{PROJECT}/images", f"{PROJECT}/fixtures")
        g.exec("sh", "-c", f"cp /images/*.tar {PROJECT}/images/")
        g.py(_SETUP)
        yield g
    finally:
        g.down()


_SETUP = f"""
from pathlib import Path
from x_ipe_secure_code.project_init import initialize_project
from x_ipe_secure_code.auth.service import initialize_authorization
from x_ipe_secure_code.auth.trust_store import resolve
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.policy import service as policy
root = Path('{PROJECT}')
(root / 'README.md').write_text('# gate\\n')
(root / 'trivy.yaml').write_text('severity: CRITICAL\\n')
(root / '.trivyignore').write_text('CVE-2013-7285\\n')
(root / 'trivy-secret.yaml').write_text('disable-rules: [aws-access-key-id]\\n')
import secrets, string
key = 'AKIA' + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
Path('/work/key.txt').write_text(key + '\\n')  # generated at run time, container-only
(root / 'fixtures' / 'settings.env').write_text('aws_key = ' + key + '\\n')
(root / 'fixtures' / 'requirements.txt').write_text('requests==2.31.0\\n')
assert initialize_project(str(root), 'github-copilot').ok
paths = resolve(Path('/trust'))
assert initialize_authorization(paths=paths, interaction=FakeInteraction(answers=[PASSPHRASE] * 2)).ok
items = [{{'namespace': 'CWE', 'version': '4.14', 'rule_id': r, 'content': 'Rule body.\\n',
           'source_location': 'https://example.org/' + r}} for r in ('CWE-79', 'CWE-89')]
batch = Path('/work/batch.json')
batch.write_text(json.dumps({{'schema': 'ai-secure-code-toolkit/knowledge-batch/v1', 'items': items}}))
assert knowledge.import_batch(str(root), str(batch), [], [], trust_paths=paths).ok
"""


def _grant(gate: Gate, recipient: str, scopes: list[str]) -> None:
    gate.py(
        "from x_ipe_secure_code.guard import egress\n"
        f"out = egress.allow_egress('{PROJECT}', '{gate.vid}', 'tool_update', '{recipient}', ['metadata'], "
        f"{scopes!r}, 'gate', interaction=FakeInteraction(answers=['{gate.vid}']))\n"
        "assert out.ok, out.to_text()"
    )


def _assert_provisioning_window(log: dict, registry: str) -> None:
    names = {e["qname"] for e in log["dns"]}
    snis = {e["sni"] for e in log["sni"]}
    assert names <= KNOWN[registry], names  # unexplained names are never tolerated
    assert snis == KNOWN[registry], snis
    assert log["catchall"] == [] and log["udp"] == 0


def _assert_silent(log: dict) -> None:
    assert log["dns"] == [] and log["sni"] == [] and log["catchall"] == [] and log["udp"] == 0, log


def test_control_windows_are_silent(gate):
    with gate.window() as log:
        gate.exec("getent", "hosts", gate.obs, check=False)
    assert log["dns"] == []
    with gate.window() as log:
        time.sleep(10)
    _assert_silent(log)


def test_register_real_binary(gate):
    out = gate.cli("tools", "register", "--project", PROJECT, "--tool", "trivy", "--path", "/opt/trivy/trivy")
    assert out["ok"] and out["data"]["version"] == "0.76.1"
    assert (
        out["data"]["platform_validated"] is (gate.arch == "aarch64")
        and out["data"]["platform"]["libc"] is None
    )


def test_open_verification_for_the_gate(gate):
    out = gate.py(
        "from x_ipe_secure_code.policy import service as policy\n"
        "from x_ipe_secure_code.guard import service as guard\n"
        f"p = policy.resolve_policies('{PROJECT}', ['CWE/4.14/CWE-79', 'CWE/4.14/CWE-89'], False, [])\n"
        "ds = [{'ref': e['requested'], 'decision': 'adopted',"
        " 'state_digest': e['source_evidence']['state_digest']}"
        " for e in p.data['entries']]\n"
        "doc = {'schema': 'ai-secure-code-toolkit/scope-decisions/v1', 'mode': 'clues', 'proposal_digest':"
        " p.data['proposal_digest'], 'clues': 'gate', 'language_context': ['java'], 'decisions': ds,"
        " 'confirmation_note': 'gate', 'considered': ['CWE/4.14/CWE-79', 'CWE/4.14/CWE-89']}\n"
        "open('/work/d.json', 'w').write(json.dumps(doc))\n"
        f"scope = policy.save_scope('{PROJECT}', '/work/d.json', True).data['scope_id']\n"
        "targets = ['WebGoat/pom.xml', 'WebGoat/Dockerfile', 'WebGoat/Dockerfile_desktop', 'WebGoat/src',"
        " 'marathon',"
        " 'fixtures', 'images/redis-6-alpine.tar', 'images/hello-world.tar', 'images/jar-only.tar']\n"
        "o = {'schema': 'ai-secure-code-toolkit/guard-open/v1', 'scope_id': scope,"
        " 'targets': [{'path': t} for t in"
        " targets], 'context': [{'path': 'README.md'}], 'budget': {'minutes': 60}}\n"
        "open('/work/o.json', 'w').write(json.dumps(o))\n"
        f"r = guard.open_verification('{PROJECT}', '/work/o.json')\nassert r.ok, r.to_text()\n"
        "print(r.data['verification_id'])"
    )
    gate.vid = out.strip().splitlines()[-1]
    checks = []
    for i, obj in enumerate(
        [
            ["WebGoat/pom.xml"],
            ["WebGoat/Dockerfile"],
            ["WebGoat/Dockerfile_desktop"],
            ["WebGoat/src"],
            ["marathon"],
            ["fixtures"],
            ["images/redis-6-alpine.tar"],
            ["images/hello-world.tar"],
            ["images/jar-only.tar"],
        ],
        1,
    ):
        checks.append(
            {
                "id": f"C{i}",
                "rule": "CWE/4.14/CWE-79",
                "object": obj,
                "methods": [{"name": "trivy", "kind": "runtime", "required": True}],
                "minimum_evidence": ["runtime"],
                "method_choice": {
                    "considered": ["trivy"],
                    "cost": "seconds",
                    "selected": ["trivy"],
                    "reason": "real-binary gate",
                },
            }
        )
    plan = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": checks,
        "not_applicable": [{"rule": "CWE/4.14/CWE-89", "reason": "gate"}],
    }
    gate.exec("sh", "-c", f"cat > /work/plan.json <<'EOF'\n{json.dumps(plan)}\nEOF")
    out = gate.cli("guard", "plan", "--project", PROJECT, "--run", gate.vid, "--request", "/work/plan.json")
    assert out["ok"], out


@pytest.mark.parametrize("registry", ["mirror.gcr.io", "ghcr.io"])
@pytest.mark.parametrize("component", ["vulnerability_db", "java_db", "checks_bundle"])
def test_provisioning_contacts_exactly_the_known_hosts(gate, registry, component):
    _grant(gate, f"https://{registry}", [REPOS[registry][component]])
    if registry == "ghcr.io":
        _grant(
            gate,
            "https://pkg-containers.githubusercontent.com",
            ["https://pkg-containers.githubusercontent.com"],
        )
    with gate.window() as log:
        out = gate.cli(
            "tools",
            "provision",
            "--project",
            PROJECT,
            "--tool",
            "trivy",
            "--run",
            gate.vid,
            "--component",
            component,
            "--registry",
            registry,
            "--time-limit",
            "1800",
        )
    assert out["ok"], out
    (op,) = out["data"]["operations"]
    assert op["outcome"] == "completed" and op["content_digest"].startswith("sha256:") and op["metadata"]
    assert {h["host"] for h in op["known_hosts"]} == KNOWN[registry]
    _assert_provisioning_window(log, registry)


@pytest.mark.parametrize("component", ["vulnerability_db", "checks_bundle"])
def test_refused_repository_fails_without_fallback(gate, component):
    gate.ctl("refuse", "mirror.gcr.io")
    try:
        with gate.window() as log:
            out = gate.cli(
                "tools",
                "provision",
                "--project",
                PROJECT,
                "--tool",
                "trivy",
                "--run",
                gate.vid,
                "--component",
                component,
                "--time-limit",
                "600",
            )
    finally:
        gate.ctl("refuse")
    (op,) = out["data"]["operations"]
    assert op["outcome"] == "failed" and op["previous"] == "kept"  # the checks bundle exits 0 yet fails
    assert {e["sni"] for e in log["sni"]} == {"mirror.gcr.io"} and {e["qname"] for e in log["dns"]} <= {
        "mirror.gcr.io"
    }
    assert log["catchall"] == [] and log["udp"] == 0
    # final state for the scans: the mirror components
    for c in ("vulnerability_db", "java_db", "checks_bundle"):
        gate.cli(
            "tools", "provision", "--project", PROJECT, "--tool", "trivy", "--run", gate.vid, "--component", c
        )


SCANS = [
    ("C1", ["vuln"], "filesystem", ["WebGoat/pom.xml"]),
    ("C2", ["misconfig"], "filesystem", ["WebGoat/Dockerfile"]),
    ("C3", ["misconfig"], "filesystem", ["WebGoat/Dockerfile_desktop"]),
    ("C4", ["secret"], "filesystem", ["WebGoat/src"]),
    ("C5", ["secret"], "filesystem", ["marathon"]),
    ("C6", ["vuln", "secret"], "filesystem", ["fixtures"]),
    ("C7", ["vuln"], "image_archive", ["images/redis-6-alpine.tar"]),
    ("C8", ["vuln"], "image_archive", ["images/hello-world.tar"]),
    ("C9", ["vuln"], "image_archive", ["images/jar-only.tar"]),
]


@pytest.mark.parametrize(("check", "scanners", "mode", "targets"), SCANS)
def test_scans_are_offline_and_match_the_validation(gate, check, scanners, mode, targets):
    c = {"check": check, "scanners": scanners, "mode": mode, "targets": targets}
    if check == "C3":
        c["config_types"] = [{"path": "WebGoat/Dockerfile_desktop", "type": "dockerfile"}]
    doc = {
        "schema": "ai-secure-code-toolkit/guard-tool/v1",
        "adapter": "trivy",
        "time_limit_seconds": 600,
        "checks": [c],
    }
    gate.exec("sh", "-c", f"cat > /work/r-{check}.json <<'EOF'\n{json.dumps(doc)}\nEOF")
    with gate.window() as log:
        out = gate.cli(
            "guard", "tool", "--project", PROJECT, "--run", gate.vid, "--request", f"/work/r-{check}.json"
        )
    assert out["ok"], out
    _assert_silent(log)
    state = json.loads(gate.exec("cat", f"{PROJECT}/.x-ipe/private/secure-code/guard/{gate.vid}/state.json"))
    entry = state["adapter_runs"][-1]
    assert set(entry["rehash"].values()) == {"unchanged"}
    findings = [f for f in state["findings"] if f["tool"]["run"] == entry["n"]]
    if check == "C1":
        assert len([f for f in findings if f["tool"]["scanner"] == "vuln"]) == 36
        assert (
            "18" in json.dumps(entry["checks"][check])
            or len(entry["checks"][check]["accounting"][0]["skipped_packages"]) == 18
        )
    if check == "C3":
        assert entry["checks"][check]["method_status"] == "ok"  # recognized through the override
    if check == "C8":
        assert "OS not detected" in json.dumps(entry["checks"][check])
    assert "CVE-2013-7285" not in json.dumps(entry.get("ignored", []))  # project .trivyignore not loaded


def test_network_none_scan_and_timeouts_mapped(gate):
    gate.exec(
        "sh",
        "-c",
        f"mkdir -p {PROJECT}/big && head -c 400000000 /dev/zero | tr '\\0' 'a' > {PROJECT}/big/a.txt",
    )
    _sh("docker", "network", "disconnect", gate.net, gate.run)
    try:
        doc = {
            "schema": "ai-secure-code-toolkit/guard-tool/v1",
            "adapter": "trivy",
            "time_limit_seconds": 600,
            "checks": [
                {"check": "C1", "scanners": ["vuln"], "mode": "filesystem", "targets": ["WebGoat/pom.xml"]}
            ],
        }
        gate.exec("sh", "-c", f"cat > /work/r-none.json <<'EOF'\n{json.dumps(doc)}\nEOF")
        out = gate.cli(
            "guard", "tool", "--project", PROJECT, "--run", gate.vid, "--request", "/work/r-none.json"
        )
        assert out["ok"] and out["data"]["checks"]["C1"]["status"] in ("completed", "completed_with_errors")
    finally:
        _sh("docker", "network", "connect", gate.net, gate.run)


def test_secret_never_stored_and_components_unchanged(gate):
    stored = gate.exec(
        "sh", "-c", f"grep -rlF -f /work/key.txt {PROJECT}/.x-ipe {PROJECT}/x-ipe-docs || true"
    )
    assert stored.strip() == ""
    status = gate.cli("status", "--project", PROJECT)["data"]["tools"]["trivy"]
    assert {c["state"] for c in status["components"].values()} == {"present"}


def test_config_types_equal_the_help_list(gate):
    text = gate.exec("/opt/trivy/trivy", "fs", "--help")
    match = re.search(r"--misconfig-scanners strings.*?\(default \[([^\]]*)\]\)", text, re.S)
    assert match, "misconfig scanner list not found in --help"
    listed = {t.strip() for t in match.group(1).split(",") if t.strip()}
    code = gate.py(
        "from x_ipe_secure_code.adapters import trivy\nprint(json.dumps(sorted(trivy.CONFIG_TYPES)))"
    )
    assert set(json.loads(code.strip().splitlines()[-1])) == listed
