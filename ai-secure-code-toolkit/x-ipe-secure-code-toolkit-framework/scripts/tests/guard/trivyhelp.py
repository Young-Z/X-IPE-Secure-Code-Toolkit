"""Shared helpers for the FEATURE-002-D integration tests (fake Trivy, plans, grants, provisioning).

Test-side interface assumptions (chosen within the technical design, which fixes the CLI arguments but
not the Python signatures): `tools_service.provision(project, tool, run_id, components, registry=...,
time_limit=..., trust_paths=...)` and `tools_service.remove_components(project, tool, components=...,
remove_all=..., trust_paths=...)` back `secure-code tools provision` / `tools remove-components`.
"""

# ruff: noqa: F811
from __future__ import annotations

import importlib.util
import json
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import FakeInteraction
from test_guard import GUARD, R1, R2, REPORTS, env, req  # noqa: F401 - fixture reuse

from x_ipe_secure_code import tools_service
from x_ipe_secure_code.adapters import digests
from x_ipe_secure_code.guard import cancel, egress, model, toolrun
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.guard.targets import file_digest

ADAPTERS_DIR = Path(__file__).resolve().parents[1] / "adapters"
FAKE = ADAPTERS_DIR / "fake_trivy.py"
FIXTURES = ADAPTERS_DIR / "fixtures" / "trivy"
_spec = importlib.util.spec_from_file_location("trivytar", ADAPTERS_DIR / "trivytar.py")
trivytar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(trivytar)

PRIVATE = ".x-ipe/private/secure-code"
CACHE = f"{PRIVATE}/tools/trivy-cache"
STAGE_ROOT = f"{PRIVATE}/adapter-stage/trivy"
RECORD = f"{PRIVATE}/tools/trivy.json"
ALL = ("vulnerability_db", "java_db", "checks_bundle")
OFFLINE = (
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
    "--offline-scan",
    "--skip-version-check",
    "--disable-telemetry",
)
REPO = {
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
BLOB = "https://pkg-containers.githubusercontent.com"
PLATFORM_GAP = "Trivy execution is supported only on Linux x86-64 and Linux arm64 in this version"
TRIVY_METHOD = {"name": "trivy", "kind": "runtime", "required": True}
READ_METHOD = {"name": "semantic-review", "kind": "reading", "required": True}
SCHEMA_TOOL = "ai-secure-code-toolkit/guard-tool/v1"

POM = """<project>
  <dependencies>
    <dependency>
      <groupId>com.thoughtworks.xstream</groupId>
      <artifactId>xstream</artifactId>
      <version>1.4.5</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
"""
POM_COMPLETE = POM.replace(
    "<artifactId>jackson-databind</artifactId>",
    "<artifactId>jackson-databind</artifactId><version>2.17.0</version>",
)
DOCKERFILE = (
    "FROM python:latest\nADD app.py /app/app.py\nRUN apt-get update && apt-get install -y curl\n"
    'EXPOSE 22\nCMD ["python", "/app/app.py"]\n'
)
DEPLOYMENT = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  template:\n    spec:\n"
    "      containers:\n        - name: demo\n          image: nginx:latest\n          securityContext:\n"
    "            privileged: true\n            runAsUser: 0\n"
)
MAIN_TF = 'resource "aws_s3_bucket" "demo" {\n  bucket = "demo-bucket"\n  acl    = "public-read"\n}\n'
COMPOSE = 'services:\n  web:\n    image: nginx:latest\n    privileged: true\n    ports:\n      - "80:80"\n'


# --------------------------------------------------------------------------- host and fake binary
@pytest.fixture
def linux(monkeypatch):
    """Patch the host to Linux (the dev host may be macOS); the real architecture is kept if supported."""
    real = digests.host_platform()
    host = {
        "os": "linux",
        "arch": real["arch"] if real["arch"] in ("aarch64", "x86") else "x86",
        "libc": "glibc",
    }
    monkeypatch.setattr(digests, "host_platform", lambda: dict(host))
    return host


def set_host(monkeypatch, os_, arch, libc=None):
    monkeypatch.setattr(digests, "host_platform", lambda: {"os": os_, "arch": arch, "libc": libc})


def install_fake(env, monkeypatch, host, *, version="0.76.1", register=True, name="trivy"):
    folder = env["tmp"] / f"fake-{name}-{version}"
    folder.mkdir(exist_ok=True)
    config = folder / "config.json"
    binary = folder / "bin" / "trivy"
    binary.parent.mkdir(exist_ok=True)
    binary.write_text(
        f"#!{sys.executable} -B\n"
        + FAKE.read_text().replace("__CONFIG__", str(config)).replace("__FIXTURES__", str(FIXTURES))
    )
    binary.chmod(0o755)
    build = digests.ToolBuild("trivy", version, "linux", host["arch"], None, "fake-asset", False)
    monkeypatch.setitem(digests.TABLE, file_digest(binary), build)
    fake = {"binary": binary, "config": config, "log": folder / "invocations.jsonl", "build": build}
    if register:
        reg = tools_service.register(str(env["project"]), "trivy", str(binary), trust_paths=env["paths"])
        assert reg.ok, reg.to_text()
    return fake


@pytest.fixture
def trivy(env, linux, monkeypatch):
    """A fake Trivy v0.76.1 binary registered as an official static Linux build for this (patched) host."""
    return install_fake(env, monkeypatch, linux)


def set_cfg(fake, **cfg):
    current = json.loads(fake["config"].read_text()) if fake["config"].exists() else {}
    current.update(cfg)
    fake["config"].write_text(json.dumps(current))


def calls(fake, kind=None):
    if not fake["log"].exists():
        return []
    out = [json.loads(x) for x in fake["log"].read_text().splitlines()]
    return [c for c in out if kind is None or c.get("kind") == kind]


def flag_value(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


# --------------------------------------------------------------------------- project files
def write(env, files):
    for rel, data in files.items():
        path = env["project"] / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data)


def fake_aws_key() -> str:
    """A self-authored fake AWS key id generated at test time (never stored in the repository)."""
    import secrets
    import string

    return "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))


def fake_github_token() -> str:
    import secrets
    import string

    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def image(**kw) -> bytes:
    return trivytar.docker_save(**kw)


ALPINE = {"Family": "alpine", "Name": "3.21.6"}
ALPINE_PKGS = [
    {
        "name": "libcrypto3",
        "version": "3.3.6-r0",
        "vulns": [{"id": "CVE-2026-31789", "severity": "CRITICAL", "fixed": "3.3.7-r0"}],
    },
    {"name": "musl", "version": "1.2.5-r9", "vulns": []},
]


# --------------------------------------------------------------------------- verification helpers
def tcheck(
    cid="C1", obj=("pom.xml",), methods=(TRIVY_METHOD,), selected=("trivy",), minimum=("runtime",), rule=R1
):
    c = {
        "id": cid,
        "rule": rule,
        "object": list(obj),
        "methods": list(methods),
        "minimum_evidence": list(minimum),
    }
    if selected is not None:
        c["method_choice"] = {
            "considered": ["semantic-review", "trivy"],
            "cost": "trivy ~1 s per scanner",
            "selected": list(selected),
            "reason": "declared dependencies and configuration: Trivy is the cheapest sufficient method",
        }
    return c


def opened(env, targets=("pom.xml",), **over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-open/v1",
        "scope_id": env["scope"],
        "targets": [t if isinstance(t, dict) else {"path": t} for t in targets],
        "context": [{"path": "README.md"}],
    }
    doc.update(over)
    result = guard.open_verification(str(env["project"]), req(env, doc))
    assert result.ok, result.to_text()
    return result.data["verification_id"]


def plan(env, vid, checks):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": checks,
        "not_applicable": [{"rule": R2, "reason": "no database access in these targets"}],
    }
    result = guard.record_plan(str(env["project"]), vid, req(env, doc))
    assert result.ok, result.to_text()


def planned(env, checks, targets=("pom.xml",), **over):
    vid = opened(env, targets=targets, **over)
    plan(env, vid, checks)
    return vid


def trc(cid="C1", scanners=("vuln",), mode="filesystem", targets=("pom.xml",), config_types=None):
    c = {"check": cid, "scanners": list(scanners), "mode": mode, "targets": list(targets)}
    if config_types is not None:
        c["config_types"] = config_types
    return c


def scan(env, vid, checks, **over):
    doc = {"schema": SCHEMA_TOOL, "adapter": "trivy", "time_limit_seconds": 120, "checks": checks}
    doc.update(over)
    for key in [k for k, v in doc.items() if v is ...]:  # `...` removes a key (missing-field cases)
        doc.pop(key)
    return toolrun.run_tool(str(env["project"]), vid, req(env, doc))


def state(env, vid):
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


def tev(env, vid, cid="C1"):
    return [e for e in state(env, vid)["evidence"] if cid in e["checks"] and e["method"] == "trivy"][-1]


def run_entry(env, vid):
    return [r for r in state(env, vid).get("adapter_runs", []) if r["adapter"] == "trivy"][-1]


def gaps_text(result, env, vid, cid="C1"):
    """Everything the toolkit says about one check: result data, evidence summary, run entry, next steps."""
    parts = [json.dumps(result.data.get("checks", {}).get(cid, {})), " ".join(result.next_steps)]
    try:
        parts.append(tev(env, vid, cid)["summary"])
        parts.append(json.dumps(run_entry(env, vid)["checks"][cid]))
    except (IndexError, KeyError):
        pass
    return "\n".join(parts)


def nothing_recorded(env, vid, before):
    after = state(env, vid)
    assert after["attempts"] == before["attempts"]
    assert after["evidence"] == before["evidence"] and after["findings"] == before["findings"]
    assert after.get("adapter_runs", []) == before.get("adapter_runs", [])
    assert after["revision"] == before["revision"]


# --------------------------------------------------------------------------- grants and provisioning
def grant(env, vid, recipient, scope, data=("metadata",), purpose="tool_update"):
    out = egress.allow_egress(
        str(env["project"]),
        vid,
        purpose,
        recipient,
        list(data),
        list(scope),
        "Trivy components",
        interaction=FakeInteraction(answers=[vid]),
    )
    assert out.ok, out.to_text()
    return out.data["grant"]["id"]


def grant_for(env, vid, components=ALL, registry="mirror.gcr.io"):
    ids = [grant(env, vid, f"https://{registry}", [f"https://{REPO[registry][c]}" for c in components])]
    if registry == "ghcr.io":
        ids.append(grant(env, vid, BLOB, [BLOB]))
    return ids


def provision(env, vid, components=ALL, registry="mirror.gcr.io", time_limit=600, paths=None):
    return tools_service.provision(
        str(env["project"]),
        "trivy",
        vid,
        list(components),
        registry=registry,
        time_limit=time_limit,
        trust_paths=paths or env["paths"],
    )


def provisioned(env, vid, components=ALL, registry="mirror.gcr.io"):
    grant_for(env, vid, components, registry)
    out = provision(env, vid, components, registry)
    assert out.ok, out.to_text()
    assert [o["outcome"] for o in out.data["operations"]] == ["completed"] * len(components), out.to_text()
    return out


def remove(env, components=None, remove_all=False, paths=None):
    return tools_service.remove_components(
        str(env["project"]),
        "trivy",
        components=components,
        remove_all=remove_all,
        trust_paths=paths or env["paths"],
    )


def pointer(env):
    path = env["project"] / CACHE / "components.json"
    return json.loads(path.read_text()) if path.exists() else None


def gen_dir(env, component):
    entry = pointer(env)["components"][component]
    return env["project"] / CACHE / "gen" / component / entry["generation"]


def tamper(path: Path, data=b"tampered", *, same_size=False):
    path.chmod(0o644)
    if same_size:
        raw = bytearray(path.read_bytes())
        raw[-2] = ord("0") if raw[-2] != ord("0") else ord("1")
        path.write_bytes(bytes(raw))
    else:
        with open(path, "ab") as handle:
            handle.write(data)


def trivy_status(env):
    from x_ipe_secure_code import status as status_mod

    return status_mod.collect(str(env["project"]), trust_paths=env["paths"]).data["tools"]["trivy"]


def conclude_report(env, vid):
    guard.conclude(str(env["project"]), vid)
    return (env["project"] / REPORTS / f"{vid}.md").read_text()


def private_tree(env):
    """Bytes of every regular file under the project's private and report folders (for leak checks)."""
    out = {}
    for base in (env["project"] / ".x-ipe", env["project"] / "x-ipe-docs" / "secure-code"):
        if base.exists():
            for p in base.rglob("*"):
                if p.is_file() and not p.is_symlink():
                    out[str(p)] = p.read_bytes()
    return out


# --------------------------------------------------------------------------- concurrency helpers
def wait_for_call(fake, kind="scan", count=1, timeout=30):
    end = time.monotonic() + timeout
    while len(calls(fake, kind)) < count:
        if time.monotonic() > end:
            raise AssertionError(f"no {kind} invocation within {timeout} s")
        time.sleep(0.05)


def cancel_when_called(env, vid, fake, kind="scan", count=1):
    """Cancel the verification from another thread once the fake was invoked `count` times."""
    box = {}

    def go():
        wait_for_call(fake, kind, count)
        time.sleep(0.3)
        box["result"] = cancel.cancel(str(env["project"]), vid, "user stopped")

    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    return thread, box


@pytest.fixture
def clock(monkeypatch):
    """Patch the Guard clock: `clock.at(env, vid, seconds)` sets now = opened_at + seconds."""

    class Clock:
        now = None

        def at(self, env_, vid, seconds):
            opened_at = model.parse_time(state(env_, vid)["opened_at"])
            self.now = (opened_at + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    c = Clock()
    real = model.utc_now
    monkeypatch.setattr(model, "utc_now", lambda: c.now or real())
    return c
