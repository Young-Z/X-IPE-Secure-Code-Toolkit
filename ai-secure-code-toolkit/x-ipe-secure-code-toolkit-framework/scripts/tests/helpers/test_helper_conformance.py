"""FEATURE-002-F conformance orchestration with the fake CLI (AC-002F-11b judge, 11f; review M7).
A fake runtime never yields a passing record; the real suite runs in test_helper_conformance_real.py."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json

from helperhelp import IMAGE_ID, env, fake, flow, henv, mod, seed_registry, state_of  # noqa: F401


def conformance(env, runtime=None):
    return mod("conformance").run(str(env["project"]), env["paths"], runtime=runtime)


def record_file(env):
    folder = env["project"] / ".x-ipe/private/secure-code/helpers/conformance"
    return json.loads(next(folder.iterdir()).read_text())


# ---------- AC-002F-11f
def test_11f_fake_runtime_cannot_produce_record(flow):
    class Seam:
        kind = "docker"

    refused = conformance(flow.env, runtime=Seam())
    assert refused.problems[0].code == "HELPER_CONFORMANCE_REFUSED"
    registry = mod("registry")
    root = flow.root
    for p in (root / ".x-ipe/private/secure-code/helpers/conformance").iterdir():
        p.unlink()
    out = conformance(flow.env)
    assert out.ok and out.data["passed"] is False
    assert any(not p["pass"] for p in out.data["probes"])
    rt = mod("runtime").CliRuntime.discover()
    assert registry.conformance(root, rt.identity(), IMAGE_ID) is None
    from helperhelp import helper_run

    submitted = flow.submit(helper_run(flow.env))
    assert submitted.problems[0].code == "HELPER_CHECK_FAILED"
    assert "no valid conformance record" in submitted.problems[0].message


# ---------- AC-002F-11b (record content with fake evidence; enforcement only from the real suite)
def test_11b_probe_failure_recorded_fake_evidence(flow):
    for p in (flow.root / ".x-ipe/private/secure-code/helpers/conformance").iterdir():
        p.unlink()
    out = conformance(flow.env)
    record = record_file(flow.env)
    assert record["passed"] is False and record["mac"].startswith("hmac-sha256:")
    ids = [p["id"] for p in record["probes"]]
    assert ids[0] == "P-00" and {"P-01", "P-08", "P-13b", "P-17", "P-18"} <= set(ids)
    assert record["identity"]["kind"] == "docker" and record["image"] == IMAGE_ID
    assert out.data["record"] == record["id"]
    subs = [r[0] for r in flow.fake.log()]
    assert "pull" not in subs and "build" not in subs


# ---------- review M7: profile identity and behavioural denials both required
def test_m7_seccomp_needs_behavioural_denials_and_default_profile():
    judge = mod("conformance").seccomp_ok
    good = {
        "NoNewPrivs": "1",
        "Seccomp": "2",
        "Seccomp_filters": "1",
        "arch": "aarch64",
        "denied": {"add_key": "EPERM", "request_key": "EPERM", "keyctl": "EPERM", "unshare": "EPERM"},
    }
    builtin = {"security_options": ["name=seccomp,profile=builtin"]}
    assert judge(good, builtin) is True
    assert judge(good, {"security_options": ["name=seccomp,profile=default"]}) is True
    assert judge({**good, "denied": {**good["denied"], "add_key": "ok"}}, builtin) is False
    assert judge({**good, "denied": {**good["denied"], "unshare": "EINVAL"}}, builtin) is False
    assert judge(good, {"security_options": ["name=seccomp,profile=/custom.json"]}) is False
    assert judge(good, {"security_options": []}) is False
    assert judge({**good, "Seccomp": "0"}, builtin) is False
    assert judge({**good, "Seccomp_filters": "0"}, builtin) is False
    assert judge({**good, "NoNewPrivs": "0"}, builtin) is False
    assert judge({**good, "denied": {}}, builtin) is False


# ---------- DAO-005 (4): AC-002F-11b v1.3.3 — "network disabled" (P-01)
ZERO = "0000000000000000"
# Evidence shaped like Docker Desktop 4.87 / LinuxKit arm64 under `--network none` (fallback tunnel devices
# present, administratively down, without addresses or routes).
P01_GOOD = {
    "ifaces": {
        "erspan0": "0x1002",
        "gre0": "0x80",
        "gretap0": "0x1002",
        "ip6tnl0": "0x80",
        "lo": "0x9",
        "sit0": "0x80",
        "tunl0": "0x80",
    },
    "v4": [],
    "v6": [],
    "route4": [],
    "route6": [],
    "CapEff": ZERO,
    "CapBnd": ZERO,
    "connect": "ENETUNREACH",
    "dns": "failed",
}
P01_CONFIG = {"host": {"NetworkMode": "none", "CapDrop": ["ALL"]}, "networks": ["none"]}


def test_dao005_p01_network_disabled_judge():
    judge = mod("conformance").network_ok
    assert judge(P01_GOOD, P01_CONFIG) is True
    assert judge({**P01_GOOD, "ifaces": {"lo": "0x9"}}, P01_CONFIG) is True
    assert judge({**P01_GOOD, "ifaces": {**P01_GOOD["ifaces"], "lo": "0x8"}}, P01_CONFIG) is True
    bad_notes = [
        {"ifaces": {**P01_GOOD["ifaces"], "eth0": "0x1003"}},
        {"ifaces": {**P01_GOOD["ifaces"], "gre0": "0x81"}},
        {"ifaces": {**P01_GOOD["ifaces"], "gre0": "ENOENT"}},
        {"ifaces": {**P01_GOOD["ifaces"], "gre0": "EBADE"}},
        {"ifaces": {**P01_GOOD["ifaces"], "gre0": 128}},
        {"ifaces": {}},
        {"ifaces": None},
        {"v4": ["172.17.0.2"]},
        {"v4": "EACCES"},
        {"v6": ["eth0"]},
        {"v6": "EACCES"},
        {"route4": ["eth0"]},
        {"route4": "ENOENT"},
        {"route6": ["eth0"]},
        {"route6": None},
        {"CapEff": "0000000000003000"},
        {"CapBnd": "00000000a80425fb"},
        {"CapEff": None},
        {"connect": "connected"},
        {"connect": None},
        {"dns": "resolved"},
        {"dns": None},
    ]
    for change in bad_notes:
        assert judge({**P01_GOOD, **change}, P01_CONFIG) is False, change
    for key in P01_GOOD:
        assert judge({k: v for k, v in P01_GOOD.items() if k != key}, P01_CONFIG) is False, key
    bad_configs = [
        None,
        {},
        {"host": {"NetworkMode": "bridge", "CapDrop": ["ALL"]}, "networks": ["none"]},
        {"host": {"NetworkMode": "none", "CapDrop": ["ALL"]}, "networks": ["bridge"]},
        {"host": {"NetworkMode": "none", "CapDrop": []}, "networks": ["none"]},
        {"host": {"NetworkMode": "none", "CapDrop": ["NET_RAW"]}, "networks": ["none"]},
    ]
    for config in bad_configs:
        assert judge(P01_GOOD, config) is False, config


def _probe_namespace() -> dict:
    """The probe source is a data file run only in the container; its pure parsers are loaded here with
    PROBE unset (no probe runs)."""
    namespace: dict = {"PROBE": ""}
    exec(compile(mod("conformance").SUITE.read_text(), "suite.probe", "exec"), namespace)  # noqa: S102
    return namespace


FIB_TRIE_LO = """Main:
  +-- 127.0.0.0/8 2 0 2
     +-- 127.0.0.0/31 1 0 0
        |-- 127.0.0.0
           /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
     |-- 127.255.255.255
        /32 link BROADCAST
Local:
  +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.1
           /32 host LOCAL
"""
FIB_TRIE_ETH = FIB_TRIE_LO + """  +-- 172.17.0.0/16 2 0 2
        |-- 172.17.0.0
           /16 link UNICAST
        |-- 172.17.0.2
           /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
"""
IF_INET6_LO = "00000000000000000000000000000001 01 80 10 80       lo\n"
IF_INET6_ETH = IF_INET6_LO + "fe800000000000000042acfffe110002 0b 40 20 80     eth0\n"
ROUTE_EMPTY = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
ROUTE_ETH = ROUTE_EMPTY + "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
V6_LO = (
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
    "00000000000000000000000000000001 80 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo\n"
)
V6_ETH = V6_LO + (
    "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
)


def test_dao005_p01_probe_parsers():
    ns = _probe_namespace()
    assert ns["v4_local"](FIB_TRIE_LO) == [] and ns["v4_local"](FIB_TRIE_ETH) == ["172.17.0.2"]
    assert ns["v6_devs"](IF_INET6_LO) == [] and ns["v6_devs"](IF_INET6_ETH) == ["eth0"]
    assert ns["route4_devs"](ROUTE_EMPTY) == [] and ns["route4_devs"](ROUTE_ETH) == ["eth0"]
    assert ns["route6_devs"](V6_LO) == [] and ns["route6_devs"](V6_ETH) == ["eth0"]


def test_dao005_p02_shared_memory_not_writable():
    judge = mod("conformance").readonly_ok
    good = {p: "EROFS" for p in ("/usr/x", "/input/x", "/helper/x", "/x")} | {"/dev/shm/x": "ENOENT"}
    assert judge(good) is True
    assert judge({**good, "/dev/shm/x": "EACCES"}) is True
    assert judge({**good, "/dev/shm/x": "written"}) is False
    assert judge({**good, "/usr/x": "ENOENT"}) is False
    assert judge({k: v for k, v in good.items() if k != "/dev/shm/x"}) is False
    assert judge({}) is False
