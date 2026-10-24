"""FEATURE-001-E tests: isolation guarantees (AC-001E-01j production-path part, 08d, 08f, 08i)."""

from __future__ import annotations

import ast
import socket
import subprocess

import pytest
import refhelp
from conftest import SCRIPTS
from netguard import GUARD, GuardViolation, network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CWE79,
    LOCAL,
    mod,
    page,
)

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures

SRC = SCRIPTS / "src" / "x_ipe_secure_code"
REFERENCE = SRC / "reference"
EGRESS = SRC / "guard" / "egress.py"
RESOLVERS = {"getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo", "getfqdn"}


def names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            found.update(a.name for a in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module)
    return found


def p6_block():
    text = EGRESS.read_text(encoding="utf-8")
    return text.split("# --- P6 GET path (FEATURE-001-E, additive) ---", 1)[1].split(
        "# --- end P6 GET path ---"
    )[0]


# AC-001E-01j (production path) / 01m
def test_validator_unreachable_from_fetch_path():
    assert "public_unicast" not in names(REFERENCE / "fetch.py")
    assert "public_unicast" not in p6_block()
    for path in [*REFERENCE.glob("*.py")]:
        assert not (names(path) & RESOLVERS), path
    assert not any(r in p6_block() for r in RESOLVERS)
    assert "ipaddress" not in names(REFERENCE / "fetch.py")


# AC-001E-08d
def test_cache_never_becomes_knowledge(renv, clock):
    renv.standard(CWE79)
    renv.serve("/docs/cwe/79.html", page("cwe-79.html"))
    local = renv.project / "x-ipe-docs/secure-code/knowledge/local"
    before = {p: p.read_bytes() for p in local.rglob("*") if p.is_file()}
    vid = renv.granted()
    assert renv.fetch(vid).ok
    renv.save_scope(LOCAL, CWE79)
    assert renv.service.list_references(str(renv.project)).ok
    assert renv.service.cache_clean(str(renv.project)).ok
    assert {p: p.read_bytes() for p in local.rglob("*") if p.is_file()} == before
    assert not (local / "CWE").exists()
    for module in ("service.py", "batch.py", "store.py"):
        tree = ast.parse((SRC / "knowledge" / module).read_text(encoding="utf-8"))
        imported = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imported += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        assert not any("reference" in m for m in imported), module


# AC-001E-08f
def test_suite_guards_active(renv):
    with pytest.raises(GuardViolation):
        socket.getaddrinfo("example.test", 443)
    with pytest.raises(GuardViolation):
        socket.gethostbyname("example.test")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(GuardViolation):
            probe.connect(("10.0.0.1", 80))
    finally:
        probe.close()
    fetch = mod("reference.fetch")

    def spawn():
        subprocess.Popen(["true"])

    code = compile("spawn()", fetch.__file__, "exec")
    with pytest.raises(GuardViolation):
        exec(code, {"spawn": spawn, "__name__": "x_ipe_secure_code.reference.fetch"})
    assert GUARD["resolver"] and GUARD["refused_connects"] == [("10.0.0.1", 80)]
    assert GUARD["subprocess"] == ["Popen"]
    for key in GUARD:
        GUARD[key].clear()


# AC-001E-08i
def test_no_injection_surfaces(renv):
    cli = mod("cli")
    base = ["knowledge", "reference", "fetch", "--project", str(renv.project), "--run", "V", "--rule", CWE79]
    for extra in (
        ["--resolver", "8.8.8.8"],
        ["--opener", "x"],
        ["--clock", "x"],
        ["--allowlist", "10.0.0.1"],
        ["--fixture", "x"],
    ):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(base + extra)
    for path in [*REFERENCE.glob("*.py")]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("environ", "getenv", "putenv"), path
    block = p6_block()
    assert "environ" not in block and "getenv" not in block
    assert "os." not in block
    urls = mod("reference.urls")
    target = urls.Target("http://localhost:1/x", "http://localhost:1", "http", "localhost", 1, "/x", "/x")
    assert urls.transport_v1(target).reason == "real_fetch_parked"
