"""No toolkit network and no model/credential option (FEATURE-001-G, AC-001G-05a, NFR-001G-1/2; Step 12)."""

from __future__ import annotations

import ast
import json
import re

import pytest
from conftest import SRC, TOOLKIT_ROOT, run_cli
from drafthelp import HOST, R89, DEnv

FORBIDDEN_IMPORTS = {
    "socket",
    "urllib",
    "http",
    "subprocess",
    "importlib",
    "requests",
    "ssl",
    "ftplib",
    "smtplib",
    "asyncio",
    "ctypes",
    "multiprocessing",
}
OPTION_WORDS = re.compile(r"model|endpoint|key|token|credential|api|secret|password|url", re.I)
COMMANDS = ("draft-check", "draft-approve", "supplements", "drafting-authorize")


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


def run(env, args, blocked):
    process = run_cli([*args, "--json"], env.trust, extra=("--block-network",) if blocked else ())
    return process.returncode, json.loads(process.stdout)


# AC-001G-05a: every 001-G command works with socket creation blocked; no model/credential option.
def test_05a_commands_work_with_sockets_blocked_no_model_options(env):
    draft, review = env.drafted()
    p = str(env.project)
    check = ["knowledge", "draft-check", "--project", p, "--draft", str(draft), "--review", str(review)]
    free, blocked = run(env, check, False), run(env, check, True)
    assert free == blocked and free[0] == 0
    for args in (
        ["knowledge", "supplements", "--project", p],
        ["knowledge", "drafting-authorize", "--project", p, "--list"],
        ["knowledge", "drafting-authorize", "--project", p, "--host", HOST],
    ):
        assert run(env, args, False) == run(env, args, True)
    code, approved = run(
        env,
        [
            "knowledge",
            "draft-approve",
            "--project",
            p,
            "--draft",
            str(draft),
            "--review",
            str(review),
            "--validation-digest",
            blocked[1]["data"]["validation_digest"],
        ],
        True,
    )
    assert code == 0 and approved["ok"], approved
    code, listed = run(env, ["knowledge", "supplements", "--project", p, "--rule", R89], True)
    assert code == 0 and len(listed["data"]["supplements"]) == 1
    for command in COMMANDS:
        helped = run_cli(["knowledge", command, "--help"], env.trust)
        options = re.findall(r"(?m)^\s+(--[a-z-]+)", helped.stdout)
        assert options and not [o for o in options if OPTION_WORDS.search(o)], (command, options)
    contract = (TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework/references/cli-contract.md").read_text(
        "utf-8"
    )
    rows = [
        line
        for line in contract.splitlines()
        if any(f"`secure-code knowledge {c}`" in line for c in COMMANDS)
    ]
    assert len(rows) == 4
    for row in rows:
        args = row.split("|")[2]
        assert not [o for o in re.findall(r"--[a-z-]+", args) if OPTION_WORDS.search(o)], row


# NFR-001G-1 static scan: drafting modules import no network/process/dynamic-import module and call no
# exec/eval/compile.
def test_static_import_scan_of_drafting_modules():
    modules = sorted((SRC / "x_ipe_secure_code" / "knowledge").glob("drafting_*.py"))
    assert len(modules) == 9
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                names = []
            assert not [n for n in names if n.split(".")[0] in FORBIDDEN_IMPORTS], (path.name, names)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("exec", "eval", "compile", "__import__"), (
                    path.name,
                    node.func.id,
                )
