"""B14 = No binding evidence (FEATURE-001-G, DAO-013 DEC-6 conditions; static, no AC).

No drafting test, helper or fixture names the internal policy namespace, its source list or a path
into the repository's sample-project folder, and every recording form of `drafting-authorize` in
the drafting tests targets a disposable test project. Forbidden tokens are assembled at runtime so
this file does not contain them either.
"""

from __future__ import annotations

import re
from pathlib import Path

from conftest import SRC, TOOLKIT_ROOT

HERE = Path(__file__).resolve().parent
INTERNAL = "CC" + "ISO"
FORBIDDEN = ("@" + INTERNAL, "SOURCES-" + INTERNAL, INTERNAL.lower() + "-sds", "de" + "mo/", "de" + "mo\\")
PRODUCT = [
    *sorted((SRC / "x_ipe_secure_code" / "knowledge").glob("drafting_*.py")),
    TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework/references/knowledge-drafting.md",
]


def drafting_files() -> list[Path]:
    return sorted(p for p in HERE.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_no_internal_namespace_or_sample_project_reference_in_tests_or_product():
    files = drafting_files() + PRODUCT
    assert len(files) > 20
    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        for token in FORBIDDEN:
            assert token.lower() not in text, (path.name, "forbidden token")
        assert INTERNAL.lower() not in text, path.name


def test_drafting_authorize_recording_only_against_test_projects():
    calls = 0
    for path in HERE.glob("test_*.py"):
        if path.name == Path(__file__).name:
            continue
        if path.name == "test_draft_skill.py":  # ledger data only: never executes a command
            text = path.read_text(encoding="utf-8")
            assert not re.search(r"run_cli\(|run_pty\(|\.cli\(|drafting_auth", text)
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if '"knowledge", "drafting-authorize"' not in line:
                continue
            calls += 1
            window = " ".join(lines[index : index + 2])
            assert re.search(r'"--project", (p\b|str\(env\.project\))', window), (path.name, index + 1)
            assert "--host" not in window or re.search(r'"--host", (HOST|"fixture-host")', window), (
                path.name,
                index + 1,
            )
        for match in re.finditer(r"\bauthorize\(\s*([^,)]+)", path.read_text(encoding="utf-8")):
            assert match.group(1).strip() in ("env", "self", "str(env.project"), (path.name, match.group(0))
    assert calls >= 5


def test_every_drafted_host_label_is_a_fixture_label():
    labels = set()
    for path in drafting_files():
        if path.suffix in (".py", ".json"):
            labels |= set(re.findall(r'"host":\s*"([^"]+)"', path.read_text(encoding="utf-8")))
    assert labels <= {"fixture-host", "other-host", "h", "Bad Host", "<hostname>"}, labels
