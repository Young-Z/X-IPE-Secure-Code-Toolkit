"""FEATURE-002-F static checks (AC-002F-02d, 02f; FR-002F-3; design §5.3 incl. review M3).

Modules are imported at Act so the tests fail for the right reason before the implementation exists.
"""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import importlib

import pytest

V312 = (3, 12, 4)


def static():
    return importlib.import_module("x_ipe_secure_code.guard.helpers.static")


def check(text: str, version=V312):
    return static().check(text.encode("utf-8"), version)


def rule_of(text: str, version=V312):
    out = check(text, version)
    return None if out is None else out.rule


GOOD = (
    "import json\n"
    "import re\n"
    "from pathlib import Path\n"
    "found = []\n"
    "for p in sorted(Path('/input').rglob('*.yaml')):\n"
    "    if re.search(r'debug: true', p.read_text(encoding='utf-8', errors='replace')):\n"
    "        found.append(p)\n"
    "with open('/results/result.json', 'w', encoding='utf-8') as out:\n"
    "    json.dump({'findings': [str(p) for p in found]}, out)\n"
)


def test_m3_allowed_result_forms():
    assert check(GOOD) is None
    write_form = (
        "import json\nwith open('/results/result.json', mode='w') as res:\n    res.write(json.dumps({}))\n"
    )
    assert check(write_form) is None
    reads = (
        "from pathlib import Path\nwith Path('/input/a').open() as f:\n    data = f.read()\n"
        "x = open('/input/b', 'rb')\n"
    )
    assert check(reads) is None


# ---------- AC-002F-02d: each rule refused with its name (deny list asserted explicitly)
DENIED_MODULES = (
    "os sys subprocess ctypes socket ssl http urllib ftplib smtplib asyncio multiprocessing threading "
    "concurrent signal importlib builtins pickle marshal shelve shutil tempfile mmap fcntl resource pty "
    "code codeop runpy inspect gc site sysconfig platform webbrowser"
).split()


@pytest.mark.parametrize("module", DENIED_MODULES)
def test_02d_denied_modules(module):
    assert rule_of(f"import {module}\n") == "import_denied"
    assert rule_of(f"from {module} import x\n") == "import_denied"


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("from json import *\n", "import_star"),
        ("from . import x\n", "import_relative"),
        ("import os.path\n", "import_denied"),
        ("from xml import etree\n", "import_denied"),
        ("from xml.etree import cElementTree\n", "import_denied"),
        ("import xml.etree.ElementTree.x\n", "import_denied"),
        ("x = eval('1')\n", "name_denied"),
        ("x = exec\n", "name_denied"),
        ("import json\njson.compile\n", "name_denied"),
        ("from json import loads as getattr\n", "name_denied"),
        ("x = memoryview(b'')\n", "name_denied"),
        ("x = (1).__class__\n", "dunder"),
        ("if __name__ == '__main__':\n    pass\n", "dunder"),
        ("def __init__():\n    pass\n", "dunder"),
        ("def f(__x__=1):\n    pass\n", "dunder"),
        ("f = open\n", "open_alias"),
        ("import functools\ng = functools.partial(open, '/tmp/x', 'w')\n", "open_alias"),
        ("x = list(map(open, ['a']))\n", "open_alias"),
        ("from pathlib import Path\nm = Path('a').open\nm('w')\n", "open_alias"),
        ("x = open('/tmp/x', 'w')\n", "open_form"),
        ("x = open('/results/result.json', 'w')\n", "open_form"),
        ("m = 'w'\nx = open('/input/a', m)\n", "open_form"),
        ("a = ['/x', 'r']\nx = open(*a)\n", "open_form"),
        ("import io\nx = io.open('/x')\n", "open_form"),
        ("from pathlib import Path\nx = Path('a').open('w')\n", "open_form"),
        ("from pathlib import Path\nPath('/tmp/x').write_text('x')\n", "write_attribute"),
        ("from pathlib import Path\nw = Path('/tmp/x').write_text\nw('x')\n", "write_attribute"),
        ("from pathlib import Path\nPath('/input/a').unlink()\n", "write_attribute"),
        ("from pathlib import Path\nPath('/tmp/d').mkdir()\n", "write_attribute"),
        ("from pathlib import Path\nPath('/tmp/d').touch()\n", "write_attribute"),
        ("from pathlib import Path\nPath('/tmp/d').symlink_to('/x')\n", "write_attribute"),
        (
            "import xml.etree.ElementTree as ET\nET.ElementTree(ET.Element('a')).write('/tmp/x')\n",
            "write_attribute",
        ),
        (
            "import configparser\ncfg = configparser.ConfigParser()\n"
            "with open('/input/a') as f:\n    cfg.write(f)\n",
            "write_attribute",
        ),
        ("import io\nb = io.FileIO('/tmp/x', 'w')\n", "write_attribute"),
        ("import csv\nwith open('/input/a') as f:\n    csv.writer(f).writerows([])\n", "write_attribute"),
        (
            "import json\nwith open('/results/result.json', 'w') as f:\n    g = f\n    g.write('x')\n",
            "results_handle",
        ),
        (
            "import json\nwith open('/results/result.json', 'w') as f:\n    print('x', file=f)\n",
            "results_handle",
        ),
        (
            "with open('/results/result.json', 'w') as f:\n    f.write('a')\n"
            "with open('/results/result.json', 'w') as g:\n    g.write('b')\n",
            "results_handle",
        ),
        ("with open('/results/result.json', 'w') as f:\n    f = 1\n", "results_handle"),
    ],
)
def test_02d_each_rule(text, rule):
    out = check(text)
    assert out is not None and out.rule == rule, (text, out)
    assert out.reason.startswith(f"static: {rule}:") and f"(line {out.line})" in out.reason


def test_02d_tomllib_only_for_311_and_later():
    assert rule_of("import tomllib\n", (3, 11, 0)) is None
    assert rule_of("import tomllib\n", (3, 10, 9)) == "import_denied"


def test_02d_first_violation_deterministic():
    text = "import os\nx = eval('1')\n"
    assert [check(text).reason for _ in range(3)] == [check(text).reason] * 3
    assert check(text).rule == "import_denied" and check(text).line == 1


def test_02d_unparseable_fail_closed():
    out = check("def f(:\n")
    assert out.step == "parse" and out.reason.startswith("parse: toolkit parser cannot parse (fail closed)")
    newer = check("x = 1\n", (3, 99, 0))
    assert newer.step == "parse" and "fail closed" in newer.reason
    match = check("match x:\n    case 1:\n        pass\n", (3, 9, 0))
    assert match.step == "parse"


def test_02d_credential_like_script_refused():
    token = "ghp_" + "c" * 36
    out = check(f"x = '{token}'\n")
    assert out.step == "credential" and "credential-like" in out.reason


# ---------- AC-002F-02f: L-03 / L-04 before compiling or rule checking
def test_02f_oversize_and_deep():
    big = check("x = 1\n" * 2001)
    assert big.step == "size" and "L-03" in big.reason
    huge = static().check(b"#" * (64 * 1024 + 1), V312)
    assert huge.step == "size"
    assert static().check(b"\xff\xfe", V312).step == "size"
    deep = check("x = " + "[" * 60 + "]" * 60 + "\n")
    assert deep.step == "ast_limits" and "L-04" in deep.reason
    nested = "x = [" + ",".join(["[1]"] * 9000) + "]\n"
    many = check(nested)
    assert many.step == "ast_limits" and "L-04" in many.reason
    depth_text = "".join("    " * i + f"if x{i}:\n" for i in range(55)) + "    " * 55 + "pass\n"
    assert check(depth_text).step == "ast_limits"
