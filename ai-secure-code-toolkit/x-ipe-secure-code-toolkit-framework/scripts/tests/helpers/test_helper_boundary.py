"""FEATURE-002-F boundary regression (DAO-014/017 TD): runs without helpers are byte-identical to the
delivered outputs captured at step 0, no delivered fixture uses the reserved prefixes, the engine edit
is the `_relevant_paths` helper branch only and the changed delivered files equal the closed list (§1.1).
"""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import hashlib
import inspect
import json
import re

import boundaryhelp
from conftest import SCRIPTS, TOOLKIT_ROOT
from helperhelp import env  # noqa: F401 - fixture reuse

GOLDEN = boundaryhelp.FIXTURES
FW = "x-ipe-secure-code-toolkit-framework"
CLOSED_LIST = {
    f"{FW}/scripts/src/x_ipe_secure_code/adapters/__init__.py",
    f"{FW}/scripts/src/x_ipe_secure_code/guard/records.py",
    f"{FW}/scripts/src/x_ipe_secure_code/guard/engine.py",
    f"{FW}/scripts/src/x_ipe_secure_code/guard/service.py",
    f"{FW}/scripts/src/x_ipe_secure_code/guard/cancel.py",
    f"{FW}/scripts/src/x_ipe_secure_code/guard/report.py",
    f"{FW}/scripts/src/x_ipe_secure_code/cli.py",
    f"{FW}/scripts/src/x_ipe_secure_code/tools_service.py",
    "x-ipe-secure-code-toolkit-guard/SKILL.md",
    "x-ipe-secure-code-toolkit-guard/references/guard-records.md",
    f"{FW}/scripts/tests/carriers/carhelp.py",
    # Maintenance points ruled by DAO-005 (code implementation; DAO-023/024 precedent).
    f"{FW}/scripts/tests/guard/test_compare_skill.py",
    f"{FW}/scripts/tests/drafting/drafthelp.py",
    f"{FW}/scripts/tests/drafting/fixtures/guard_copilot_hashes.json",
}


def _outputs(env):
    current = boundaryhelp.delivered_outputs(env)
    golden = {p.name: p.read_text(encoding="utf-8") for p in sorted(GOLDEN.iterdir())}
    assert set(current) == set(golden)
    return current, golden


def _compare(current, golden, prefix):
    names = [n for n in golden if n.startswith(prefix)]
    assert names
    for name in names:
        assert current[name] + "\n" == golden[name], name


def test_show_and_conclude_json_md_byte_identical_without_helpers(env):  # noqa: F811
    current, golden = _outputs(env)
    for prefix in ("a-", "b-", "f-conclude", "f-result", "f-report"):
        _compare(current, golden, prefix)


def test_cancel_finalize_byte_identical_without_helpers(env):  # noqa: F811
    current, golden = _outputs(env)
    _compare(current, golden, "c-")


def test_plan_and_record_validation_outputs_byte_identical(env):  # noqa: F811
    current, golden = _outputs(env)
    for prefix in ("d-", "e-", "f-review"):
        _compare(current, golden, prefix)


HELPER_PREFIX = re.compile(r"[\"'](?:helper\.[A-Za-z0-9]|helper-)", re.I)


def test_no_delivered_fixture_uses_helper_prefixes():
    """No delivered test input or fixture uses `helper.`/`helper-` names (DAO-017 condition 3)."""
    baseline = json.loads((GOLDEN.parent / "delivered_step0.json").read_text(encoding="utf-8"))
    tests = [p for p in baseline if p.startswith(f"{FW}/scripts/tests/")]
    assert len(tests) > 100
    hits = []
    for rel in tests:
        text = (TOOLKIT_ROOT / rel).read_bytes().decode("utf-8", "replace")
        for match in HELPER_PREFIX.finditer(text):
            hits.append(f"{rel}: {text[match.start() : match.start() + 30]!r}")
    allowed = {"tests/guard/test_guard_budget_helpers.py"}  # CR-TASK-077 seeds `h-1` ids, never `helper-`
    assert [h for h in hits if not any(a in h for a in allowed)] == []


def test_relevant_paths_helper_branch_only():
    from x_ipe_secure_code.guard import engine

    source = inspect.getsource(engine._relevant_paths)
    assert 'subject["type"] == "helper"' in source
    state = {
        "artifact": {
            "targets": [{"path": "src", "kind": "dir", "digest": "sha256:" + "1" * 64}],
            "context": [],
            "copilot_reports": [],
        },
        "helpers": [{"id": "h-1-aaaaaaaa", "read_scope": ["src/config", "src/config/app.yaml"]}],
        "findings": [],
        "plan": {"checks": [{"id": "C1", "object": ["src/config"]}]},
    }
    assert engine._relevant_paths(state, {"type": "helper", "id": "h-1-aaaaaaaa"}) == ["src"]
    assert engine._relevant_paths(state, {"type": "na_decision", "id": "C1"}) == ["src"]
    assert list(inspect.signature(engine._judge_review).parameters) == ["state", "review", "current"]


def test_closed_list_diff():
    """Changed delivered files stay within the closed list of design §1.1 plus the DAO-005 maintenance
    points; none removed."""
    baseline = json.loads((GOLDEN.parent / "delivered_step0.json").read_text(encoding="utf-8"))
    changed, removed = set(), []
    for rel, digest in baseline.items():
        path = TOOLKIT_ROOT / rel
        if not path.is_file():
            removed.append(rel)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            changed.add(rel)
    assert removed == []
    assert changed <= CLOSED_LIST, sorted(changed - CLOSED_LIST)
    engine_rel = f"{FW}/scripts/src/x_ipe_secure_code/guard/engine.py"
    engine_now = (SCRIPTS / "src/x_ipe_secure_code/guard/engine.py").read_text(encoding="utf-8")
    without = engine_now.replace(ENGINE_BRANCH, "", 1)
    assert hashlib.sha256(without.encode("utf-8")).hexdigest() == baseline[engine_rel]


ENGINE_BRANCH = (
    '    elif subject["type"] == "helper":  # FEATURE-002-F: bound to the read scope\'s owning targets\n'
    '        helper = next((h for h in state.get("helpers") or [] if h.get("id") == subject["id"]), {})\n'
    '        paths = [owning_target(artifact, p) for p in helper.get("read_scope") or []]\n'
)
