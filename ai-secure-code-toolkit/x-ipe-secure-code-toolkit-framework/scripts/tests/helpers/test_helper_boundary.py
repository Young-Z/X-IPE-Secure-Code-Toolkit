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

# maintenance: later features append their ruled delivered-file changes here (DAO-007 code implementation).
# A changed delivered file outside CLOSED_LIST is accepted only when its current SHA-256 equals the pinned,
# ruled hash; a file listed in BLOCK_PINNED is hashed with its delimited additive block removed.
LATER_FEATURE_CHANGES: dict[str, dict[str, str]] = {
    "FEATURE-001-E (DAO-007 code implementation)": {
        f"{FW}/SKILL.md":
            "774e642d9682ac5f4750399c80aec7f0f2dcdd48cad92b9ddac223aeea7dc91b",
        f"{FW}/references/cli-contract.md":
            "930fd035f451e920a9ad04623ae4304de2cfeaefcc7590b085a3e999417d7885",
        f"{FW}/references/presets-and-tags.md":
            "42dff964a2d5c3ae0222b6241e54d45d9ca8c375844e8bd9935c199068d9e7f4",
        f"{FW}/scripts/src/x_ipe_secure_code/cli.py":
            "f33ea766b59fd396af6cfba6c9939a1f7f32437d06795b9c9a41b776c32caf1f",
        f"{FW}/scripts/src/x_ipe_secure_code/guard/egress.py":
            "836f8b36a35b6418b354a467b1d53c96dfd288606b3bb4a9400d64afbc2ee7bc",
        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/catalog.py":
            "c81fa20db680198430f16717151e9fde8af01df89fa5816d09c8d35b3bf23742",
        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/exit.py":
            "91afb99e8b72fc0cb5561fc46ce2f74323ae3fa2fd51715be337aa9dc28218ca",
        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/impact.py":
            "6c18b768cbfbaf8794cec3d04c960ff4dda8fdecf0d746ce2640b437f62bd473",
        f"{FW}/scripts/src/x_ipe_secure_code/knowledge/presets.py":
            "7edc7a4c1eea470c361319bb05da509ea03bf4f0fbec43a34c3506825db72df5",
        f"{FW}/scripts/src/x_ipe_secure_code/policy/resolve.py":
            "4d90e5500f844a6e32a6af7fd2d9df1ee00326c97174c586c15ba3fd392fbd60",
        f"{FW}/scripts/src/x_ipe_secure_code/status.py":
            "b15b32184193ab034190fd3e627e0dc9a0b45aec8b4eddf40fcf2d3253002f42",
        f"{FW}/scripts/tests/carriers/carhelp.py":
            "770a0b9f0b9ecb56e7b0418cba146caa29ca3ba9e1d50f83b755b77c4b0e001d",
        f"{FW}/scripts/tests/drafting/drafthelp.py":
            "8a105fb80428bdeb0ffae426b1910241a7884f4b899c33368f08192618bb962a",
        f"{FW}/scripts/tests/drafting/fixtures/delivered_tests_001abcdf.json":
            "3d9a15eeb18a6a821e28c6049a7098c0b3a02e6a5d3f74e39099f57322b33987",
        f"{FW}/scripts/tests/drafting/fixtures/pre_001g/exit-preview.json":
            "7dd807cb04495cd6e0fb8d3e739ea31bb479e16040ca386547b4d8a3f7aa9cc7",
        f"{FW}/scripts/tests/drafting/fixtures/pre_001g/init.json":
            "2b376eb7343c39b2f7800f97be450af88b393d306dc73f2208ee716deb5bed88",
        f"{FW}/scripts/tests/knowledge/test_exit_preview.py":
            "c4b475ff2b46aaf499d13cb387798ad3c87c6bae334ad03ff81fcc6b49a69ef3",
        f"{FW}/scripts/tests/presets/test_preset_impact.py":
            "bf82f4c30e373d88555ffcebd8ebc27d236e1422bfea4458cc357dbad9c4e9de",
        f"{FW}/scripts/tests/presets/test_preset_skill.py":
            "447ed018799e246c460740f50e4e34aecaf3b13dd2edcada156b4df9104f3665",
        f"{FW}/scripts/tests/presets/test_tags.py":
            "572f6790dba5a1890e481f42077a68e8ed538d644f76c3ab95c1d00654ba0721",
    },
}
BLOCK_PINNED = {
    f"{FW}/scripts/src/x_ipe_secure_code/guard/egress.py": (
        "    # --- P6 GET path (FEATURE-001-E, additive) ---",
        "    # --- end P6 GET path ---",
    ),
}


def _later_digest(rel: str, raw: bytes) -> str:
    markers = BLOCK_PINNED.get(rel)
    if markers is not None:
        lines = raw.decode("utf-8").split("\n")
        if lines.count(markers[0]) == 1 and lines.count(markers[1]) == 1:
            start, end = lines.index(markers[0]), lines.index(markers[1])
            if start < end:
                raw = "\n".join(lines[:start] + lines[end + 1 :]).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


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
    approved = {rel: digest for ruled in LATER_FEATURE_CHANGES.values() for rel, digest in ruled.items()}
    # a pin wins over CLOSED_LIST: a pinned changed file must match its pin exactly
    off_pin = sorted(
        rel for rel in changed & set(approved)
        if _later_digest(rel, (TOOLKIT_ROOT / rel).read_bytes()) != approved[rel]
    )
    assert off_pin == [], off_pin
    assert changed - set(approved) <= CLOSED_LIST, sorted(changed - set(approved) - CLOSED_LIST)
    engine_rel = f"{FW}/scripts/src/x_ipe_secure_code/guard/engine.py"
    engine_now = (SCRIPTS / "src/x_ipe_secure_code/guard/engine.py").read_text(encoding="utf-8")
    without = engine_now.replace(ENGINE_BRANCH, "", 1)
    assert hashlib.sha256(without.encode("utf-8")).hexdigest() == baseline[engine_rel]


ENGINE_BRANCH = (
    '    elif subject["type"] == "helper":  # FEATURE-002-F: bound to the read scope\'s owning targets\n'
    '        helper = next((h for h in state.get("helpers") or [] if h.get("id") == subject["id"]), {})\n'
    '        paths = [owning_target(artifact, p) for p in helper.get("read_scope") or []]\n'
)
