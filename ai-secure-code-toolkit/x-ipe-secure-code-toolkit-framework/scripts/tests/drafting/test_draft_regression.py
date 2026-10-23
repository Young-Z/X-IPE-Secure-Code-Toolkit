"""Preservation of delivered behaviour and approved-example regression (FEATURE-001-G, AC-001G-08a…08g).

Stop rule (BR-15): if any of these needed a delivered test or output to change, delivery stops and a
human CR is raised. Goldens in `fixtures/pre_001g/` were captured with the delivered code before any
FEATURE-001-G change (design Implementation Step 0).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil

import pytest
from conftest import TOOLKIT_ROOT
from drafthelp import (
    A03,
    DRAFTS,
    FIXTURES,
    JAVA,
    NEW_PAYLOAD,
    NEW_REFERENCE,
    NOTICE,
    PY,
    R78,
    R89,
    DEnv,
    fixture_items,
    mod,
    normalise,
    pre_001g_outputs,
)
from presets.presethelp import PEnv

from x_ipe_secure_code.knowledge import exit as exits
from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import service as policy

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DOC = "sha256:" + "e" * 64


@pytest.fixture
def env(project, tmp_path):
    return DEnv(project, tmp_path)


def approve_java(env):
    draft, review = env.drafted(examples={"java": dict(JAVA)}, name="cwe-89--java")
    result = env.checked_approve(draft, review)
    assert result.ok, result.to_dict()
    return env.rule_files()["example-java.md"].decode()


# AC-001G-08a: delivered suites unchanged; delivered outputs equal the pre-001-G goldens.
def test_08a_delivered_suites_unchanged_and_outputs_equal_pre_001g(tmp_path):
    recorded = json.loads((FIXTURES / "delivered_tests_001abcdf.json").read_text(encoding="utf-8"))
    tests = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework/scripts/tests"
    changed = [
        rel
        for rel, digest in recorded.items()
        if hashlib.sha256((tests / rel).read_bytes()).hexdigest() != digest
    ]
    assert changed == [], (
        f"Delivered 001-A/B/C/D/F test files changed since FEATURE-001-G step 0: {changed}. "
        "Maintenance point (DAO-004 DEC-I13): if the change is legitimate and approved, update "
        "tests/drafting/fixtures/delivered_tests_001abcdf.json with the new SHA-256; otherwise this is a "
        "stop-rule regression (BR-15)."
    )
    removed: list[str] = []
    (tmp_path / "golden").mkdir()
    outputs = pre_001g_outputs(tmp_path / "golden", removed)
    golden = {p.name: p.read_text(encoding="utf-8") for p in sorted((FIXTURES / "pre_001g").iterdir())}
    assert set(outputs) == set(golden)
    for name, text in outputs.items():
        assert text + "\n" == golden[name], name
    suffixes = sorted(p.split("x-ipe-secure-code-toolkit-framework/", 1)[1] for p in removed)
    assert suffixes == sorted([f"scripts/src/x_ipe_secure_code/{p}" for p in NEW_PAYLOAD] + [NEW_REFERENCE])


# AC-001G-08b: results equal those of the same project without the drafts folder (a byte copy taken
# before the drafts were written).
def test_08b_with_and_without_drafts_folder_equal(env, tmp_path):
    saved = env.save(env.decisions((R89, R78)))
    scope_id = saved.data["scope_id"]
    twin = tmp_path / "twin"
    shutil.copytree(env.project, twin, symlinks=True)
    draft, review = env.drafted()
    env.drafted(examples={"java": dict(JAVA)}, name="second")
    assert env.check(draft, review).ok and not (twin / DRAFTS).exists()

    def outputs(root):
        p = str(root)
        result = {
            name: env.cli(*args)
            for name, args in (
                ("resolve", ["policy", "resolve", "--project", p, "--rule", R89, "--rule", R78]),
                ("scope", ["scope", "show", "--project", p, "--scope", scope_id]),
                ("links", ["knowledge", "links", "--project", p]),
                (
                    "exit",
                    [
                        "knowledge",
                        "exit-preview",
                        "--project",
                        p,
                        "--rule",
                        R89,
                        "--action",
                        "deactivate",
                        "--reason",
                        "fixture reason",
                    ],
                ),
            )
        }
        result["guard_policy_load"] = policy.load_adopted(root, scope_id, "guard open")
        request = env.req(
            {
                "schema": "ai-secure-code-toolkit/guard-open/v1",
                "scope_id": scope_id,
                "targets": [{"path": "src/entry.py", "change": "modified"}],
            }
        )
        (root / "src").mkdir(exist_ok=True)
        (root / "src/entry.py").write_text("def entry(value):\n    return value\n")
        result["guard_open"] = env.cli("guard", "open", "--project", p, "--request", request)
        text = json.dumps(result, sort_keys=True, ensure_ascii=False).replace(p, "<root>")
        return normalise(text)

    assert outputs(env.project) == outputs(twin)


# AC-001G-08c: requirement byte-identical; examples differ only by the added key; other fields equal
# except state_digest and last_changed_at.
def test_08c_requirement_identical_examples_key_only(env):
    def policy_of():
        result = policy.resolve_policies(str(env.project), [R89], False, ["python"])
        return next(e for e in result.data["entries"] if e["rule"] == R89)

    before = policy_of()
    approve_java(env)
    after = policy_of()
    assert after["requirement"] == before["requirement"]
    assert after["examples"] == sorted(before["examples"] + ["java"])
    for entry in (before, after):
        entry.pop("examples")
        entry["source_evidence"].pop("state_digest")
        entry["source_evidence"].pop("last_changed_at")
    assert after == before


# AC-001G-08d: Guard/Copilot Policy inputs carry no supplement bytes; their skill packages are unchanged.
def test_08d_guard_copilot_inputs_lack_block_bytes_skills_unchanged(env):
    saved = env.save(env.decisions((R89, A03)))
    text = approve_java(env)
    resaved = env.save(env.decisions((R89, A03)))
    assert saved.ok and resaved.ok
    block_lines = [
        ln
        for ln in text.splitlines()[
            text.splitlines().index(next(ln for ln in text.splitlines() if "x-ipe-ai-supplement" in ln)) :
        ]
        if ln.strip()
    ]
    loaded = json.dumps(
        policy.load_adopted(env.project, resaved.data["scope_id"], "guard open"), ensure_ascii=False
    )
    resolved = env.cli("policy", "resolve", "--project", str(env.project), "--rule", R89)[1]
    guard_id, copilot_id = env.open_runs(resaved.data["scope_id"])
    records = "".join(
        p.read_text(encoding="utf-8", errors="replace")
        for root in (".x-ipe/private/secure-code/guard", ".x-ipe/private/secure-code/copilot")
        for p in (env.project / root).rglob("*")
        if p.is_file()
    )
    for haystack in (loaded, json.dumps(resolved, ensure_ascii=False), records):
        for line in block_lines + [NOTICE, "x-ipe-ai-supplement"]:
            assert line not in haystack, line
    assert guard_id and copilot_id
    recorded = json.loads((FIXTURES / "guard_copilot_hashes.json").read_text(encoding="utf-8"))
    changed = [
        rel
        for rel, digest in recorded.items()
        if hashlib.sha256((TOOLKIT_ROOT / rel).read_bytes()).hexdigest() != digest
    ]
    assert changed == [], (
        f"Guard/Copilot skill files changed since FEATURE-001-G step 0: {changed}. "
        "Maintenance point (DAO-004 DEC-I13): if the change is legitimate and approved, update "
        "tests/drafting/fixtures/guard_copilot_hashes.json with the new SHA-256; AC-001G-08d only requires "
        "that FEATURE-001-G itself never changes them."
    )


# AC-001G-08e: item and state digests are exactly the delivered computation of the new files.
def test_08e_item_and_state_digest_recomputed(env):
    approve_java(env)
    stored = store.read_rule(env.project, mod("drafting_model").RuleRef.parse(R89))
    recomputed = store.item_from(stored.ref, stored.record, dict(stored.files)).digest()
    assert recomputed == stored.record["item_digest"] == stored.digest
    assert env.state() == store.revision_digest(recomputed, store.lifecycle_state(stored.record)[1])


# AC-001G-08f: the delivered `knowledge check` reports stored_changed / not_fully_stored after approval.
def test_08f_check_stored_changed_not_fully_stored(project, tmp_path):
    env = DEnv(project, tmp_path, seed=False)
    items = [dict(i, source_document_digest=DOC) for i in fixture_items("seed_batch.json")]
    assert env.load(*items).ok
    batch_digests = {i["rule"]: i["item_digest"] for i in env.load(*items).data["items"]}
    check = env.req(
        {
            "schema": "ai-secure-code-toolkit/knowledge-check/v1",
            "items": [{"rule": r, "item_digest": d} for r, d in batch_digests.items()],
            "source_documents": [DOC],
        }
    )
    from x_ipe_secure_code.knowledge import service as knowledge

    first = knowledge.check(str(env.project), check)
    assert (
        first.data["items"][R89] == "stored_unchanged"
        and first.data["source_documents"][DOC] == "fully_stored"
    )
    assert env.checked_approve(*env.drafted()).ok
    after = knowledge.check(str(env.project), check)
    assert after.data["items"][R89] == "stored_changed"
    assert after.data["items"][R78] == "stored_unchanged"
    assert after.data["source_documents"][DOC] == "not_fully_stored"


# AC-001G-08g: Presets/tags and their exit impact are unchanged apart from digests.
class PDEnv(DEnv, PEnv):
    pass


def test_08g_exit_preview_impact_equal_preset_tag_files_unchanged(project, tmp_path):
    env = PDEnv(project, tmp_path)
    assert env.psave("web-input", (R89, R78)).ok
    assert env.tsave("injection", (R89,)).ok
    files = {p: p.read_bytes() for p in (env.preset_file("web-input"), env.tag_file("injection"))}

    def impact():
        preview = exits.preview(
            str(env.project), R89, "deactivate", None, "fixture reason", trust_paths=env.paths
        )
        assert preview.ok, preview.to_dict()
        return json.loads(DIGEST.sub("<digest>", json.dumps(preview.data["impact"], sort_keys=True)))

    before = impact()
    assert env.checked_approve(*env.drafted()).ok
    assert impact() == before
    assert "web-input" in json.dumps(before) and "injection" in json.dumps(before)
    assert {p: p.read_bytes() for p in files} == files
    assert PY
