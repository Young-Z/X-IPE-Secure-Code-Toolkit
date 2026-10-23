"""FEATURE-001-F Unit: identity slugs, selector detection, request loading, deterministic
serialization, membership validation and the query-never-executed guarantee.

AC-001F-02f, 02g, 02j (timeout equality), 03b, 08b. Modules are imported at Act.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest
from knowledge.exithelp import R1, R2, need_symlinks
from presethelp import PRESET_REQ, PEnv, mod

from x_ipe_secure_code import atomic
from x_ipe_secure_code.knowledge import durable
from x_ipe_secure_code.policy import resolve


def catalog():
    return mod("knowledge.catalog")


def refused_code(call, *args, **kwargs):
    error = catalog().CatalogError
    with pytest.raises(error) as caught:
        call(*args, **kwargs)
    assert caught.value.next_step, caught.value.message
    return caught.value.code, caught.value.message


# AC-001F-02g
@pytest.mark.parametrize("kind,name,reason", [
    ("preset", "CON", "reserved"),
    ("preset", "con", "reserved"),
    ("preset", "lpt1", "reserved"),
    ("tag", "com9", "reserved"),
    ("preset", "a/b", "separator"),
    ("tag", "a\\b", "separator"),
    ("preset", "My_Preset", "lowercase"),
    ("preset", "Web-Input", "lowercase"),
    ("preset", "", "lowercase"),
    ("preset", "-web", "lowercase"),
    ("tag", "x" * 65, "lowercase"),
    ("tag", "default", "default"),
    ("tag", "Default", "lowercase"),
])
def test_slug_rules(kind, name, reason):
    code, message = refused_code(catalog().check_slug, name, kind)
    assert code == "IDENTITY_INVALID"
    assert reason in message.lower()


@pytest.mark.parametrize("kind,name,becomes_default", [
    ("preset", "default", True), ("preset", "web-input", False), ("tag", "injection", False),
    ("preset", "a", False), ("tag", "a1-b2", False),
])
def test_slug_accepted(kind, name, becomes_default):
    assert catalog().check_slug(name, kind) is becomes_default


# AC-001F-01b (unit part of A2)
@pytest.mark.parametrize("text,dynamic", [
    ("injection", True), ("tag:injection", True), ("preset:web@sha256:" + "a" * 64, True),
    ("CWE/*", True), ("CWE/4.14/CWE-7?", True), ("CWE/4.14/CWE-79 or CWE-89", True),
    ("CWE/4.14/{CWE-79,CWE-89}", True), ("CWE/4.14/[CWE-79]", True), ("!CWE/4.14/CWE-79", True),
    ("CWE/4.14/CWE-79", False), ("CWE/CWE-79", False), ("@ACME/v1/A-1", False),
])
def test_dynamic_selector_detection(text, dynamic):
    assert catalog().is_dynamic(text) is dynamic


# AC-001F-02f
def test_empty_membership_refused():
    lib = resolve.Library({}, set())
    code, _ = refused_code(catalog().validated_members, lib, [])
    assert code == "MEMBERSHIP_EMPTY"


def test_empty_membership_refused_by_save(project, tmp_path):
    env = PEnv(project, tmp_path)
    env.rules()
    result = env.psave(rules=[])
    assert not result.ok and result.problems[0].code == "MEMBERSHIP_EMPTY", result.to_dict()
    assert not env.preset_file().exists()


# AC-001F-08b
def test_serialization_deterministic():
    c = catalog()
    first = c.preset_doc("web-input", [R2, R1, R1], "intent", "summary", "2026-10-23T13:41:11+08:00")
    second = c.preset_doc("web-input", [R1, R2], "intent", "summary", "2026-10-23T13:41:11+08:00")
    a, b = c.serialize(first), c.serialize(second)
    assert a == b
    assert a.endswith(b"\n")
    data = json.loads(a)
    assert list(data) == sorted(data)
    assert [r["rule"] for r in data["rules"]] == [R1, R2]
    assert data["rules"][0] == {"rule": R1, "source": "local"}
    tag_a = c.serialize(c.tag_doc("injection", [R2, R1]))
    tag_b = c.serialize(c.tag_doc("injection", [R1, R2]))
    assert tag_a == tag_b
    assert c.file_digest(a).startswith("sha256:") and len(c.file_digest(a)) == 71


def test_serialization_deterministic_across_saves(project, tmp_path, monkeypatch):
    presets = mod("knowledge.presets")
    monkeypatch.setattr(presets, "_now", lambda: "2026-10-23T13:41:11+08:00")
    env = PEnv(project, tmp_path)
    env.rules()
    assert env.psave("one", [R2, R1], query_intent="i", applicability_summary="s").ok
    assert env.psave("two", [R1, R2], query_intent="i", applicability_summary="s").ok
    one = env.preset_file("one").read_bytes()
    two = env.preset_file("two").read_bytes()
    assert one.replace(b'"one"', b'"two"') == two


# Request files (REQUEST_INVALID) — Storage Formats / CLI Contract
@pytest.mark.parametrize("case", [
    "absent", "folder", "link", "too_big", "not_json", "not_object", "schema", "unknown_key",
    "long_text", "not_utf8",
])
def test_request_loader_refuses_bad_files(tmp_path, case):
    path = tmp_path / "req.json"
    good = {"schema": PRESET_REQ, "name": "web-input", "rules": [R1]}
    if case == "folder":
        path.mkdir()
    elif case == "link":
        need_symlinks(tmp_path)
        (tmp_path / "real.json").write_text(json.dumps(good))
        path.symlink_to(tmp_path / "real.json")
    elif case == "too_big":
        path.write_text(json.dumps({**good, "query_intent": "x" * (1024 * 1024)}))
    elif case == "not_json":
        path.write_text("{")
    elif case == "not_object":
        path.write_text("[]")
    elif case == "schema":
        path.write_text(json.dumps({**good, "schema": "other/v1"}))
    elif case == "unknown_key":
        path.write_text(json.dumps({**good, "extra": 1}))
    elif case == "long_text":
        path.write_text(json.dumps({**good, "applicability_summary": "x" * 4097}))
    elif case == "not_utf8":
        path.write_bytes(b'{"schema": "\xff"}')
    keys = {"schema", "name", "rules", "query_intent", "applicability_summary"}
    code, _ = refused_code(catalog().load_request, str(path), PRESET_REQ, keys)
    assert code == "REQUEST_INVALID"


def test_request_loader_accepts_valid(tmp_path):
    path = tmp_path / "req.json"
    path.write_text(json.dumps({"schema": PRESET_REQ, "name": "web-input", "rules": [R1]}))
    data = catalog().load_request(str(path), PRESET_REQ, {"schema", "name", "rules"})
    assert data["rules"] == [R1]


# AC-001F-03b
@pytest.mark.parametrize("intent", [
    "$(touch PWNED)", "`touch PWNED`; rm -rf /tmp/never", "__import__('os').system('touch PWNED')",
    "import os; os.system('touch PWNED')", "{{7*7}} ${IFS} | touch PWNED",
])
def test_query_text_never_executed(project, tmp_path, intent):
    env = PEnv(project, tmp_path)
    env.rules()
    saved = env.psave(query_intent=intent)
    assert saved.ok, saved.to_dict()
    shown = env.pshow()
    assert shown.data["query_intent"] == intent
    assert "not run" in shown.data["query_intent_note"]
    diff = env.recompute([R1])
    assert diff.ok, diff.to_dict()
    assert diff.data["query_intent"] == intent
    confirmed = env.recompute_confirm([R1], diff.data["recompute_digest"], keep_summary=True)
    assert confirmed.ok, confirmed.to_dict()
    assert env.presolve().ok
    for where in (Path.cwd(), project, tmp_path, Path(project).parent):
        assert not list(Path(where).rglob("PWNED")), where


FEATURE_MODULES = ("knowledge/catalog.py", "knowledge/presets.py", "knowledge/tags.py",
                   "policy/preset_scope.py")


def test_no_exec_eval_subprocess_in_feature_modules():
    root = Path(mod("knowledge").__file__).resolve().parents[1]
    for rel in FEATURE_MODULES:
        tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {a.name.split(".")[0] for a in node.names} & {"subprocess", "pty", "code"}, rel
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in ("subprocess", "pty", "code"), rel
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile", "__import__"), (rel, node.func.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in ("system", "popen", "spawnv", "execv", "execvp", "startfile",
                                              "eval", "exec"), (rel, node.func.attr)


# AC-001F-02j (OBS-5)
def test_dirlock_default_equals_lock_timeout():
    timeout = inspect.signature(durable.DirLock.__init__).parameters["timeout"].default
    assert timeout == atomic.LOCK_TIMEOUT == 10.0


# AC-001F-06f/08a (closing review TASK-071): printable stand-ins for listed names that are not valid UTF-8,
# including the unpaired surrogates Windows can return for NTFS names (never an encoding crash).
@pytest.mark.parametrize(
    ("listed", "shown"),
    [
        ("web-input.json", None),
        ("ü.json", None),
        (b"\xff.json".decode("utf-8", "surrogateescape"), "\\xff.json"),
        ("\ud800.json", "\\ud800.json"),
        ("a\udcff\ud800.json", "a\\udcff\\ud800.json"),
    ],
)
def test_undecodable_name_stand_in(listed, shown):
    result = mod("knowledge.catalog")._undecodable(listed)
    assert result == shown
    if result is not None:
        result.encode("utf-8")
