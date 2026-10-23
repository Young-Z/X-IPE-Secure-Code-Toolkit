"""CR-TASK-086 renderer identity in Guard results (AC-002A-01i, 01j, 01k, 01l; FR-002A-10)."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import test_guard
from conftest import FakeInteraction, run_cli
from test_guard import REPORTS, full_run, opened, plan
from test_guard_engine import finding, review, run, state, subject

import x_ipe_secure_code
from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.guard import cancel, report, runs
from x_ipe_secure_code.guard import service as guard

# The FEATURE-002-A integration fixture (project, trust store, imported rules, saved scope).
env = test_guard.env

PACKAGE = Path(x_ipe_secure_code.__file__).resolve().parent
SECTION = "## Structured Result Origin"
HEX64 = re.compile(r"[0-9a-f]{64}")
FOREIGN = {"toolkit_version": "0.0.9", "renderer_digest": "0" * 64}
# SHA-256 of `report.render(...)` for unstamped results, recorded with the delivered renderer
# (guard/report.py 36a655d9…) before CR-TASK-086 was implemented.
GOLDEN_UNSTAMPED = {
    "engine_fail": "8bd81dfe8a096c107b93f2de06ecc27e07a0102ddbd0b8177b532444a863c19b",
    "engine_plain": "d4c71e9e03ad7b12f0b206913d2e8adab5ff1ac53f0fd2338e0b9469f637323e",
    "compare_rich": "23e31d53869b8170951f148dd755ac48c98d02adc99b83b37467d2b6d6fdb879",
}


@pytest.fixture(autouse=True)
def fresh_identity():
    """The package digest is cached per process; tests that patch the package root must not leak."""
    clear = getattr(getattr(report, "_package_digest", None), "cache_clear", lambda: None)
    clear()
    yield
    clear()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _unstamped_samples():
    import comparehelp

    return {
        "engine_fail": run(state(findings=[finding()], reviews=[review(subject())])),
        "engine_plain": run(state()),
        "compare_rich": json.loads(dumps_json(comparehelp.rich_pair()[1])),
    }


def _framed(root: Path, manifest) -> str:
    """Independent recomputation of FR-002A-10 framing: path NUL length NUL bytes, sorted paths."""
    h = hashlib.sha256()
    for rel in sorted(manifest):
        data = (root / rel).read_bytes()
        h.update(rel.encode("utf-8") + b"\0" + str(len(data)).encode("ascii") + b"\0" + data)
    return h.hexdigest()


def _copy_manifest(dest: Path) -> Path:
    for rel in report.RENDERER_MANIFEST:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PACKAGE / rel, dest / rel)
    return dest


def _result_bytes(env, vid) -> bytes:
    return (env["project"] / REPORTS / f"{vid}.json").read_bytes()


def _md(env, vid) -> str:
    return (env["project"] / REPORTS / f"{vid}.md").read_text(encoding="utf-8")


def _assert_stamped_outputs(env, vid, identity=None):
    identity = identity or report.renderer_identity()
    raw = _result_bytes(env, vid)
    result = json.loads(raw)
    assert result["schema"] == "ai-secure-code-toolkit/guard-result/v1"
    assert result["renderer"] == identity
    md = _md(env, vid)
    headings = [line for line in md.splitlines() if line.startswith("## ")]
    assert headings[-2:] == ["## Limits", SECTION]
    tail = md.split(SECTION, 1)[1]
    assert f"secure-code toolkit {report.md_text(identity['toolkit_version'])}" in tail
    assert (identity["renderer_digest"] or "renderer unknown") in tail
    assert "identifies the build that wrote the structured result" in tail
    assert "re-created later by repair may come from a different build" in tail
    assert report.footer_digest(md) == hashlib.sha256(raw).hexdigest()
    assert md == report.render(result)
    return result


# ------------------------------------------------------------------------------------ AC-002A-01l
def test_01l_manifest_sorted_and_names_report_and_atomic():
    manifest = report.RENDERER_MANIFEST
    assert list(manifest) == sorted(manifest) and len(set(manifest)) == len(manifest)
    assert {"atomic.py", "guard/report.py"} <= set(manifest)
    assert all((PACKAGE / rel).is_file() for rel in manifest)


def test_01l_identity_shape_and_independent_recomputation():
    identity = report.renderer_identity()
    assert set(identity) == {"toolkit_version", "renderer_digest"}
    assert identity["toolkit_version"] == x_ipe_secure_code.__version__
    assert HEX64.fullmatch(identity["renderer_digest"])
    assert identity["renderer_digest"] == _framed(PACKAGE, report.RENDERER_MANIFEST)
    assert report.manifest_digest(PACKAGE) == identity["renderer_digest"]
    assert report.renderer_identity() == identity and report.renderer_identity() is not identity


def test_01l_identity_version_is_the_cli_version(env):
    proc = run_cli(["--version"], env["trust_dir"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split()[-1] == report.renderer_identity()["toolkit_version"]


@pytest.mark.parametrize("component", ["guard/report.py", "atomic.py", "__init__.py"])
def test_01l_changing_any_component_changes_identity(tmp_path, component):
    root = _copy_manifest(tmp_path / "pkg")
    before = report.manifest_digest(root)
    assert before == report.renderer_identity()["renderer_digest"]
    path = root / component
    path.write_bytes(path.read_bytes() + b"# changed\n")
    after = report.manifest_digest(root)
    assert after is not None and after != before and after == _framed(root, report.RENDERER_MANIFEST)


def test_01l_framing_separates_components_and_paths(tmp_path):
    root = _copy_manifest(tmp_path / "pkg")
    base = report.manifest_digest(root)
    # moving bytes across the component boundary changes the digest (length framing)
    a, b = root / "atomic.py", root / "guard/report.py"
    data_a, data_b = a.read_bytes(), b.read_bytes()
    a.write_bytes(data_a + data_b[:10])
    b.write_bytes(data_b[10:])
    assert report.manifest_digest(root) != base
    a.write_bytes(data_a)
    b.write_bytes(data_b)
    # an added manifest component changes it too (path framing)
    (root / "extra.py").write_text("X = 1\n")
    assert report.manifest_digest(root, (*report.RENDERER_MANIFEST, "extra.py")) != base
    assert report.manifest_digest(root) == base


def test_01l_unreadable_component_is_unknown_and_never_matches(tmp_path, monkeypatch):
    root = _copy_manifest(tmp_path / "pkg")
    (root / "atomic.py").unlink()
    assert report.manifest_digest(root) is None
    (root / "atomic.py").mkdir()  # a directory in its place is unreadable as a file too
    assert report.manifest_digest(root) is None
    monkeypatch.setattr(report, "_PACKAGE_ROOT", root)
    unknown = report.renderer_identity()
    assert unknown == {"toolkit_version": x_ipe_secure_code.__version__, "renderer_digest": None}
    real = {
        "toolkit_version": x_ipe_secure_code.__version__,
        "renderer_digest": _framed(PACKAGE, ["atomic.py"]),
    }
    assert not report.same_renderer(unknown, unknown)
    assert not report.same_renderer(unknown, real) and not report.same_renderer(real, unknown)
    assert not report.same_renderer(None, None) and not report.same_renderer({}, real)
    assert report.same_renderer(real, dict(real))
    assert not report.same_renderer(real, {**real, "renderer_digest": "1" * 64})
    assert not report.same_renderer(real, {**real, "toolkit_version": "9.9.9"})


def test_01l_unreadable_component_when_a_result_is_written(env, tmp_path, monkeypatch):
    monkeypatch.setattr(report, "_PACKAGE_ROOT", tmp_path / "missing-package")
    vid, _ = full_run(env)
    result = _assert_stamped_outputs(env, vid)
    assert result["renderer"]["renderer_digest"] is None
    assert "renderer sha256 renderer unknown" in _md(env, vid)


# Closure guard: every toolkit-internal module imported by a manifest module is in the manifest.
def _module_file(parts: list[str]) -> str | None:
    if parts and (PACKAGE.joinpath(*parts[:-1]) / f"{parts[-1]}.py").is_file():
        return "/".join(parts) + ".py"
    if PACKAGE.joinpath(*parts, "__init__.py").is_file():
        return "/".join([*parts, "__init__.py"])
    return None


def toolkit_imports(source: str, module_rel: str) -> set[str]:
    """Package-relative files of the toolkit-internal modules a module imports (any nesting level)."""
    package_parts = module_rel.split("/")[:-1]
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "x_ipe_secure_code":
                    found.add(_module_file(parts[1:]) or "/".join(parts[1:]) + ".py")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package_parts[: len(package_parts) - (node.level - 1)]
            elif (node.module or "").split(".")[0] == "x_ipe_secure_code":
                base = []
                node_module = node.module.split(".", 1)[1] if "." in node.module else None
                parts = [*base, *(node_module.split(".") if node_module else [])]
                found |= _from_targets(parts, node.names)
                continue
            else:
                continue
            parts = [*base, *(node.module.split(".") if node.module else [])]
            found |= _from_targets(parts, node.names)
    return found


def _from_targets(parts: list[str], names) -> set[str]:
    submodules = {_module_file([*parts, a.name]) for a in names} - {None}
    if submodules:
        return submodules
    return {_module_file(parts) or "/".join(parts) + ".py"}


def unlisted(manifest, read=lambda rel: (PACKAGE / rel).read_text(encoding="utf-8")) -> set[str]:
    missing: set[str] = set()
    for rel in manifest:
        missing |= toolkit_imports(read(rel), rel) - set(manifest)
    return missing


def test_01l_closure_every_toolkit_import_of_the_renderer_is_in_the_manifest():
    assert "guard/report.py" in report.RENDERER_MANIFEST
    assert toolkit_imports(
        (PACKAGE / "guard/report.py").read_text(encoding="utf-8"), "guard/report.py"
    ) == {"__init__.py", "atomic.py"}
    assert unlisted(report.RENDERER_MANIFEST) == set()


@pytest.mark.parametrize(
    ("added", "expected"),
    [
        ("from ..knowledge import store\n", "knowledge/store.py"),
        ("from .model import MAX_TEXT\n", "guard/model.py"),
        ("from . import runs\n", "guard/runs.py"),
        ("import x_ipe_secure_code.policy.resolve\n", "policy/resolve.py"),
        ("from x_ipe_secure_code.guard import mask\n", "guard/mask.py"),
        ("def late():\n    from . import targets\n    return targets\n", "guard/targets.py"),
    ],
)
def test_01l_closure_check_fails_on_an_unlisted_toolkit_import(added, expected):
    real = (PACKAGE / "guard/report.py").read_text(encoding="utf-8")

    def read(rel):
        return (
            real + "\n" + added
            if rel == "guard/report.py"
            else (PACKAGE / rel).read_text(encoding="utf-8")
        )

    assert expected in unlisted(report.RENDERER_MANIFEST, read)


# ------------------------------------------------------------------------------- AC-002A-01i / 01j
def test_01j_render_without_renderer_is_byte_identical_to_the_delivered_renderer():
    for name, result in _unstamped_samples().items():
        text = report.render(result)
        assert _sha(text) == GOLDEN_UNSTAMPED[name], name
        assert SECTION not in text


def test_01i_render_with_renderer_adds_exactly_the_final_section():
    identity = report.renderer_identity()
    for name, result in _unstamped_samples().items():
        plain = report.render(result)
        stamped = {**copy.deepcopy(result), "renderer": identity}
        text = report.render(stamped)
        body, footer = text.rsplit("<!-- guard-result-sha256: ", 1)
        plain_body = plain.rsplit("<!-- guard-result-sha256: ", 1)[0]
        assert body.startswith(plain_body), name
        assert body[len(plain_body) :] == (
            f"{SECTION}\n\n"
            "- Structured result written by secure-code toolkit "
            f"{report.md_text(identity['toolkit_version'])}; "
            f"renderer sha256 {identity['renderer_digest']}\n"
            "- This identifies the build that wrote the structured result; a report re-created later by "
            "repair may come from a different build\n\n"
        ), name
        assert report.footer_digest(text) == hashlib.sha256(dumps_json(stamped)).hexdigest()
        assert report.render(stamped) == text


def test_01i_render_neutralizes_recorded_version_and_shows_unknown():
    result = run(state())
    result["renderer"] = {"toolkit_version": "1.0\n## Verdict <b>x</b>", "renderer_digest": None}
    text = report.render(result)
    tail = text.split(SECTION, 1)[1]
    assert "toolkit 1.0 \\#\\# Verdict \\<b\\>x\\</b\\>; renderer sha256 renderer unknown" in tail
    assert [line for line in text.splitlines() if line.startswith("## ")].count("## Verdict") == 1


def test_01i_normal_conclusion_records_current_build(env):
    vid, out = full_run(env)
    assert out.ok
    _assert_stamped_outputs(env, vid)
    raw = _result_bytes(env, vid)
    assert guard.conclude(str(env["project"]), vid).ok
    assert _result_bytes(env, vid) == raw  # concluding again does not rewrite the result


def test_01i_direct_cancel_records_current_build(env):
    vid = opened(env)
    assert plan(env, vid).ok
    out = cancel.cancel(str(env["project"]), vid, "user stopped")
    assert out.ok, out.to_text()
    result = _assert_stamped_outputs(env, vid)
    assert result["cancellation"]["reason"] == "user stopped" and result["verdict"] != "pass"


def test_01i_pending_cancellation_finalized_by_conclude_records_current_build(env):
    vid = opened(env)
    assert plan(env, vid).ok
    marker = {"requested_at": "2026-10-20T10:00:00Z", "reason": "pending", "consumed_at_request": 1.0}
    assert runs.create_marker(env["project"], vid, marker)
    assert runs.read_result(env["project"], vid) is None
    out = guard.conclude(str(env["project"]), vid)
    assert out.ok, out.to_text()
    result = _assert_stamped_outputs(env, vid)
    assert result["cancellation"]["reason"] == "pending"


def test_01i_cancel_race_keeps_the_stored_winner_unchanged(env, monkeypatch):
    vid = opened(env)
    assert plan(env, vid).ok
    real = runs.create_result_exclusive

    def another_writer_wins(root, result):
        real(root, {**result, "renderer": FOREIGN})
        raise FileExistsError

    monkeypatch.setattr(runs, "create_result_exclusive", another_writer_wins)
    out = cancel.cancel(str(env["project"]), vid, "race")
    assert out.ok, out.to_text()
    _assert_stamped_outputs(env, vid, FOREIGN)


def _make_unstamped(env, vid) -> dict:
    """Simulate a result written before CR-TASK-086: no `renderer`, report from the delivered renderer."""
    result = runs.read_result(env["project"], vid)
    result.pop("renderer", None)
    runs.write_result(env["project"], result)
    runs.write_report(env["project"], vid, report.render(result))
    return result


def test_01j_old_result_shown_concluded_and_cleaned_up_unchanged(env):
    vid, _ = full_run(env)
    old = _make_unstamped(env, vid)
    raw, md = _result_bytes(env, vid), _md(env, vid)
    assert SECTION not in md
    shown = guard.show(str(env["project"]), vid)
    assert shown.ok and shown.data["report_consistent"] is True
    assert guard.conclude(str(env["project"]), vid).ok
    assert _result_bytes(env, vid) == raw and _md(env, vid) == md
    md_path = env["project"] / REPORTS / f"{vid}.md"
    md_path.unlink()  # repair re-renders the report without rewriting the result
    assert guard.conclude(str(env["project"]), vid).ok
    assert _result_bytes(env, vid) == raw and _md(env, vid) == md
    later = datetime.now(UTC) + timedelta(days=60)
    cleaned = guard.cleanup(str(env["project"]), later)
    assert cleaned.ok and vid in [r["verification_id"] for r in cleaned.data["removed"]]
    assert _result_bytes(env, vid) == raw and _md(env, vid) == md
    assert guard.show(str(env["project"]), vid).ok
    assert runs.read_result(env["project"], vid) == old and "renderer" not in old


def test_01j_cross_build_repair_does_not_rewrite_the_result(env):
    vid, _ = full_run(env)
    result = runs.read_result(env["project"], vid)
    result["renderer"] = FOREIGN
    runs.write_result(env["project"], result)
    raw = _result_bytes(env, vid)
    (env["project"] / REPORTS / f"{vid}.md").unlink()
    assert guard.conclude(str(env["project"]), vid).ok
    assert _result_bytes(env, vid) == raw
    assert json.loads(raw)["renderer"] == FOREIGN
    assert _md(env, vid) == report.render(result)


# ------------------------------------------------------------------------------------ AC-002A-01k
@pytest.mark.parametrize("prior", ["absent", "foreign"])
def test_01k_risk_acceptance_records_current_build_verdict_unchanged(env, prior):
    vid, _ = full_run(env)
    if prior == "absent":
        _make_unstamped(env, vid)
    else:
        result = runs.read_result(env["project"], vid)
        result["renderer"] = FOREIGN
        runs.write_result(env["project"], result)
        runs.write_report(env["project"], vid, report.render(result))
    before = runs.read_result(env["project"], vid)
    out = guard.accept_risk(
        str(env["project"]),
        vid,
        "F1",
        "Accepted until the rewrite",
        interaction=FakeInteraction(answers=["F1"]),
    )
    assert out.ok, out.to_text()
    after = _assert_stamped_outputs(env, vid)
    assert after["verdict"] == before["verdict"] == "fail"
    assert after["findings"] == before["findings"]
    assert [f["final_severity"] for f in after["findings"]] == [
        f["final_severity"] for f in before["findings"]
    ]
    assert len(after["risk_acceptances"]) == len(before["risk_acceptances"]) + 1
    unchanged = {k: v for k, v in after.items() if k not in ("renderer", "risk_acceptances")}
    assert unchanged == {k: v for k, v in before.items() if k not in ("renderer", "risk_acceptances")}


# ----------------------------------------------------------- FEATURE-002-G v1 accepts the optional key
def test_002g_validator_accepts_results_with_renderer():
    import comparehelp

    from x_ipe_secure_code.guard import compare_validate

    for identity in (report.renderer_identity(), FOREIGN, {**FOREIGN, "renderer_digest": None}):
        doc = json.loads(dumps_json({**comparehelp.rich_pair()[1], "renderer": identity}))
        compare_validate.validate(doc, doc["verification_id"])


def test_002g_compare_of_stamped_results_is_consistent(tmp_path):
    import comparehelp as ch

    identity = report.renderer_identity()
    root = ch.make_project(tmp_path)
    ch.put(root, {**ch.result(ch.E_ID), "renderer": identity})
    ch.put(root, {**ch.result(ch.L_ID), "renderer": identity})
    envelope, code = ch.run_compare(root)
    assert envelope["ok"] and code == 0, envelope
    data, _ = ch.load_comparison(root, envelope)
    assert data["input_integrity"]["earlier"]["state"] == "consistent"
    assert data["input_integrity"]["later"]["state"] == "consistent"


def test_002g_compare_of_real_stamped_guard_results(env):
    import comparehelp as ch

    first, _ = full_run(env)
    time.sleep(1.1)  # the earlier verification must end strictly before the later one (seconds)
    second, _ = full_run(env)
    for vid in (first, second):
        assert runs.read_result(env["project"], vid)["renderer"] == report.renderer_identity()
    envelope, code = ch.run_compare(env["project"], earlier=(first,), later=(second,))
    assert envelope["ok"] and code == 0, envelope
    data, _ = ch.load_comparison(env["project"], envelope)
    assert data["input_integrity"]["earlier"]["state"] == "consistent"
    assert data["input_integrity"]["later"]["state"] == "consistent"
