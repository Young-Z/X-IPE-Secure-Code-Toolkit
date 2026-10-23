"""Integration tests for FEATURE-002-B: tool registration, `guard tool` and the 002-A extensions."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from conftest import run_cli, tree_hashes
from test_guard import (  # noqa: F401 - fixture reuse
    GUARD,
    R1,
    R2,
    REPORTS,
    TOKEN,
    change_rule,
    env,
    req,
    with_attempt,
)

from x_ipe_secure_code import status as status_mod
from x_ipe_secure_code import tools_service
from x_ipe_secure_code.adapters import digests
from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.guard import toolrun
from x_ipe_secure_code.guard.targets import file_digest

FAKE = Path(__file__).resolve().parents[1] / "adapters" / "fake_opengrep.py"
posix_only = pytest.mark.skipif(os.name == "nt", reason="Adapter execution is POSIX only")


@pytest.fixture
def fake(env, monkeypatch):
    """A fake Opengrep binary registered as an official build for this host."""
    folder = env["tmp"] / "fake"
    folder.mkdir()
    config = folder / "config.json"
    binary = env["tmp"] / "bin" / "opengrep"
    binary.parent.mkdir()
    binary.write_text(f"#!{sys.executable}\n" + FAKE.read_text().replace("__CONFIG__", str(config)))
    binary.chmod(0o755)
    host = digests.host_platform()
    build = digests.ToolBuild(
        "opengrep", "1.31.0", host["os"], host["arch"], host["libc"], "fake-asset", False
    )
    monkeypatch.setitem(digests.TABLE, file_digest(binary), build)
    project = env["project"]
    (project / "src" / "login.py").write_text(f"def login(u):\n    return '<p>' + u  # VULN token={TOKEN}\n")
    (project / "src" / "tests").mkdir()
    (project / "src" / "tests" / "test_login.py").write_text("def test_x():\n    pass\n")
    rules_dir = project / "x-ipe-docs" / "rules"
    rules_dir.mkdir(parents=True)
    rule_py = {
        "id": "py-xss",
        "languages": ["python"],
        "severity": "ERROR",
        "message": "XSS sink",
        "metadata": {"cwe": "CWE-79"},
        "pattern": "'<p>' + $X",
    }
    (rules_dir / "py.yaml").write_text(json.dumps({"rules": [rule_py]}))
    (rules_dir / "py2.yaml").write_text(json.dumps({"rules": [{**rule_py, "id": "py-two"}]}))
    (rules_dir / "dup.yaml").write_text(json.dumps({"rules": [rule_py]}))
    (rules_dir / "java.yaml").write_text(
        json.dumps({"rules": [{**rule_py, "id": "java-x", "languages": ["java"]}]})
    )
    reg = tools_service.register(str(project), "opengrep", str(binary), trust_paths=env["paths"])
    assert reg.ok, reg.to_text()
    return {"binary": binary, "config": config, "log": folder / "invocations.jsonl", "build": build}


def set_mode(fake, mode):
    fake["config"].write_text(json.dumps({"mode": mode}))


def invocations(fake):
    return [json.loads(x) for x in fake["log"].read_text().splitlines()] if fake["log"].exists() else []


TOOL_METHOD = {"name": "opengrep", "kind": "runtime", "required": True}
READ_METHOD = {"name": "semantic-review", "kind": "reading", "required": True}


def check(
    cid="C1", obj=("src/login.py",), methods=(TOOL_METHOD,), selected=("opengrep",), minimum=("runtime",)
):
    c = {
        "id": cid,
        "rule": R1,
        "object": list(obj),
        "methods": list(methods),
        "minimum_evidence": list(minimum),
    }
    if selected is not None:
        c["method_choice"] = {
            "considered": ["semantic-review", "opengrep"],
            "cost": "opengrep ~1 s per rule",
            "selected": list(selected),
            "reason": "pattern rule exists for this sink",
        }
    return c


def opened(env, targets=("src/login.py",), **over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-open/v1",
        "scope_id": env["scope"],
        "targets": [{"path": t} for t in targets],
        "context": [{"path": "README.md"}],
    }
    doc.update(over)
    result = guard.open_verification(str(env["project"]), req(env, doc))
    assert result.ok, result.to_text()
    return result.data["verification_id"]


def planned(env, checks, targets=("src/login.py",)):
    vid = opened(env, targets=targets)
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": checks,
        "not_applicable": [{"rule": R2, "reason": "no database"}],
    }
    result = guard.record_plan(str(env["project"]), vid, req(env, doc))
    assert result.ok, result.to_text()
    return vid


def tool(env, vid, checks, **over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-tool/v1",
        "adapter": "opengrep",
        "include_ignored": False,
        "time_limit_seconds": 60,
        "checks": checks,
    }
    doc.update(over)
    return toolrun.run_tool(str(env["project"]), vid, req(env, doc))


def tc(cid="C1", rules=("x-ipe-docs/rules/py.yaml",), targets=("src/login.py",)):
    return {"check": cid, "rules": list(rules), "targets": list(targets)}


def state(env, vid):
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


def evidence(env, vid, check_id="C1"):
    return [e for e in state(env, vid)["evidence"] if check_id in e["checks"] and e["method"] == "opengrep"][
        -1
    ]


# ---------- AC-002B-01 registration and pre-check


def test_01a_registration_records_build_without_executing(env, fake):
    record = json.loads((env["project"] / ".x-ipe/private/secure-code/tools/opengrep.json").read_text())
    assert record["digest"] == file_digest(fake["binary"]) and record["version"] == "1.31.0"
    assert record["platform"] == {
        "os": fake["build"].os,
        "arch": fake["build"].arch,
        "libc": fake["build"].libc,
    }
    assert record["platform_validated"] is False and record["path"] == str(fake["binary"])
    assert invocations(fake) == []


def test_01b_registration_needs_maintainer(env, fake):
    other = resolve_trust(env["tmp"] / "no-trust")
    result = tools_service.register(str(env["project"]), "opengrep", str(fake["binary"]), trust_paths=other)
    assert result.problems[0].code == "NOT_AUTHORIZED" and result.next_steps


def test_01c_unknown_digest_symlink_or_missing_refused_unexecuted(env, fake):
    other = env["tmp"] / "other-opengrep"
    other.write_bytes(fake["binary"].read_bytes() + b"\n# modified\n")
    other.chmod(0o755)
    project, paths = str(env["project"]), env["paths"]
    assert (
        tools_service.register(project, "opengrep", str(other), trust_paths=paths).problems[0].code
        == "TOOL_DIGEST_UNKNOWN"
    )
    link = env["tmp"] / "link-opengrep"
    os.symlink(fake["binary"], link)
    assert (
        tools_service.register(project, "opengrep", str(link), trust_paths=paths).problems[0].code
        == "TOOL_PATH_INVALID"
    )
    assert (
        tools_service.register(project, "opengrep", str(env["tmp"] / "nope"), trust_paths=paths)
        .problems[0]
        .code
        == "TOOL_PATH_INVALID"
    )
    assert (
        tools_service.register(project, "strix", str(fake["binary"]), trust_paths=paths).problems[0].code
        == "TOOL_UNKNOWN"
    )
    assert invocations(fake) == []


@posix_only
@pytest.mark.parametrize("problem", ["swapped", "missing", "windows", "unregistered"])
def test_01d_precheck_gap_recorded_as_failed_method(env, fake, monkeypatch, problem):
    vid = planned(env, [check()])
    if problem == "swapped":
        fake["binary"].write_text(fake["binary"].read_text() + "\n# swapped\n")
    elif problem == "missing":
        fake["binary"].unlink()
    elif problem == "windows":
        monkeypatch.setattr(digests, "host_platform", lambda: {"os": "windows", "arch": "x86", "libc": None})
    else:
        (env["project"] / ".x-ipe/private/secure-code/tools/opengrep.json").unlink()
    result = tool(env, vid, [tc()])
    assert result.ok and result.data["status"] == "precheck_failed" and result.next_steps
    ev = evidence(env, vid)
    assert ev["method_status"] == "failed" and invocations(fake) == []
    expected = {"swapped": "digest", "missing": "binary", "windows": "Windows", "unregistered": "registered"}[
        problem
    ]
    assert expected.lower() in ev["summary"].lower()
    assert state(env, vid)["findings"] == []


# ---------- AC-002B-02 typed parameters


@posix_only
@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"surprise": 1}, "TOOL_REQUEST_INVALID"),
        ({"time_limit_seconds": 0}, "TOOL_REQUEST_INVALID"),
        ({"time_limit_seconds": 1801}, "TOOL_REQUEST_INVALID"),
        ({"time_limit_seconds": "60"}, "TOOL_REQUEST_INVALID"),
        ({"include_ignored": "yes"}, "TOOL_REQUEST_INVALID"),
        ({"adapter": "trivy"}, "TOOL_REQUEST_INVALID"),
        ({"checks": [tc(rules=["p/default"])]}, "TOOL_REQUEST_INVALID"),
        ({"checks": [tc(rules=["https://example.org/r.yaml"])]}, "TOOL_REQUEST_INVALID"),
        ({"checks": [tc(rules=["x-ipe-docs/rules"])]}, "TOOL_REQUEST_INVALID"),
        ({"checks": [tc(rules=["../outside.yaml"])]}, "TOOL_REQUEST_INVALID"),
        ({"checks": [tc(rules=["x-ipe-docs/rules/py.yaml; rm -rf /"])]}, "TOOL_REQUEST_INVALID"),
        ({"checks": [tc(targets=["src"])]}, "TARGETS_MISMATCH"),
        ({"checks": [tc(targets=["README.md"])]}, "TARGETS_MISMATCH"),
        (
            {"checks": [tc(rules=["x-ipe-docs/rules/py.yaml", "x-ipe-docs/rules/dup.yaml"])]},
            "RULE_ID_DUPLICATE",
        ),
        ({"checks": [tc(cid="C9")]}, "METHOD_NOT_PLANNED"),
    ],
)
def test_02_request_refusals_execute_nothing(env, fake, over, code):
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()] if "checks" not in over else over.pop("checks"), **over)
    assert not result.ok and result.problems[0].code == code, result.to_text()
    assert invocations(fake) == [] and state(env, vid)["evidence"] == []


@posix_only
def test_02b_symlinked_rule_refused(env, fake):
    os.symlink(env["project"] / "x-ipe-docs/rules/py.yaml", env["project"] / "x-ipe-docs/rules/link.yaml")
    vid = planned(env, [check()])
    result = tool(env, vid, [tc(rules=["x-ipe-docs/rules/link.yaml"])])
    assert result.problems[0].code == "TOOL_REQUEST_INVALID" and invocations(fake) == []


@posix_only
def test_02c_targets_must_cover_whole_object(env, fake):
    vid = planned(env, [check(obj=("src/login.py", "src/util.py"))], targets=("src/login.py", "src/util.py"))
    result = tool(env, vid, [tc(targets=["src/login.py"])])
    assert result.problems[0].code == "TARGETS_MISMATCH"


@posix_only
def test_02d_rule_digests_recorded(env, fake):
    vid = planned(env, [check()])
    assert tool(env, vid, [tc()]).ok
    run = state(env, vid)["adapter_runs"][0]
    assert run["rules"] == [
        {
            "check": "C1",
            "path": "x-ipe-docs/rules/py.yaml",
            "digest": file_digest(env["project"] / "x-ipe-docs/rules/py.yaml"),
            "ids": ["py-xss"],
            "config_digests": {"py-xss": invocations(fake)[0]["config_sha"][0]},
        }
    ]
    manifest = json.loads((env["project"] / GUARD / vid / run["manifest"]["path"]).read_text())
    assert [r["config_digest"] for r in manifest["checks"]["C1"]["rules"]] == [
        invocations(fake)[0]["config_sha"][0]
    ]


@posix_only
def test_02d_rule_not_staged_faithfully_is_not_run(env, fake, monkeypatch):
    from x_ipe_secure_code.adapters import rules as rules_mod

    real = rules_mod.dump_single
    monkeypatch.setattr(rules_mod, "dump_single", lambda rule: real({**rule, "message": "altered"}))
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    assert invocations(fake) == []
    assert result.data["status"] == "failed"
    assert any("staged faithfully" in g for g in result.data["checks"]["C1"]["gaps"])


@posix_only
def test_02_unsupported_rule_feature_refused(env, fake):
    (env["project"] / "x-ipe-docs/rules/taint.yaml").write_text(
        "rules:\n  - id: t\n    languages: [python]\n    mode: taint\n    message: m\n"
    )
    vid = planned(env, [check()])
    result = tool(env, vid, [tc(rules=["x-ipe-docs/rules/taint.yaml"])])
    assert result.problems[0].code == "RULE_FILE_INVALID" and invocations(fake) == []


# ---------- AC-002B-03 execution, normalization, accounting


@posix_only
def test_03a_03b_staged_copy_minimal_env_and_cleanup(env, fake):
    set_mode(fake, "write")
    project = env["project"]
    before = tree_hashes(project / "src", project / "README.md", project / "x-ipe-docs/rules")
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    assert result.ok
    (call,) = invocations(fake)
    stage = project / GUARD / vid / "adapter"
    assert call["argv"][0].startswith(str(stage)) and call["cwd"].startswith(str(stage.resolve()))
    config = call["argv"][call["argv"].index("--config") + 1]
    assert config.startswith(str(stage)) and all(t.startswith(str(stage)) for t in call["argv"][-1:])
    os_added = {"__CF_USER_TEXT_ENCODING"}  # injected by macOS into every process, not passed by the Adapter
    assert set(call["env"]) - os_added <= {
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "TMPDIR",
        "PATH",
        "LANG",
    }
    assert tree_hashes(project / "src", project / "README.md", project / "x-ipe-docs/rules") == before
    assert not any(stage.iterdir()) if stage.exists() else True
    assert not list(project.rglob("tool-wrote*")) and not list(project.rglob("semgrep.log"))
    home = Path(call["home"])
    assert call["cache"].startswith(call["home"]) and not home.exists()


# ---------- TASK-032: Opengrep cannot run with a non-ASCII cache path


@posix_only
def test_tool_runs_in_a_project_with_a_non_ascii_path(env, fake):
    project = env["project"]
    assert not str(project).isascii()
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    assert result.ok and result.data["status"] == "completed", result.to_text()
    (call,) = invocations(fake)
    home = Path(call["home"])
    assert call["home"].isascii() and call["cache"].isascii()
    assert not home.resolve().is_relative_to(project.resolve())
    assert not home.exists()
    assert [f["tool"]["rule_id"] for f in state(env, vid)["findings"]] == ["py-xss"]


@posix_only
def test_non_ascii_temporary_folder_refused_before_execution(env, fake, monkeypatch):
    import tempfile

    tmp = env["tmp"] / "tëmp"
    tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    assert result.ok and result.data["status"] == "precheck_failed" and result.next_steps
    assert invocations(fake) == [] and list(tmp.iterdir()) == []
    ev = evidence(env, vid)
    assert ev["method_status"] == "failed" and "ascii" in ev["summary"].lower()


@posix_only
def test_exit_zero_without_output_is_an_explicit_gap(env, fake):
    set_mode(fake, "silent")
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    assert result.data["status"] == "failed"
    assert any("no output" in g for g in result.data["checks"]["C1"]["gaps"])


@posix_only
def test_03c_03d_findings_and_evidence_with_provenance(env, fake):
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    st = state(env, vid)
    (finding,) = st["findings"]
    assert finding["source"] == "opengrep" and finding["check"] == "C1" and finding["rule"] == R1
    assert finding["location"] == {"path": "src/login.py", "line": 2} and finding["severity"] == "high"
    assert finding["cwe"] == "CWE-79" and finding["id"].startswith("opengrep-1-")
    assert finding["tool"]["rule_id"] == "py-xss" and finding["tool"]["tool_severity"] == "ERROR"
    assert finding["tool"]["rule_file"] == "x-ipe-docs/rules/py.yaml"
    ev = evidence(env, vid)
    assert ev["kind"] == "runtime" and ev["method_status"] == "ok" and ev["paths"] == ["src/login.py"]
    assert ev["stored"] == "evidence/opengrep-1-output.json" and ev["adapter_run"] == 1
    run = st["adapter_runs"][0]
    assert run["version"] == "1.31.0" and run["binary_digest"] == file_digest(fake["binary"])
    assert run["platform_validated"] is False and run["staged_digests"]["src/login.py"].startswith("sha256:")
    assert run["checks"]["C1"]["status"] == "completed" and run["manifest"]["path"].endswith("manifest.json")
    assert st["next_adapter_run"] == 2 and result.data["checks"]["C1"]["method_status"] == "ok"


@posix_only
@pytest.mark.parametrize(
    ("setup", "gap"),
    [
        ("skipped_folder", "skipped"),
        ("other_language", "not analyse"),
        ("rule_no_file", "applied to no file"),
        ("skipped_rule", "skipped by the tool"),
        ("syntax_error", "syntax error"),
    ],
)
def test_03e_incomplete_coverage_fails_only_that_check(env, fake, setup, gap):
    project = env["project"]
    (project / "src" / "util.py").write_text("def helper():\n    return 1\n")
    obj, rules = ("src",), ["x-ipe-docs/rules/py.yaml"]
    if setup == "other_language":
        (project / "src" / "page.html").write_text("<p>hi</p>")
    elif setup == "rule_no_file":
        rules = ["x-ipe-docs/rules/java.yaml"]
    elif setup == "skipped_rule":
        set_mode(fake, "skipped_rule")
    elif setup == "syntax_error":
        (project / "src" / "broken.py").write_text("def broken(:\n    pass\n")
    if setup != "skipped_folder":
        import shutil

        shutil.rmtree(project / "src" / "tests")
    vid = planned(env, [check(obj=obj), check("C2", obj=("src/util.py",))], targets=("src",))
    result = tool(
        env,
        vid,
        [
            tc(rules=rules, targets=["src"]),
            tc("C2", rules=["x-ipe-docs/rules/py2.yaml"], targets=["src/util.py"]),
        ],
    )
    assert result.ok
    ev1, ev2 = evidence(env, vid, "C1"), evidence(env, vid, "C2")
    assert ev1["method_status"] == "failed" and gap in ev1["summary"], ev1["summary"]
    if setup != "skipped_rule":
        assert ev2["method_status"] == "ok", ev2["summary"]


@posix_only
@pytest.mark.parametrize(
    ("mode", "status"), [("exit7", "failed"), ("garbage", "failed"), ("errors", "completed_with_errors")]
)
def test_03f_tool_errors_are_failed_methods(env, fake, mode, status):
    set_mode(fake, mode)
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()])
    assert result.data["checks"]["C1"]["status"] == status
    assert evidence(env, vid)["method_status"] == "failed"
    if mode == "errors":
        assert len(state(env, vid)["findings"]) == 1


@posix_only
def test_03g_timeout(env, fake):
    set_mode(fake, "sleep")
    vid = planned(env, [check()])
    result = tool(env, vid, [tc()], time_limit_seconds=2)
    assert result.data["checks"]["C1"]["status"] == "timed_out"
    assert evidence(env, vid)["method_status"] == "failed"


@posix_only
def test_03h_clean_zero_results(env, fake):
    (env["project"] / "src" / "login.py").write_text("def login(u):\n    return escape(u)\n")
    vid = planned(env, [check()])
    assert tool(env, vid, [tc()]).ok
    assert evidence(env, vid)["method_status"] == "ok" and state(env, vid)["findings"] == []


@posix_only
def test_03i_masking_and_no_retained_logs(env, fake):
    set_mode(fake, "write")
    vid = planned(env, [check()])
    assert tool(env, vid, [tc()]).ok
    run_dir = env["project"] / GUARD / vid
    for path in run_dir.rglob("*"):
        if path.is_file():
            assert TOKEN not in path.read_text(errors="replace"), path
    output = json.loads((run_dir / "evidence/opengrep-1-output.json").read_text())
    assert "[removed: matched source]" in json.dumps(output)
    assert not list(run_dir.rglob("semgrep.log"))


@posix_only
def test_03k_target_changed_since_open(env, fake):
    vid = planned(env, [check()])
    (env["project"] / "src" / "login.py").write_text("changed\n")
    result = tool(env, vid, [tc()])
    assert result.ok and invocations(fake) == []
    ev = evidence(env, vid)
    assert ev["method_status"] == "failed" and "changed since the verification opened" in ev["summary"]


@posix_only
def test_03j_failed_auxiliary_tool_method_substituted_required_not(env, fake):
    set_mode(fake, "exit7")
    aux = dict(TOOL_METHOD, required=False)
    vid = planned(
        env,
        [
            check(
                methods=(READ_METHOD, aux),
                selected=("semantic-review", "opengrep"),
                minimum=("reading", "runtime"),
            )
        ],
    )
    assert tool(env, vid, [tc()]).ok
    rec = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "evidence": [
            {
                "id": "E1",
                "kind": "reading",
                "method": "semantic-review",
                "method_status": "ok",
                "checks": ["C1"],
                "paths": ["src/login.py"],
                "summary": "read",
            }
        ],
        "ledger": [{"check": "C1", "state": "met", "evidence": ["E1", "opengrep-1-1"]}],
    }
    assert guard.record(str(env["project"]), vid, req(env, with_attempt(env, vid, rec))).ok
    guard.conclude(str(env["project"]), vid)
    res = json.loads((env["project"] / REPORTS / f"{vid}.json").read_text())
    row = next(r for r in res["ledger"] if r["check"] == "C1")
    assert row["state"] == "met" and row["substitution"] == [{"method": "opengrep", "status": "failed"}]


# ---------- AC-002B-04 Guard integration


@posix_only
def test_04b_04d_method_choice_required_and_selected(env, fake):
    vid = opened(env)
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": [check(selected=None)],
        "not_applicable": [{"rule": R2, "reason": "no db"}],
    }
    refused = guard.record_plan(str(env["project"]), vid, req(env, doc))
    assert refused.problems[0].code == "PLAN_INVALID" and "method_choice" in refused.problems[0].message
    vid = planned(
        env, [check(methods=(READ_METHOD, dict(TOOL_METHOD, required=False)), selected=("semantic-review",))]
    )
    assert tool(env, vid, [tc()]).problems[0].code == "METHOD_NOT_SELECTED"
    change = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "method_changes": [
            {
                "check": "C1",
                "change": "supplement",
                "method": {"name": "opengrep", "kind": "runtime"},
                "reason": "semantic review uncertain about the sink",
            }
        ],
    }
    assert guard.record(str(env["project"]), vid, req(env, change)).ok
    assert tool(env, vid, [tc()]).ok
    plan = state(env, vid)["plan"]
    (event,) = plan["method_changes"]
    assert event["reason"] == "semantic review uncertain about the sink" and event["selected_before"] == [
        "semantic-review"
    ]


@posix_only
def test_04e_method_change_adds_auxiliary_and_report_shows(env, fake):
    vid = planned(env, [check(methods=(READ_METHOD,), selected=("semantic-review",), minimum=("reading",))])
    change = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "evidence": [
            {
                "id": "E1",
                "kind": "reading",
                "method": "semantic-review",
                "method_status": "ok",
                "checks": ["C1"],
                "paths": ["src/login.py"],
                "summary": "read",
            }
        ],
        "method_changes": [
            {
                "check": "C1",
                "change": "supplement",
                "method": {"name": "opengrep", "kind": "runtime"},
                "reason": "add tool evidence",
            }
        ],
    }
    # FEATURE-002-C: a record citing an attempt cannot carry method changes, so record them first
    evidence_part = {"schema": change["schema"], "evidence": change.pop("evidence")}
    assert guard.record(str(env["project"]), vid, req(env, change)).ok
    assert guard.record(str(env["project"]), vid, req(env, with_attempt(env, vid, evidence_part))).ok
    methods = state(env, vid)["plan"]["checks"][0]["methods"]
    assert methods[-1] == {"name": "opengrep", "kind": "runtime", "required": False}
    assert state(env, vid)["plan"]["method_changes"][0]["evidence_ids"] == []
    assert tool(env, vid, [tc()]).ok
    guard.conclude(str(env["project"]), vid)
    text = (env["project"] / REPORTS / f"{vid}.md").read_text()
    assert "## Method Choices and Changes" in text and "add tool evidence" in text
    assert "## Adapter Runs" in text and "1.31.0" in text


@posix_only
def test_04c_agent_cannot_fake_tool_records_and_review_rules_apply(env, fake):
    vid = planned(env, [check()])
    project = str(env["project"])
    for bad in (
        {
            "evidence": [
                {
                    "id": "E1",
                    "kind": "runtime",
                    "method": "OpenGrep",
                    "method_status": "ok",
                    "checks": ["C1"],
                    "paths": ["src/login.py"],
                    "summary": "ran it",
                }
            ]
        },
        {
            "evidence": [
                {
                    "id": "opengrep-1-1",
                    "kind": "runtime",
                    "method": "opengrep",
                    "method_status": "ok",
                    "checks": ["C1"],
                    "paths": ["src/login.py"],
                    "summary": "x",
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "opengrep-9-1",
                    "rule": R1,
                    "location": {"path": "src/login.py"},
                    "title": "t",
                    "source": "semantic",
                    "severity": "low",
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "F1",
                    "rule": R1,
                    "location": {"path": "src/login.py"},
                    "title": "t",
                    "source": "opengrep",
                    "severity": "low",
                }
            ]
        },
    ):
        doc = {"schema": "ai-secure-code-toolkit/guard-record/v1", **bad}
        result = guard.record(project, vid, req(env, doc))
        assert result.problems and result.problems[0].code == "RECORD_INVALID", bad
    assert tool(env, vid, [tc()]).ok
    (fid,) = [f["id"] for f in state(env, vid)["findings"]]
    ledger = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "ledger": [{"check": "C1", "state": "not_met", "evidence": ["opengrep-1-1"], "findings": [fid]}],
    }
    assert guard.record(project, vid, req(env, ledger)).ok
    out = guard.conclude(project, vid)
    assert out.data["verdict"] == "cannot_confirm_pass" and "FINDING_UNCONFIRMED" in [
        r["code"] for r in out.data["reasons"]
    ]


@posix_only
def test_rule_file_shared_between_checks_refused(env, fake):
    vid = planned(env, [check(), check("C2")])
    result = tool(env, vid, [tc(), tc("C2")])
    assert result.problems[0].code == "RULE_FILE_SHARED"


# ---------- AC-002B-06 status


def test_06_status_reports_tools(env, fake):
    data = status_mod.collect(str(env["project"]), trust_paths=env["paths"]).data["tools"]
    og = data["opengrep"]
    assert og["state"] == "provided" and og["registered"] is True and og["check"] == "ok"
    assert og["version"] == "1.31.0" and og["platform_validated"] is False
    assert data["strix"]["state"] == "adapter not provided by this toolkit version"
    assert data["trivy"]["state"] == "provided"  # FEATURE-002-D AC-002D-08a supersedes the Trivy part
    fake["binary"].write_text("tampered")
    og = status_mod.collect(str(env["project"]), trust_paths=env["paths"]).data["tools"]["opengrep"]
    assert og["check"] != "ok" and og["next_step"] and invocations(fake) == []


def test_06_status_unregistered(env):
    og = status_mod.collect(str(env["project"]), trust_paths=env["paths"]).data["tools"]["opengrep"]
    assert og["state"] == "provided" and og["registered"] is False and "tools register" in og["next_step"]


def test_cli_tools_register_and_guard_tool_refusals(env):
    out = run_cli(
        [
            "tools",
            "register",
            "--project",
            str(env["project"]),
            "--tool",
            "opengrep",
            "--path",
            str(env["tmp"] / "nope"),
            "--json",
        ],
        env["trust_dir"],
    )
    assert out.returncode == 1 and json.loads(out.stdout)["problems"][0]["code"] == "TOOL_PATH_INVALID"
    vid = opened(env)
    bad = req(env, {"schema": "ai-secure-code-toolkit/guard-tool/v1"})
    out = run_cli(
        ["guard", "tool", "--project", str(env["project"]), "--run", vid, "--request", bad, "--json"],
        env["trust_dir"],
    )
    assert out.returncode == 1 and "Traceback" not in out.stderr
    assert json.loads(out.stdout)["problems"][0]["code"] in ("TOOL_REQUEST_INVALID", "PLAN_REQUIRED")


# ---------- code review regressions (TASK-030)


@posix_only
def test_git_ignore_does_not_hide_staged_files(env, fake):
    set_mode(fake, "git")
    vid = planned(env, [check()])
    assert tool(env, vid, [tc()]).ok
    assert evidence(env, vid)["method_status"] == "ok"
    assert "--no-git-ignore" in invocations(fake)[0]["argv"]


def test_adapter_method_name_must_be_exact(env, fake):
    vid = opened(env)
    bad = check(methods=({"name": "OpenGrep", "kind": "runtime", "required": True},), selected=("OpenGrep",))
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": [bad],
        "not_applicable": [{"rule": R2, "reason": "no db"}],
    }
    result = guard.record_plan(str(env["project"]), vid, req(env, doc))
    assert result.problems[0].code == "PLAN_INVALID" and "opengrep" in result.problems[0].message


@posix_only
def test_nested_targets_in_one_request(env, fake):
    import shutil

    shutil.rmtree(env["project"] / "src" / "tests")
    vid = planned(
        env, [check(obj=("src",)), check("C2", obj=("src/login.py",))], targets=("src", "src/login.py")
    )
    result = tool(
        env,
        vid,
        [tc(targets=["src"]), tc("C2", rules=["x-ipe-docs/rules/py2.yaml"], targets=["src/login.py"])],
    )
    assert result.ok and result.data["status"] != "precheck_failed", result.to_text()
    assert evidence(env, vid, "C2")["method_status"] == "ok", evidence(env, vid, "C2")["summary"]


@posix_only
def test_nested_target_under_skipped_folder_is_still_staged(env, fake):
    import shutil

    shutil.rmtree(env["project"] / "src" / "tests")
    (env["project"] / "src" / ".git").mkdir()
    (env["project"] / "src" / ".git" / "h.py").write_text("x = '<p>' + y  # VULN\n")
    vid = planned(
        env, [check(obj=("src",)), check("C2", obj=("src/.git/h.py",))], targets=("src", "src/.git/h.py")
    )
    result = tool(
        env,
        vid,
        [tc(targets=["src"]), tc("C2", rules=["x-ipe-docs/rules/py2.yaml"], targets=["src/.git/h.py"])],
    )
    assert result.ok
    ev = evidence(env, vid, "C2")
    assert ev["method_status"] == "ok" and "1 scanned" in ev["summary"], ev["summary"]
    assert [f["location"]["path"] for f in state(env, vid)["findings"] if f["check"] == "C2"] == [
        "src/.git/h.py"
    ]


@posix_only
def test_empty_object_never_ok(env, fake):
    (env["project"] / "src" / "empty").mkdir()
    vid = planned(env, [check(obj=("src/empty",))], targets=("src/empty",))
    assert tool(env, vid, [tc(targets=["src/empty"])]).ok
    ev = evidence(env, vid)
    assert ev["method_status"] == "failed" and "no object file" in ev["summary"], ev["summary"]
