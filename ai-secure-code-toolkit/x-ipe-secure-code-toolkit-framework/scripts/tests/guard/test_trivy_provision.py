"""Integration tests for FEATURE-002-D provisioning (`tools provision`) and removal (`remove-components`).

AC-002D-02a…02c, 02h, 04e (provisioning) and the DAO-001 known-host decision (decided by the 工程師 DAO
representative under the human's delegation, specification v1.0 10-23-2026).
"""

# ruff: noqa: F811
from __future__ import annotations

import hashlib
import json
import threading
import time

import pytest
from conftest import posix_only, run_cli
from trivyhelp import (  # noqa: F401 - fixture reuse
    ALL,
    BLOB,
    CACHE,
    GUARD,
    PLATFORM_GAP,
    POM_COMPLETE,
    RECORD,
    REPO,
    calls,
    cancel_when_called,
    clock,
    conclude_report,
    env,
    gen_dir,
    grant,
    grant_for,
    install_fake,
    linux,
    opened,
    planned,
    pointer,
    provision,
    provisioned,
    remove,
    scan,
    set_cfg,
    set_host,
    state,
    tcheck,
    trc,
    trivy,
    trivy_status,
    wait_for_call,
    write,
)

from x_ipe_secure_code.adapters import process
from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust
from x_ipe_secure_code.guard import control, runs
from x_ipe_secure_code.guard import service as guard

pytestmark = posix_only
LIMIT_TEXT = "configuration-level expectation of the launched tool, not network enforcement"


def prov_calls(fake):
    return calls(fake, "provision")


def declarations(env, vid):
    return state(env, vid)["egress"]["declarations"]


def ready(env):
    write(env, {"pom.xml": POM_COMPLETE})
    return planned(env, [tcheck()])


def no_side_effects(env, vid, before, fake, cache_before):
    after = state(env, vid)
    assert after["attempts"] == before["attempts"]  # no attempt registered, no budget charged
    assert after["budget"] == before["budget"]
    assert after.get("tool_provisioning", []) == before.get("tool_provisioning", [])
    assert prov_calls(fake) == [] and pointer(env) == cache_before


# ======================================================================= AC-002D-02a refusals
@pytest.mark.parametrize(
    ("case", "missing", "code"),
    [
        ("no-maintainer", "maintainer", "NOT_AUTHORIZED"),
        ("invalid-component", "component", "PROVISION_REQUEST_INVALID"),
        ("invalid-time-limit", "argument", "PROVISION_REQUEST_INVALID"),
        ("no-grant", "purpose", "EGRESS_NOT_AUTHORIZED"),
        ("other-origin", "recipient", "EGRESS_NOT_AUTHORIZED"),
        ("other-purpose", "purpose", "EGRESS_NOT_AUTHORIZED"),
        ("no-metadata", "data", "EGRESS_NOT_AUTHORIZED"),
        ("scope-other-tag", "scope", "EGRESS_NOT_AUTHORIZED"),
    ],
)
def test_02a_refusals_recorded_used_false_without_attempt(env, trivy, case, missing, code):
    vid = ready(env)
    components, time_limit, paths = ["vulnerability_db", "java_db"], 600, None
    if case in ("no-maintainer", "invalid-time-limit"):
        grant_for(env, vid)
    if case == "no-maintainer":
        paths = resolve_trust(env["tmp"] / "no-trust")
    elif case == "invalid-component":
        components = ["kernel_db"]
    elif case == "invalid-time-limit":
        time_limit = 3601
    elif case == "other-origin":
        grant(env, vid, "https://ghcr.io", ["https://ghcr.io/aquasec/trivy-db:2", "https://ghcr.io/aquasec/"])
    elif case == "other-purpose":
        grant(
            env, vid, "https://mirror.gcr.io", ["https://mirror.gcr.io/aquasec/"], purpose="reference_fetch"
        )
    elif case == "no-metadata":
        grant(env, vid, "https://mirror.gcr.io", ["https://mirror.gcr.io/aquasec/"], data=("public_query",))
    elif case == "scope-other-tag":
        grant(
            env,
            vid,
            "https://mirror.gcr.io",
            ["https://mirror.gcr.io/aquasec/trivy-db:1", "https://mirror.gcr.io/aquasec/trivy-java-db:2"],
        )
    before, cache_before = state(env, vid), pointer(env)
    out = provision(env, vid, components, time_limit=time_limit, paths=paths)
    assert not out.ok and out.problems[0].code == code, out.to_text()
    assert out.next_steps
    new = declarations(env, vid)[len(before["egress"]["declarations"]) :]
    expected = 1 if case == "invalid-component" else len(components)
    assert len(new) == expected and [d["id"] for d in new] == out.data["declarations"]
    for d in new:
        assert d["by"] == "toolkit" and d["purpose"] == "tool_update" and d["decision"] == "refused"
        assert d["used"] is False and d["missing"] == missing and d["grant"] is None
        assert d["data"] == ["metadata"] and d["operation"].startswith("trivy-provision-")
    if case != "invalid-component":
        assert set(out.data["components"]) == set(components)
        assert {v["missing"] for v in out.data["components"].values()} == {missing}
    no_side_effects(env, vid, before, trivy, cache_before)


@pytest.mark.parametrize("case", ["unknown", "finished", "cancelled", "paused", "out-of-time", "macos"])
def test_02a_unaccepted_verification_or_platform_records_nothing(env, trivy, clock, monkeypatch, case):
    vid = ready(env)
    grant_for(env, vid)
    expected = {
        "unknown": "RUN_NOT_FOUND",
        "finished": "RUN_FINISHED",
        "cancelled": "RUN_CANCELLED",
        "paused": "RUN_PAUSED",
        "out-of-time": "BUDGET_TIME_EXHAUSTED",
        "macos": "ADAPTER_PLATFORM_UNSUPPORTED",
    }[case]
    target = vid
    if case == "unknown":
        target = vid[:-8] + "00000000"
    elif case == "finished":
        guard.conclude(str(env["project"]), vid)
    elif case == "cancelled":
        from x_ipe_secure_code.guard import cancel

        assert cancel.cancel(str(env["project"]), vid, "stop").ok
    elif case == "paused":
        assert control.pause(str(env["project"]), vid, "asking the user").ok
    elif case == "out-of-time":
        clock.at(env, vid, 3601)
    else:
        set_host(monkeypatch, "macos", "aarch64")
    before = (env["project"] / GUARD / vid / "state.json").read_bytes()
    out = provision(env, target, ["vulnerability_db"])
    assert not out.ok and out.problems[0].code == expected, out.to_text()
    if case == "macos":
        assert PLATFORM_GAP in out.problems[0].message
    assert (env["project"] / GUARD / vid / "state.json").read_bytes() == before  # nothing recorded
    assert prov_calls(trivy) == [] and pointer(env) is None


# ======================================================================= AC-002D-02b operations
def test_02b_operation_argv_declaration_budget_report(env, trivy):
    vid = ready(env)
    grant_ids = grant_for(env, vid)
    out = provision(env, vid, ALL, time_limit=900)
    assert out.ok, out.to_text()
    data = out.data
    assert (
        data["verification_id"] == vid and data["registry"] == "mirror.gcr.io" and data["time_limit"] <= 900
    )
    assert data["attempt"] and data["budget"] and LIMIT_TEXT in data["limit"]
    ops = data["operations"]
    assert [o["component"] for o in ops] == list(ALL)
    for op in ops:
        repo, tag = REPO["mirror.gcr.io"][op["component"]].rsplit(":", 1)
        assert op["repository"] == repo and op["tag"] == tag and op["outcome"] == "completed"
        assert (
            op["previous"] == "missing"
            and op["size_bytes"] > 0
            and op["content_digest"].startswith("sha256:")
        )
        assert op["seconds"] >= 0 and op["grants"] == grant_ids
        assert op["known_hosts"] == [
            {
                "host": "mirror.gcr.io",
                "origin": "https://mirror.gcr.io",
                "scope": f"https://{repo}:{tag}",
                "grant": grant_ids[0],
            }
        ]
    assert set(ops[0]["metadata"]) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
    assert set(ops[2]["metadata"]) >= {"MajorVersion", "Digest", "DownloadedAt"}
    # exact validated argv: one repository, fallback replaced, no project file, no version check/telemetry
    calls_ = prov_calls(trivy)
    assert [c["component"] for c in calls_] == list(ALL)
    for c in calls_:
        argv, op = c["argv"][1:], c["cache_dir"]
        timeout = argv[argv.index("--timeout") + 1]
        assert timeout.endswith("s") and int(timeout[:-1]) >= 60
        common = [
            "--skip-version-check",
            "--disable-telemetry",
            "--no-progress",
            "--cache-dir",
            op,
            "--timeout",
            timeout,
        ]
        if c["component"] == "vulnerability_db":
            assert argv == [
                "image",
                "--download-db-only",
                "--db-repository",
                "mirror.gcr.io/aquasec/trivy-db:2",
                *common,
            ]
        elif c["component"] == "java_db":
            assert argv == [
                "image",
                "--download-java-db-only",
                "--java-db-repository",
                "mirror.gcr.io/aquasec/trivy-java-db:1",
                *common,
            ]
        else:
            empty = argv[-1]
            assert argv == [
                "fs",
                "--scanners",
                "misconfig",
                "--checks-bundle-repository",
                "mirror.gcr.io/aquasec/trivy-checks:2",
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--skip-version-check",
                "--disable-telemetry",
                "--no-progress",
                "--format",
                "json",
                "--cache-dir",
                op,
                "--timeout",
                timeout,
                empty,
            ]
        assert str(env["project"] / "pom.xml") not in json.dumps(c["argv"])
        assert c["cwd_listing"] == [] and str(env["project"] / CACHE / "staging") in c["cwd"]
        assert set(c["env"]) - {"__CF_USER_TEXT_ENCODING"} == {
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "TMPDIR",
            "PATH",
            "LANG",
            "TZ",
        }
    st = state(env, vid)
    allowed = [d for d in st["egress"]["declarations"] if d["decision"] == "allowed"]
    assert len(allowed) == 3 and all(d["used"] is True and d["by"] == "toolkit" for d in allowed)
    assert [d["id"] for d in allowed] == [o["declaration"] for o in ops]
    assert all(d["known_hosts"][0]["host"] == "mirror.gcr.io" and LIMIT_TEXT in d["note"] for d in allowed)
    (attempt,) = [a for a in st["attempts"] if a["kind"] == "tool_update"]
    assert attempt["id"] == data["attempt"] and attempt["status"] == "finished"
    assert attempt["covers"]["components"] == list(ALL) and attempt["covers"]["pairs"] == []
    (entry,) = st["tool_provisioning"]
    assert entry["adapter"] == "trivy" and entry["attempt"] == attempt["id"] and LIMIT_TEXT in entry["limit"]
    assert entry["maintainer"]["action"] == "tools.provision" and entry["maintainer"]["role"] == "maintainer"
    assert (
        entry["version"] == "0.76.1"
        and entry["binary_digest"] == json.loads((env["project"] / RECORD).read_text())["digest"]
    )
    report = conclude_report(env, vid)
    assert "## Tool Provisioning" in report and "mirror.gcr.io/aquasec/trivy-db:2" in report
    assert (
        ops[0]["content_digest"] in report
        and "contacts outside the known-host list cannot be detected" in report
    )
    assert (
        "not interchangeable" in report and "mirror.gcr.io" in report.split("## Outbound Calls (Egress)")[1]
    )


def test_02b_declaration_used_only_when_spawned(env, trivy, monkeypatch):
    vid = ready(env)
    grant_for(env, vid)
    real = process.run
    seen = []

    def spy(argv, *args, **kwargs):
        decl = [d for d in declarations(env, vid) if d["decision"] == "allowed"]
        seen.append([d["used"] for d in decl])
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(process, "run", spy)
    assert provision(env, vid, ALL).ok
    assert seen == [[True, False, False], [True, True, False], [True, True, True]]


# ======================================================================= DAO-001 known hosts
@pytest.mark.parametrize("blob_scope", [None, "https://pkg-containers.githubusercontent.com/ghcr1"])
def test_dao001_ghcr_refused_when_blob_host_lacks_grant(env, trivy, blob_scope):
    vid = ready(env)
    grant(env, vid, "https://ghcr.io", ["https://ghcr.io/aquasecurity/"])
    if blob_scope:
        grant(env, vid, BLOB, [blob_scope])  # narrower than the origin root: does not cover it
    before, cache_before = state(env, vid), pointer(env)
    out = provision(env, vid, ["vulnerability_db"], registry="ghcr.io")
    assert not out.ok and out.problems[0].code == "EGRESS_NOT_AUTHORIZED"
    assert "pkg-containers.githubusercontent.com" in out.problems[0].message and out.next_steps
    (d,) = declarations(env, vid)[len(before["egress"]["declarations"]) :]
    assert (
        d["decision"] == "refused"
        and d["used"] is False
        and d["host"] == "pkg-containers.githubusercontent.com"
    )
    assert d["missing"] in ("purpose", "recipient", "scope")
    assert out.data["components"]["vulnerability_db"]["host"] == "pkg-containers.githubusercontent.com"
    no_side_effects(env, vid, before, trivy, cache_before)


def test_dao001_egress_record_lists_both_hosts(env, trivy):
    vid = ready(env)
    repo_grant, blob_grant = grant_for(env, vid, ["vulnerability_db"], registry="ghcr.io")
    out = provision(env, vid, ["vulnerability_db"], registry="ghcr.io")
    assert out.ok, out.to_text()
    (op,) = out.data["operations"]
    expected = [
        {
            "host": "ghcr.io",
            "origin": "https://ghcr.io",
            "scope": "https://ghcr.io/aquasecurity/trivy-db:2",
            "grant": repo_grant,
        },
        {
            "host": "pkg-containers.githubusercontent.com",
            "origin": BLOB,
            "scope": BLOB + "/",
            "grant": blob_grant,
        },
    ]
    assert op["known_hosts"] == expected and op["repository"] == "ghcr.io/aquasecurity/trivy-db"
    (d,) = [d for d in declarations(env, vid) if d["decision"] == "allowed"]
    assert d["known_hosts"] == expected and d["used"] is True and d["recipient"] == "https://ghcr.io"
    assert pointer(env)["components"]["vulnerability_db"]["registry"] == "ghcr.io"
    egress_section = conclude_report(env, vid).split("## Outbound Calls (Egress)")[1]
    assert "pkg-containers.githubusercontent.com" in egress_section and "ghcr.io" in egress_section


def test_dao001_mirror_gcr_io_unchanged_single_host(env, trivy):
    vid = ready(env)
    grant_for(env, vid, ["checks_bundle"])
    out = provision(env, vid, ["checks_bundle"])
    assert out.ok, out.to_text()
    (op,) = out.data["operations"]
    assert [h["host"] for h in op["known_hosts"]] == ["mirror.gcr.io"]
    assert pointer(env)["components"]["checks_bundle"]["metadata"]["Digest"].startswith("sha256:b591e919")


def test_dao001_unknown_tool_version_refused_before_launch(env, linux, monkeypatch):
    fake = install_fake(env, monkeypatch, linux, version="0.77.0")
    vid = ready(env)
    grant_for(env, vid)
    before, cache_before = state(env, vid), pointer(env)
    out = provision(env, vid, ["vulnerability_db"])
    assert not out.ok and out.problems[0].code == "TRIVY_KNOWN_HOSTS_UNKNOWN"
    assert "re-validation" in " ".join(out.next_steps)
    (d,) = declarations(env, vid)[len(before["egress"]["declarations"]) :]
    assert d["decision"] == "refused" and d["used"] is False and d["missing"] == "known_hosts"
    no_side_effects(env, vid, before, fake, cache_before)


# ======================================================================= AC-002D-02c results and failures
@pytest.mark.parametrize(
    ("component", "variant", "outcome"),
    [
        ("vulnerability_db", "fail", "failed"),
        ("checks_bundle", "bundle-refused", "failed"),
        ("vulnerability_db", "slow", "timed_out"),
        ("vulnerability_db", "extra-file", "failed"),
        ("java_db", "symlink", "failed"),
        ("checks_bundle", "hardlink", "failed"),
        ("vulnerability_db", "wrong-metadata", "failed"),
    ],
)
@pytest.mark.parametrize("previous", [True, False])
def test_02c_result_metadata_and_failures_keep_previous(env, trivy, component, variant, outcome, previous):
    vid = ready(env)
    grant_for(env, vid)
    if previous:
        assert provision(env, vid, [component]).ok
    old = pointer(env)
    generations = (
        sorted(p.name for p in (env["project"] / CACHE / "gen" / component).iterdir()) if previous else []
    )
    set_cfg(trivy, provision={component: variant}, nap=30)
    out = provision(env, vid, [component], time_limit=3 if variant == "slow" else 600)
    assert out.ok, out.to_text()  # executed (any outcome)
    (op,) = out.data["operations"]
    assert op["outcome"] == outcome and op["reason"] and op["previous"] == ("kept" if previous else "missing")
    assert pointer(env) == old
    gen_root = env["project"] / CACHE / "gen" / component
    assert (sorted(p.name for p in gen_root.iterdir()) if gen_root.exists() else []) == generations
    staging = env["project"] / CACHE / "staging"
    assert not staging.exists() or list(staging.iterdir()) == []
    st = trivy_status(env)["components"][component]
    assert st["state"] == ("present" if previous else "missing")
    entry = state(env, vid)["tool_provisioning"][-1]
    assert entry["operations"][0]["outcome"] == outcome


def test_02c_partial_download_never_used_by_a_scan(env, trivy):
    vid = ready(env)
    grant_for(env, vid)
    set_cfg(trivy, provision={"vulnerability_db": "slow"}, nap=30)
    assert (
        provision(env, vid, ["vulnerability_db"], time_limit=3).data["operations"][0]["outcome"]
        == "timed_out"
    )
    result = scan(env, vid, [trc()])
    assert result.ok and "vulnerability_db" in json.dumps(result.data["checks"]["C1"])
    assert [c for c in calls(trivy, "scan") if "vuln" in c["argv"]] == []


def test_02c_successful_result_records_maintainer_grant_size_and_metadata(env, trivy):
    vid = ready(env)
    grant_ids = grant_for(env, vid, ["java_db"])
    out = provision(env, vid, ["java_db"])
    (op,) = out.data["operations"]
    assert op["component"] == "java_db" and op["repository"] == "mirror.gcr.io/aquasec/trivy-java-db"
    assert op["tag"] == "1" and op["outcome"] == "completed" and op["grants"] == grant_ids[:1]
    entry = pointer(env)["components"]["java_db"]
    assert op["size_bytes"] == entry["size_bytes"] and op["content_digest"] == entry["content_digest"]
    files = entry["files"]
    assert set(files) == {"java-db/trivy-java.db", "java-db/metadata.json"}
    lines = "".join(f"{rel}\0{rec['sha256']}\n" for rel, rec in sorted(files.items()))
    assert entry["content_digest"] == "sha256:" + hashlib.sha256(lines.encode()).hexdigest()
    assert op["metadata"]["Version"] == 1 and set(op["metadata"]) >= {
        "UpdatedAt",
        "NextUpdate",
        "DownloadedAt",
    }
    prov = state(env, vid)["tool_provisioning"][-1]
    assert (
        prov["maintainer"]["action"] == "tools.provision" and prov["operations"][0]["grants"] == grant_ids[:1]
    )


# ======================================================================= AC-002D-04e cancellation
@pytest.mark.parametrize("moment", ["during-download", "at-barrier"])
def test_04e_cancel_provisioning_keeps_previous_state(env, trivy, monkeypatch, moment):
    vid = ready(env)
    grant_for(env, vid)
    assert provision(env, vid, ["vulnerability_db"]).ok
    old = pointer(env)
    gens = sorted(p.name for p in (env["project"] / CACHE / "gen" / "vulnerability_db").iterdir())
    if moment == "during-download":
        set_cfg(trivy, provision={"vulnerability_db": "slow"}, nap=60)
        thread, box = cancel_when_called(env, vid, trivy, kind="provision", count=2)
        out = provision(env, vid, ["vulnerability_db"])
        thread.join(60)
        cancellation = box["result"].data["cancellation"]
        tool_update = [a["id"] for a in state(env, vid)["attempts"] if a["kind"] == "tool_update"]
        assert not set(tool_update) & set(cancellation["agent_attempts"])  # toolkit-owned, not agent work
    else:
        real = runs.commit_state

        def cancel_first(root, st, *, expected_revision, on_commit=None):
            if on_commit is not None:
                runs.create_marker(
                    root,
                    vid,
                    {"requested_at": "2026-10-23T00:00:00Z", "reason": None, "consumed_at_request": 1.0},
                )
            return real(root, st, expected_revision=expected_revision, on_commit=on_commit)

        monkeypatch.setattr(runs, "commit_state", cancel_first)
        out = provision(env, vid, ["vulnerability_db"])
    assert not out.ok and out.problems[0].code == "RUN_CANCELLED", out.to_text()
    assert pointer(env) == old
    assert sorted(p.name for p in (env["project"] / CACHE / "gen" / "vulnerability_db").iterdir()) == gens
    assert not (env["project"] / CACHE / "journal.json").exists()
    staging = env["project"] / CACHE / "staging"
    assert not staging.exists() or list(staging.iterdir()) == []
    attempts = [a for a in state(env, vid)["attempts"] if a["kind"] == "tool_update"]
    assert attempts[-1]["status"] in ("cancelled", "unfinished")


# ======================================================================= AC-002D-02h removal
def test_02h_remove_components_frees_bytes_status_missing(env, trivy):
    vid = ready(env)
    provisioned(env, vid)
    project = env["project"]
    record = (project / RECORD).read_bytes()
    run_state = (project / GUARD / vid / "state.json").read_bytes()
    originals = {p: p.read_bytes() for p in project.rglob("*") if p.is_file() and ".x-ipe" not in p.parts}
    java_gen = gen_dir(env, "java_db")
    invoked = len(calls(trivy))
    out = remove(env, ["java_db"])
    assert out.ok, out.to_text()
    (removed,) = out.data["removed"]
    assert removed["component"] == "java_db" and removed["freed_disk_bytes"] > 0
    assert out.data["freed_disk_bytes_total"] == removed["freed_disk_bytes"]
    assert not java_gen.exists() and trivy_status(env)["components"]["java_db"]["state"] == "missing"
    assert trivy_status(env)["components"]["vulnerability_db"]["state"] == "present"
    assert (project / RECORD).read_bytes() == record
    assert (project / GUARD / vid / "state.json").read_bytes() == run_state
    assert {p: p.read_bytes() for p in originals} == originals and len(calls(trivy)) == invoked
    out = remove(env, remove_all=True)
    assert out.ok and {r["component"] for r in out.data["removed"]} == {"vulnerability_db", "checks_bundle"}
    assert out.data["not_present"] == ["java_db"]
    assert {c["state"] for c in trivy_status(env)["components"].values()} == {"missing"}
    assert not list((project / CACHE / "gen").rglob("*.db"))


@pytest.mark.parametrize(
    "case", ["no-maintainer", "unknown-component", "scan-running", "provisioning-running"]
)
def test_02h_remove_refusals_remove_nothing(env, trivy, monkeypatch, case):
    vid = ready(env)
    provisioned(env, vid)
    monkeypatch.setattr(guard, "LOCK_TIMEOUT", 1.0)
    old = pointer(env)
    worker = None
    if case == "scan-running":
        set_cfg(trivy, mode="sleep")
        worker = threading.Thread(target=lambda: scan(env, vid, [trc()], time_limit_seconds=30), daemon=True)
        worker.start()
        wait_for_call(trivy, "scan")
    elif case == "provisioning-running":
        set_cfg(trivy, provision={"java_db": "slow"}, nap=30)
        worker = threading.Thread(target=lambda: provision(env, vid, ["java_db"], time_limit=20), daemon=True)
        worker.start()
        wait_for_call(trivy, "provision", count=4)
    paths = resolve_trust(env["tmp"] / "no-trust") if case == "no-maintainer" else None
    components = ["kernel_db"] if case == "unknown-component" else ["vulnerability_db"]
    out = remove(env, components, paths=paths)
    code = {
        "no-maintainer": "NOT_AUTHORIZED",
        "unknown-component": "PROVISION_REQUEST_INVALID",
        "scan-running": "TRIVY_CACHE_BUSY",
        "provisioning-running": "TRIVY_CACHE_BUSY",
    }[case]
    assert not out.ok and out.problems[0].code == code, out.to_text()
    assert out.next_steps
    if worker is not None:
        from x_ipe_secure_code.guard import cancel

        cancel.cancel(str(env["project"]), vid, "test cleanup")
        worker.join(60)
    assert pointer(env)["components"]["vulnerability_db"] == old["components"]["vulnerability_db"]
    assert gen_dir(env, "vulnerability_db").exists()


# ======================================================================= CLI contract
def test_cli_tools_provision_and_remove_components(env):
    out = run_cli(
        [
            "tools",
            "provision",
            "--project",
            str(env["project"]),
            "--tool",
            "opengrep",
            "--run",
            "gv-20261023T010000Z-1a2b3c4d",
            "--component",
            "vulnerability_db",
            "--json",
        ],
        env["trust_dir"],
    )
    assert out.returncode == 1 and json.loads(out.stdout)["problems"][0]["code"] == "TOOL_UNKNOWN"
    out = run_cli(
        [
            "tools",
            "remove-components",
            "--project",
            str(env["project"]),
            "--tool",
            "trivy",
            "--component",
            "kernel_db",
            "--json",
        ],
        env["trust_dir"],
    )
    assert (
        out.returncode == 1 and json.loads(out.stdout)["problems"][0]["code"] == "PROVISION_REQUEST_INVALID"
    )
    for args in (["tools", "provision", "--help"], ["tools", "remove-components", "--help"]):
        text = run_cli(args, env["trust_dir"]).stdout
        for opt in ("--project", "--tool", "--component", "--json"):
            assert opt in text, (args, opt)
    help_text = run_cli(["tools", "provision", "--help"], env["trust_dir"]).stdout
    assert "--run" in help_text and "--registry" in help_text and "--time-limit" in help_text
    assert "--all" in run_cli(["tools", "remove-components", "--help"], env["trust_dir"]).stdout


def test_provisioning_time_is_charged_to_the_verification(env, trivy):
    vid = ready(env)
    grant_for(env, vid, ["vulnerability_db"])
    set_cfg(trivy, provision={"vulnerability_db": "slow"}, nap=1.5)
    start = time.monotonic()
    out = provision(env, vid, ["vulnerability_db"])
    assert out.ok and out.data["operations"][0]["seconds"] >= 1.0
    assert out.data["budget"]["consumed_seconds"] >= min(1.0, time.monotonic() - start - 0.5)
