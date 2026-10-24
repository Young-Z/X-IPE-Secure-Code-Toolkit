"""FEATURE-002-F execution orchestration with the fake runtime (AC-002F-03b, 04a, 04d, 04e, 04g, 04h, 04l,
04m, 04n, 06a; review M1, M4). Enforcement itself is proven only by the real-runtime conformance suite."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json
import time

from conftest import tree_hashes
from helperhelp import (  # noqa: F401 - fixture reuse
    GUARD,
    METHOD,
    Flow,
    env,
    extend,
    fake,
    flow,
    helper_run,
    henv,
    mod,
    state_of,
)

from x_ipe_secure_code.guard import control


def helper_of(env, vid, hid):
    return next(h for h in state_of(env, vid)["helpers"] if h["id"] == hid)


def attempt_of(env, vid, aid):
    return next(a for a in state_of(env, vid)["attempts"] if a["id"] == aid)


def refused(out, code, reason_code=None):
    assert not out.ok and out.problems[0].code == code, out.to_text()
    if reason_code:
        assert out.data["reason_code"] == reason_code, out.data


# ---------- AC-002F-04a
def test_04a_grant_required_toolkit_container(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    assert flow.review(vid, hid).ok
    a = flow.helper_attempt(vid)
    refused(flow.run(vid, hid, a), "HELPER_NOT_EXECUTED", "not_granted")
    assert not flow.fake.creates("target") and not flow.fake.creates("sample")
    assert flow.grant(vid).ok
    out = flow.run(vid, hid, a)
    assert out.ok and out.data["outcome"] == "clean", out.to_text()
    targets = flow.fake.creates("target")
    assert len(targets) == 1 and "--pull=never" in targets[0] and "--network" in targets[0]
    assert attempt_of(flow.env, vid, a)["status"] == "finished"


# ---------- AC-002F-03b
def test_03b_samples_own_containers_mismatch_blocks_target(flow):
    vid, hid = flow.ready()
    flow.fake.set(
        runs={
            "sample-1": {
                "mode": "result",
                "result": {
                    "schema": "x-ipe-helper-result/1",
                    "helper": hid,
                    "status": "complete",
                    "scanned": ["src/config/app.yaml"],
                    "findings": [],
                    "notes": "",
                },
            }
        }
    )
    a = flow.helper_attempt(vid)
    out = flow.run(vid, hid, a)
    refused(out, "HELPER_NOT_EXECUTED", "samples_mismatch")
    samples = flow.fake.creates("sample")
    assert len(samples) == 1 and not flow.fake.creates("target")
    h = helper_of(flow.env, vid, hid)
    assert h["blocked"] == "samples_mismatch" and h["runs"][0]["samples"][0]["outcome"] == "clean"
    assert attempt_of(flow.env, vid, a)["status"] == "unfinished"


def test_03b_each_sample_own_container_same_configuration(flow):
    vid, _hid, out = flow.executed()
    assert out.ok, out.to_text()
    samples, target = flow.fake.creates("sample"), flow.fake.creates("target")[0]
    assert len(samples) == 2

    def shape(argv):
        skip = {"--name", "--label", "--mount"}
        return [a for i, a in enumerate(argv) if a not in skip and (i == 0 or argv[i - 1] not in skip)][:-2]

    assert shape(samples[0]) == shape(samples[1]) == shape(target)


def test_m1_samples_mismatch_blocks_and_retry_refused(flow):
    vid, hid = flow.ready()
    flow.fake.set(
        runs={"sample-2": {"mode": "auto"}}, auto={**flow.fake.control["auto"], "pattern": "name: app"}
    )
    a = flow.helper_attempt(vid)
    refused(flow.run(vid, hid, a), "HELPER_NOT_EXECUTED", "samples_mismatch")
    refused(flow.run(vid, hid, a), "HELPER_NOT_EXECUTED", "blocked")


def test_m1_samples_infrastructure_retry_same_attempt(flow):
    vid, hid = flow.ready()
    flow.fake.set(deviations={"sample": {"HostConfig.Privileged": True}})
    a = flow.helper_attempt(vid)
    refused(flow.run(vid, hid, a), "HELPER_NOT_EXECUTED", "samples_infrastructure")
    assert attempt_of(flow.env, vid, a)["status"] == "unfinished"
    flow.fake.set(deviations={})
    out = flow.run(vid, hid, a)
    assert out.ok and out.data["outcome"] == "clean", out.to_text()


def test_m1_target_failed_then_retry_new_attempt_end_to_end(flow):
    vid, hid = flow.ready()
    flow.fake.set(runs={"target": {"mode": "none", "exit": 0}})
    a1 = flow.helper_attempt(vid)
    first = flow.run(vid, hid, a1)
    assert first.ok and first.data["outcome"] == "failed" and "no result" in first.data["reason"]
    assert attempt_of(flow.env, vid, a1)["status"] == "finished"
    refused(flow.run(vid, hid, a1), "ATTEMPT_INVALID")
    flow.fake.set(runs={})
    before = state_of(flow.env, vid)["budget"]["extra_used"]
    a2 = flow.helper_attempt(vid)
    assert attempt_of(flow.env, vid, a2)["extra"] == 1
    assert state_of(flow.env, vid)["budget"]["extra_used"] == before + 1
    second = flow.run(vid, hid, a2)
    assert second.ok and second.data["outcome"] == "clean" and second.data["run"] == 2


# ---------- AC-002F-04d
def test_04d_targets_identical_no_project_mount(flow):
    vid, hid = flow.ready()
    before = tree_hashes(flow.root / "src", flow.root / "README.md")
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.ok, out.to_text()
    assert tree_hashes(flow.root / "src", flow.root / "README.md") == before
    for argv in flow.fake.creates():
        for i, a in enumerate(argv):
            if a == "--mount" and "type=bind" in argv[i + 1]:
                source = argv[i + 1].split("source=", 1)[1].split(",target=")[0]
                assert "/helper-stage-" in source and source != str(flow.root)


# ---------- AC-002F-04e / M4
def test_04e_time_cap_and_timeout_failed(flow, monkeypatch):
    vid, hid = flow.ready()
    from x_ipe_secure_code.guard.helpers import model as hmodel

    monkeypatch.setitem(hmodel.L10, "target", 2)
    flow.fake.set(runs={"target": {"mode": "auto", "sleep": 6}})
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.ok and out.data["outcome"] == "failed" and out.data["limit"] == "time", out.to_text()
    assert "time limit (L-10)" in out.data["reason"]
    assert "x-ipe.secure-code.purpose=target" in flow.fake.creates("target")[0]
    assert any(r[0] == "kill" for r in flow.fake.log())


def test_04e_time_limit_capped_by_remaining_budget(flow, monkeypatch):
    vid, hid = flow.ready()
    from x_ipe_secure_code.guard import service

    real = service.consumed
    monkeypatch.setattr(service, "consumed", lambda root, state: max(real(root, state), 3600 - 50))
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.ok and out.data["time_limit"] <= 50 and out.data["time_limit_capped"] is True, out.to_text()
    assert "cpu=" in " ".join(flow.fake.creates("target")[0])


def test_m4_cpu_ulimit_and_deadline_labels_in_argv(flow):
    vid, _hid, out = flow.executed()
    argv = flow.fake.creates("target")[0]
    joined = " ".join(argv)
    assert "--ulimit cpu=120:120" in joined and "nofile=256:256" in joined
    deadline = next(a for a in argv if a.startswith("x-ipe.secure-code.deadline="))
    assert int(deadline.split("=")[1]) > time.time()
    assert any(a.startswith("x-ipe.secure-code.owner-pid=") for a in argv)
    assert argv[-5:-2] == ["-I", "-B", "/helper/launcher.py"] and argv[-2:] == ["target", "120"]


def test_dao005_ipc_none_no_shared_memory_mount(flow):
    """DAO-005 (5, DEC-I6): every helper container uses `--ipc none` (private IPC namespace without the
    writable /dev/shm tmpfs that `--ipc private` adds)."""
    flow.executed()
    for purpose in ("compile", "sample", "target"):
        for argv in flow.fake.creates(purpose):
            i = argv.index("--ipc")
            assert argv[i + 1] == "none", (purpose, argv)


def test_m4_orphan_sweep_removes_expired_and_dead_owner(flow):
    old = {
        "Config": {
            "Labels": {
                "x-ipe.secure-code": "helper",
                "x-ipe.secure-code.deadline": "1",
                "x-ipe.secure-code.owner-pid": "999999",
            }
        },
        "State": {"Running": False},
    }
    alive = {
        "Config": {
            "Labels": {
                "x-ipe.secure-code": "helper",
                "x-ipe.secure-code.deadline": str(int(time.time()) + 999),
                "x-ipe.secure-code.owner-pid": "1",
            }
        },
        "State": {"Running": True},
    }
    flow.fake.set(
        ps_extra={"xsc-old-target-1": old, "xsc-live-target-1": alive},
        volumes_extra={"xsc-old-results": {"Labels": old["Config"]["Labels"]}},
    )
    rt = mod("runtime").CliRuntime.discover()
    removed = mod("execute_io").sweep(rt)
    assert set(removed) == {"xsc-old-target-1", "xsc-old-results"}
    assert ["rm", "-f", "xsc-old-target-1"] in flow.fake.log()
    assert ["volume", "rm", "-f", "xsc-old-results"] in flow.fake.log()


# ---------- AC-002F-04g
def test_04g_paused_or_exhausted_refused(flow, monkeypatch):
    vid, hid = flow.ready()
    a = flow.helper_attempt(vid)
    assert control.pause(str(flow.root), vid, "asking the user").ok
    refused(flow.run(vid, hid, a), "RUN_PAUSED")
    assert control.resume(str(flow.root), vid).ok
    from x_ipe_secure_code.guard import service

    monkeypatch.setattr(service, "consumed", lambda root, state: 4000.0)
    refused(flow.run(vid, hid, a), "BUDGET_TIME_EXHAUSTED")
    assert not flow.fake.creates("sample") and not flow.fake.creates("target")
    events = [e["outcome"] for e in helper_of(flow.env, vid, hid)["events"] if e["step"] == "not_executed"]
    assert events == ["run_paused", "budget_time_exhausted"]


# ---------- AC-002F-04h
def test_04h_cleanup_no_container_stage_raw(flow):
    vid, hid, out = flow.executed()
    assert out.ok
    state = flow.fake.state()
    assert state["containers"] == {} and state["volumes"] == {}
    run_dir = flow.root / GUARD / vid
    assert not any(p.name.startswith("helper-stage-") for p in run_dir.iterdir())
    files = sorted(p.name for p in (run_dir / "helpers" / hid).iterdir())
    assert "result.json" not in files and "run-1-result.json" in files
    stored = json.loads((run_dir / "helpers" / hid / "run-1-result.json").read_text())
    assert set(stored) == {"schema", "helper", "status", "scanned", "findings", "notes", "masked_types"}


def test_04h_leftover_staging_swept(flow):
    vid, hid = flow.ready()
    leftover = flow.root / GUARD / vid / "helper-stage-0123456789ab" / "target" / "input"
    leftover.mkdir(parents=True)
    (leftover / "copy.yaml").write_text("x")
    assert flow.run(vid, hid, flow.helper_attempt(vid)).ok
    assert not (flow.root / GUARD / vid / "helper-stage-0123456789ab").exists()


# ---------- AC-002F-04l (orchestration twin: limit naming from runtime state)
def test_04l_limit_naming_fake(flow):
    vid, hid = flow.ready()
    flow.fake.set(runs={"target": {"mode": "none", "oom": True}})
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["outcome"] == "failed" and out.data["limit"] == "memory" and "L-06" in out.data["reason"]
    flow.fake.set(
        runs={"target": {"mode": "none", "exit": 1, "stderr": "OSError: [Errno 24] Too many open files"}}
    )
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["limit"] == "open_files", out.data
    flow.fake.set(runs={"target": {"mode": "none", "exit": 124}})
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["limit"] == "time"


# ---------- AC-002F-04m
def test_04m_stdout_flood_terminated(flow):
    vid, hid = flow.ready()
    flow.fake.set(runs={"target": {"mode": "auto", "stdout_bytes": 200000, "sleep": 3}})
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["outcome"] == "failed" and out.data["limit"] == "output", out.to_text()
    run = helper_of(flow.env, vid, hid)["runs"][0]
    assert run["diagnostics"]["truncated"] is True and len(run["diagnostics"]["stdout"]) <= 64 * 1024
    flow.fake.set(runs={"target": {"mode": "auto", "stderr_bytes": 200000, "sleep": 3}})
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["limit"] == "output"


# ---------- AC-002F-04n
def test_04n_limits_before_container(flow, monkeypatch):
    vid, hid = flow.ready()
    monkeypatch.setattr(mod("snapshot"), "L05_FILES", 1)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    refused(out, "HELPER_NOT_EXECUTED", "limit")
    assert "L-05" in out.problems[0].message
    assert not flow.fake.creates("sample") and not flow.fake.creates("target")
