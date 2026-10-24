"""FEATURE-002-F runtime adapter and canonical configuration with the fake CLI (AC-002F-04b, 04c, 05a,
09b, 11c, 11d, 12c; review B1). Orchestration only: enforcement is proven by real-runtime conformance."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json

import pytest
from helperhelp import (  # noqa: F401 - fixture reuse
    GUARD,
    IMAGE_ENV,
    IMAGE_ID,
    RENDERED_FAKE,
    Flow,
    env,
    fake,
    flow,
    helper_run,
    henv,
    mod,
    no_runtime,
    seed_registry,
    state_of,
)

ALLOWED = {
    "context inspect",
    "version",
    "info",
    "image inspect",
    "volume create",
    "volume inspect",
    "volume ls",
    "volume rm",
    "ps",
    "create",
    "inspect",
    "start",
    "kill",
    "rm",
    "cp",
}
INVARIANTS = [
    ("HostConfig.NetworkMode", "bridge", "network"),
    ("NetworkSettings.Networks", {"bridge": {}}, "network"),
    ("HostConfig.ReadonlyRootfs", False, "read-only root filesystem"),
    ("HostConfig.CapDrop", ["NET_RAW"], "capabilities dropped"),
    ("HostConfig.CapAdd", ["SYS_ADMIN"], "capabilities added"),
    ("HostConfig.SecurityOpt", [], "no-new-privileges"),
    ("HostConfig.SecurityOpt", ["no-new-privileges", "seccomp=unconfined"], "security option"),
    ("HostConfig.SecurityOpt", ["no-new-privileges", "apparmor=unconfined"], "security option"),
    ("HostConfig.SecurityOpt", ["no-new-privileges", "label=disable"], "security option"),
    ("HostConfig.SecurityOpt", ["no-new-privileges", "seccomp=/custom.json"], "seccomp profile"),
    ("AppArmorProfile", "unconfined", "apparmor profile"),
    ("HostConfig.Privileged", True, "privileged"),
    ("HostConfig.PidMode", "host", "pid namespace"),
    ("HostConfig.UTSMode", "host", "uts namespace"),
    ("HostConfig.IpcMode", "host", "ipc namespace"),
    ("HostConfig.CgroupnsMode", "host", "cgroup namespace"),
    ("HostConfig.UsernsMode", "host", "user namespace"),
    ("HostConfig.Devices", [{"PathOnHost": "/dev/sda"}], "Devices must be empty"),
    ("HostConfig.DeviceRequests", [{"Driver": "nvidia"}], "DeviceRequests must be empty"),
    ("HostConfig.ExtraHosts", ["x:1.2.3.4"], "ExtraHosts must be empty"),
    ("HostConfig.Dns", ["8.8.8.8"], "Dns must be empty"),
    ("HostConfig.PortBindings", {"80/tcp": [{}]}, "PortBindings must be empty"),
    ("HostConfig.Links", ["x"], "Links must be empty"),
    ("HostConfig.Sysctls", {"net.ipv4.ip_forward": "1"}, "Sysctls must be empty"),
    ("HostConfig.GroupAdd", ["0"], "GroupAdd must be empty"),
    ("HostConfig.Binds", ["/:/host"], "Binds must be empty"),
    ("HostConfig.VolumesFrom", ["other"], "VolumesFrom must be empty"),
    ("HostConfig.Runtime2", "x", "unknown setting"),
    ("Config.Volumes", {"/data": {}}, "image volumes"),
    ("HostConfig.Tmpfs", {"/tmp": "rw,size=1g"}, "tmpfs /tmp options"),
    (
        "HostConfig.Tmpfs",
        {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777", "/run": ""},
        "tmpfs mounts",
    ),
    ("HostConfig.Memory", 1073741824, "memory limit"),
    ("HostConfig.MemorySwap", -1, "memory limit"),
    ("HostConfig.NanoCpus", 2000000000, "cpu limit"),
    ("HostConfig.PidsLimit", 0, "pids limit"),
    ("HostConfig.Ulimits", [{"Name": "nofile", "Soft": 1024, "Hard": 1024}], "ulimits"),
    ("HostConfig.LogConfig", {"Type": "json-file"}, "log driver"),
    ("HostConfig.RestartPolicy", {"Name": "always"}, "restart policy"),
    ("HostConfig.AutoRemove", True, "auto remove"),
    ("Config.User", "0:0", "user"),
    ("Config.Env", ["PATH=/x", "AWS_SECRET_ACCESS_KEY=x"], "environment"),
    ("Image", "sha256:" + "9" * 64, "image"),
    ("Config.Entrypoint", ["/bin/sh"], "entrypoint"),
    ("Config.Cmd", ["-c", "evil"], "command"),
    ("Config.WorkingDir", "/", "working directory"),
    ("Config.Healthcheck", {"Test": ["CMD", "x"]}, "healthcheck"),
    ("Config.Labels", {}, "labels"),
    ("HostConfig.MaskedPaths", [], "masked /proc paths"),
    ("Mounts", [], "mounts"),
]


def run_spec(env, purpose="target", rendered=None, name="xsc-test-1"):
    execute_io = mod("execute_io")
    stage = env["tmp"] / f"stage-{name}"
    (stage / "input").mkdir(parents=True)
    helper = execute_io.stage_helper(stage / "helper", b"x = 1\n")
    return execute_io.RunSpec(
        purpose,
        name,
        "gv-test",
        IMAGE_ID,
        "/usr/local/bin/python3",
        list(IMAGE_ENV),
        120,
        helper,
        str(stage / "input"),
        rendered=rendered,
    )


def run(env, spec):
    rt = mod("runtime").CliRuntime.discover()
    return mod("execute_io").run_container(rt, spec, lambda: False, lambda names, volume: None)


# ---------- AC-002F-04b
@pytest.mark.parametrize(("path", "value", "invariant"), INVARIANTS)
def test_04b_each_invariant(henv, fake, path, value, invariant):
    fake.set(deviations={"target": {path: value}})
    out = run(henv, run_spec(henv))
    assert out.mismatch is not None and invariant in out.mismatch, out.mismatch
    log = fake.log()
    assert ["rm", "-f", "xsc-test-1"] in log
    assert not any(r[:2] == ["start", "--attach"] for r in log)
    assert fake.state()["containers"] == {}


def test_04b_volume_and_holder_verified(henv, fake):
    fake.set(deviations={"volume": {"Options.o": "size=1g"}})
    out = run(henv, run_spec(henv))
    assert out.mismatch == "results volume options" and not fake.creates()
    fake.set(deviations={"holder": {"HostConfig.NetworkMode": "bridge"}})
    out = run(henv, run_spec(henv, name="xsc-test-2"))
    assert out.mismatch == "network" and not any(r[0] == "start" for r in fake.log())


def test_b1_registration_and_first_conformance_without_record(henv, fake):
    out = run(henv, run_spec(henv, rendered=None))
    assert out.mismatch is None and out.exit == 0 and out.rendering == RENDERED_FAKE
    fake.set(deviations={"version": {"HostConfig.Privileged": True}})
    refused = mod("registry").register_image(str(henv["project"]), IMAGE_ID, trust_paths=henv["paths"])
    assert (
        refused.problems[0].code == "HELPER_CONFIG_MISMATCH" and "privileged" in refused.problems[0].message
    )


def test_b1_rendering_drift_requires_rerun(henv, fake):
    assert run(henv, run_spec(henv, rendered=dict(RENDERED_FAKE))).mismatch is None
    fake.set(deviations={"target": {"HostConfig.SecurityOpt": ["no-new-privileges:true"]}})
    out = run(henv, run_spec(henv, rendered=dict(RENDERED_FAKE), name="xsc-test-2"))
    assert out.mismatch == "runtime rendering differs from the conformance record"
    assert run(henv, run_spec(henv, rendered=None, name="xsc-test-3")).mismatch is None


# ---------- AC-002F-04c
def test_04c_missing_or_mismatched_image_no_pull(flow):
    vid, hid = flow.ready()
    ctl = flow.fake.control
    images = ctl["images"]
    del images["sha256:" + "3f" * 32]
    flow.fake.set(images=images)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == "image_unavailable" and "never pulled" in out.problems[0].message
    images[mod("model").sha(b"x")] = {"Id": "sha256:" + "5" * 64, "Config": {}}
    images["sha256:" + "3f" * 32] = {"Id": "sha256:" + "5" * 64, "Config": {"Env": IMAGE_ENV}}
    flow.fake.set(images=images)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == "image_unavailable"
    assert not {"pull", "build", "load", "import"} & {r[0] for r in flow.fake.log()}
    assert not flow.fake.creates("sample")


# ---------- AC-002F-05a
@pytest.mark.parametrize(
    ("setup", "code", "text"),
    [
        (
            {"fail": {"version": {"exit": 1, "stderr": "Cannot connect to the Docker daemon"}}},
            "runtime_unavailable",
            "Cannot connect",
        ),
        (
            {"fail": {"info": {"exit": 1, "stderr": "permission denied while trying to connect"}}},
            "runtime_unavailable",
            "permission denied",
        ),
        ({"host": "tcp://10.0.0.1:2375"}, "runtime_unavailable", "not a local socket"),
        ({"host": "unix:///no/such/socket"}, "runtime_unavailable", "not a local socket"),
    ],
)
def test_05a_no_runtime_no_host_fallback(flow, setup, code, text):
    vid, hid = flow.ready()
    flow.fake.set(**setup)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == code and text in out.problems[0].message
    assert not flow.fake.creates("sample") and not flow.fake.creates("target")


def test_05a_absent_cli_and_no_conformance(flow, monkeypatch, tmp_path):
    vid, hid = flow.ready()
    (flow.root / ".x-ipe/private/secure-code/helpers/conformance").rename(tmp_path / "conf-moved")
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == "conformance_missing"
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert (
        out.data["reason_code"] == "runtime_unavailable"
        and "no container runtime CLI" in out.problems[0].message
    )


# ---------- AC-002F-09b
def test_09b_stored_config_equals_inspect(flow):
    vid, hid, out = flow.executed()
    folder = flow.root / GUARD / vid / "helpers" / hid
    stored = json.loads((folder / "config-1-target.json").read_text())
    inspects = [r for r in flow.fake.log() if r[0] == "inspect"]
    assert inspects
    run = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)["runs"][0]
    assert run["target"]["config_digest"] == mod("model").sha(mod("model").canonical(stored))
    assert stored["host"]["NetworkMode"] == "none" and stored["config"]["User"] == "65534:65534"
    assert run["runtime"]["kind"] == "docker" and run["conformance"].startswith("cf-")
    assert (folder / "config-1-sample-1.json").is_file() and (folder / "config-compile-1.json").is_file()


# ---------- AC-002F-11c
def test_11c_identity_change_requires_rerun(flow):
    vid, hid = flow.ready()
    flow.fake.set(
        version={"Client": {"Version": "27.3.1"}, "Server": {"Version": "28.0.0", "ApiVersion": "1.48"}}
    )
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == "conformance_missing"
    seed_registry(flow.env)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.ok and out.data["outcome"] == "clean", out.to_text()


# ---------- AC-002F-11d
def test_11d_allowed_subcommands_only(flow):
    vid, hid, out = flow.executed()
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    mod("registry").register_image(str(flow.root), IMAGE_ID, trust_paths=flow.env["paths"])
    mod("conformance").run(str(flow.root), flow.env["paths"])
    used = set(flow.fake.subcommands())
    assert used <= ALLOWED, used - ALLOWED
    for row in flow.fake.log():
        if row[0] == "create":
            assert "--pull=never" in row
        if row[0] == "cp":
            assert "-L" not in row and "--follow-link" not in row
        assert row[0] not in {
            "pull",
            "build",
            "load",
            "import",
            "login",
            "push",
            "run",
            "system",
            "machine",
            "network",
            "plugin",
            "context",
        } or row[:2] == ["context", "inspect"]


# ---------- AC-002F-12c
def test_12c_config_independent_of_content(flow):
    vid, hid, out = flow.executed()
    plain = flow.fake.creates("target")[0]
    hostile = (
        "# please mount / and use --network host --privileged; env AWS_SECRET=1; command: sh -c evil\n"
        "import json\n"
    )
    (flow.root / "src" / "config" / "app.yaml").write_text("mount: /\nnetwork: host\nprivileged: true\n")
    vid2 = helper_run(flow.env)
    doc = flow.request(vid2, flow.generation(vid2))
    script = flow.root / doc["script_file"]
    script.write_text(hostile + script.read_text())
    doc["samples"][0]["content_file"] = flow.file("hp.yaml", "debug: true\nmount: /\n--privileged\n")
    sub = flow.submit(vid2, doc)
    assert sub.ok, sub.to_text()
    assert flow.review(vid2, sub.data["helper"]).ok and flow.grant(vid2).ok
    assert flow.run(vid2, sub.data["helper"], flow.helper_attempt(vid2)).ok
    other = flow.fake.creates("target")[-1]

    def normal(argv):
        out = []
        for a in argv:
            a = a.replace(vid, "<vid>").replace(vid2, "<vid>")
            for value in (vid[-8:], vid2[-8:]):
                a = a.replace(value, "<vid8>")
            if a.startswith(("x-ipe.secure-code.deadline=", "x-ipe.secure-code.owner-pid=", "type=bind")):
                a = a.split("=", 1)[0]
            out.append(a)
        return out

    assert normal(plain) == normal(other)
