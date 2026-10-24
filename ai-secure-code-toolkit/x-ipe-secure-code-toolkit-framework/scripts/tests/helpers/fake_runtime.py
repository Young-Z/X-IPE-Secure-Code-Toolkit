"""Test double of a Docker-compatible container CLI for FEATURE-002-F orchestration tests.

Tests copy this file into an executable named `docker` with an absolute interpreter and an embedded
`CONTROL` path (the toolkit passes a sanitized environment, so no variable reaches this program). It
never executes a helper script: run outcomes are scripted by the control file, or computed in `auto` mode
by searching the staged `/input` copy for a pattern. Every argv is appended to `<dir>/log.jsonl`;
containers and volumes live in `<dir>/state.json`.

Control keys: host, version, info, images, fail {subcommand: {exit, stderr}}, deviations {purpose: {dotted
path: value}}, runs {purpose | sample-<k> | target: behaviour}, auto {helper, rule, pattern}, ps_extra,
volumes_extra, cp_follow (simulate a runtime that dereferences links). Behaviour: mode (auto | result |
tar | stdout | none), result, members, stdout, stdout_bytes, stderr, stderr_bytes, exit, oom, sleep.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tarfile
import time
from pathlib import Path

CONTROL = Path(os.environ.get("FAKE_RUNTIME_CONTROL_PATH", "control.json"))  # replaced when installed


def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


CTL = load(CONTROL, {})
DIR = CONTROL.parent
STATE_PATH = DIR / "state.json"
STATE = load(STATE_PATH, {"containers": {}, "volumes": {}})


def save() -> None:
    STATE_PATH.write_text(json.dumps(STATE), encoding="utf-8")


def log(argv: list[str]) -> None:
    with open(DIR / "log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(argv) + "\n")


def out(data) -> None:
    sys.stdout.write(data if isinstance(data, str) else json.dumps(data))
    sys.stdout.write("\n")


def opt_values(args: list[str], name: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == name]


def set_path(doc: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    for part in parts[:-1]:
        doc = doc.setdefault(part, {})
    if value == "__delete__":
        doc.pop(parts[-1], None)
    else:
        doc[parts[-1]] = value


def parse_create(args: list[str]) -> dict:
    """Build an inspect document the way Docker renders these `create` options."""
    flags_with_value = {
        "--name",
        "--label",
        "--network",
        "--security-opt",
        "--ipc",
        "--cgroupns",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--ulimit",
        "--user",
        "--workdir",
        "--log-driver",
        "--restart",
        "--env",
        "--tmpfs",
        "--mount",
        "--entrypoint",
        "--cap-drop",
        "--pull",
    }
    opts: dict[str, list[str]] = {}
    i, rest = 0, []
    while i < len(args):
        a = args[i]
        if a.startswith("--pull="):
            opts.setdefault("--pull", []).append(a.split("=", 1)[1])
        elif a in flags_with_value:
            opts.setdefault(a, []).append(args[i + 1])
            i += 1
        elif a.startswith("--"):
            opts.setdefault(a, []).append("true")
        else:
            rest = args[i:]
            break
        i += 1
    image, cmd = rest[0], rest[1:]
    labels = dict(x.split("=", 1) for x in opts.get("--label", []))
    image_doc = (CTL.get("images") or {}).get(image) or {}
    env = {e.split("=", 1)[0]: e for e in (image_doc.get("Config") or {}).get("Env", [])}
    for e in opts.get("--env", []):
        env[e.split("=", 1)[0]] = e
    mounts_hc, mounts = [], []
    for m in opts.get("--mount", []):
        kv = dict(p.split("=", 1) if "=" in p else (p, "true") for p in m.split(","))
        ro = "readonly" in kv
        if kv["type"] == "bind":
            mounts_hc.append({"Type": "bind", "Source": kv["source"], "Target": kv["target"], "ReadOnly": ro})
            mounts.append({"Type": "bind", "Source": kv["source"], "Destination": kv["target"], "RW": not ro})
        else:
            mounts_hc.append(
                {
                    "Type": "volume",
                    "Source": kv["source"],
                    "Target": kv["target"],
                    **({"ReadOnly": True} if ro else {}),
                }
            )
            mounts.append({"Type": "volume", "Name": kv["source"], "Destination": kv["target"], "RW": not ro})
    tmpfs = dict(t.split(":", 1) for t in opts.get("--tmpfs", []))
    ulimits = []
    for u in opts.get("--ulimit", []):
        name, vals = u.split("=", 1)
        soft, hard = vals.split(":")
        ulimits.append({"Name": name, "Soft": int(soft), "Hard": int(hard)})
    memory = int(opts.get("--memory", ["0"])[0])
    doc = {
        "Id": "c" * 64,
        "Name": "/" + opts["--name"][0],
        "Image": image if image.startswith("sha256:") else image_doc.get("Id", image),
        "Path": opts.get("--entrypoint", [""])[0],
        "Args": cmd,
        "AppArmorProfile": "",
        "State": {"Status": "created", "Running": False, "OOMKilled": False, "ExitCode": 0},
        "Mounts": mounts,
        "NetworkSettings": {"Networks": {opts.get("--network", ["bridge"])[0]: {}}},
        "Config": {
            "User": opts.get("--user", [""])[0],
            "Env": sorted(env.values()),
            "Cmd": cmd,
            "Entrypoint": opts.get("--entrypoint"),
            "WorkingDir": opts.get("--workdir", [""])[0],
            "Labels": labels,
            "Volumes": None,
            "Healthcheck": {"Test": ["NONE"]} if "--no-healthcheck" in opts else None,
            "Image": image,
        },
        "HostConfig": {
            "Binds": None,
            "NetworkMode": opts.get("--network", ["bridge"])[0],
            "LogConfig": {"Type": opts.get("--log-driver", ["json-file"])[0], "Config": {}},
            "RestartPolicy": {"Name": opts.get("--restart", [""])[0], "MaximumRetryCount": 0},
            "AutoRemove": False,
            "VolumesFrom": None,
            "CapAdd": None,
            "CapDrop": opts.get("--cap-drop"),
            "CgroupnsMode": opts.get("--cgroupns", [""])[0],
            "Dns": None,
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": None,
            "GroupAdd": None,
            "IpcMode": opts.get("--ipc", ["shareable"])[0],
            "Links": None,
            "PidMode": "",
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": "--read-only" in opts,
            "SecurityOpt": opts.get("--security-opt"),
            "Tmpfs": tmpfs,
            "UTSMode": "",
            "UsernsMode": "",
            "ShmSize": 67108864,
            "Runtime": "runc",
            "Memory": memory,
            "NanoCpus": int(float(opts.get("--cpus", ["0"])[0]) * 1e9),
            "MemorySwap": int(opts.get("--memory-swap", ["0"])[0]),
            "PidsLimit": int(opts.get("--pids-limit", ["0"])[0]),
            "Ulimits": ulimits,
            "Devices": [],
            "DeviceCgroupRules": None,
            "DeviceRequests": None,
            "Mounts": mounts_hc,
            "PortBindings": {},
            "Sysctls": None,
            "CpuPeriod": 0,
            "CpuQuota": 0,
            "MaskedPaths": ["/proc/kcore"],
            "ReadonlyPaths": ["/proc/sys"],
            "OomScoreAdj": 0,
        },
    }
    for dotted, value in (
        (CTL.get("deviations") or {}).get(labels.get("x-ipe.secure-code.purpose", ""), {})
    ).items():
        set_path(doc, dotted, value)
    return doc


def behaviour(name: str) -> dict:
    labels = STATE["containers"][name]["Config"]["Labels"]
    purpose = labels.get("x-ipe.secure-code.purpose", "")
    runs = CTL.get("runs") or {}
    key = purpose
    m = re.search(r"-(sample)-(\d+)$", name)
    if m and f"sample-{m.group(2)}" in runs:
        key = f"sample-{m.group(2)}"
    named = next((v for k, v in runs.items() if k.startswith("name:") and k[5:] in name), None)
    found = named or runs.get(key) or runs.get(purpose)
    if found is not None:
        return found
    if purpose == "version":
        return {
            "mode": "stdout",
            "stdout": json.dumps(
                {"version": [3, 12, 4], "implementation": "cpython", "executable": "/usr/local/bin/python3"}
            ),
        }
    if purpose == "compile":
        return {"mode": "stdout", "stdout": json.dumps({"ok": True, "version": [3, 12, 4], "error": ""})}
    return {"mode": "auto"}


def mount_source(doc: dict, target: str) -> str | None:
    for m in doc["HostConfig"]["Mounts"]:
        if m["Target"] == target:
            return m["Source"]
    return None


def auto_result(doc: dict) -> dict:
    spec = CTL.get("auto") or {}
    base = Path(mount_source(doc, "/input") or ".")
    scanned, findings = [], []
    for path in sorted(p for p in base.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(base).as_posix()
        scanned.append(rel)
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if spec.get("pattern", "debug: true") in line:
                findings.append(
                    {
                        "path": rel,
                        "line": n,
                        "rule": spec.get("rule", ""),
                        "title": "debug enabled",
                        "excerpt": line[:200],
                        "basis": "key debug is true",
                    }
                )
    skip = set(spec.get("skip_scanned") or [])
    return {
        "schema": "x-ipe-helper-result/1",
        "helper": spec.get("helper", ""),
        "status": "complete",
        "scanned": [s for s in scanned if s not in skip],
        "findings": findings,
        "notes": spec.get("notes", ""),
    }


def start_attach(name: str) -> int:
    doc = STATE["containers"][name]
    doc["State"].update(Status="running", Running=True)
    save()
    b = behaviour(name)
    if b.get("sleep"):
        time.sleep(float(b["sleep"]))
    if b.get("stdout"):
        sys.stdout.write(b["stdout"] + "\n")
    if b.get("stdout_bytes"):
        sys.stdout.write("x" * int(b["stdout_bytes"]))
    if b.get("stderr"):
        sys.stderr.write(b["stderr"])
    if b.get("stderr_bytes"):
        sys.stderr.write("e" * int(b["stderr_bytes"]))
    sys.stdout.flush()
    sys.stderr.flush()
    volume = next((m["Name"] for m in doc["Mounts"] if m["Destination"] == "/results"), None)
    mode = b.get("mode", "auto")
    members = None
    if mode == "auto":
        members = [
            {"name": "results", "type": "dir"},
            {"name": "results/result.json", "data": json.dumps(auto_result(doc))},
        ]
    elif mode == "result":
        data = b["result"] if isinstance(b["result"], str) else json.dumps(b["result"])
        members = [{"name": "results", "type": "dir"}, {"name": "results/result.json", "data": data}]
    elif mode == "tar":
        members = b["members"]
    elif mode == "none":
        members = [{"name": "results", "type": "dir"}]
    if volume and members is not None and volume in STATE["volumes"]:
        STATE["volumes"][volume]["members"] = members
    code = int(b.get("exit", 0))
    if b.get("oom"):
        doc["State"]["OOMKilled"], code = True, 137
    doc["State"].update(Status="exited", Running=False, ExitCode=code)
    save()
    return code


def tar_stream(members: list[dict]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for m in members:
            info = tarfile.TarInfo(m["name"])
            info.uid = info.gid = int(m.get("uid", 65534))
            kind = m.get("type", "file")
            data = m.get("data", "").encode("utf-8")
            if kind == "dir":
                info.type, info.mode = tarfile.DIRTYPE, 0o700
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, m.get("linkname", "/input/probe.txt")
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, m.get("linkname", "results/other")
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            elif kind == "pax":
                info.pax_headers = {"path": m.get("linkname", "etc/passwd")}
                info.size = len(data)
            else:
                info.size = int(m.get("size", len(data)))
            if info.type == tarfile.REGTYPE or kind == "pax":
                tar.addfile(info, io.BytesIO(data.ljust(info.size, b" ")))
            else:
                tar.addfile(info)
    raw = buf.getvalue()
    return raw[: int(CTL["truncate_tar"])] if CTL.get("truncate_tar") else raw


def main(argv: list[str]) -> int:
    log(argv)
    args = list(argv)
    if args[:1] == ["-H"]:
        args = args[2:]
    sub = " ".join(args[:2])
    for key, failure in (CTL.get("fail") or {}).items():
        if " ".join(args).startswith(key):
            sys.stderr.write(failure.get("stderr", "error"))
            return int(failure.get("exit", 1))
    if sub == "context inspect":
        out([{"Name": "default", "Endpoints": {"docker": {"Host": CTL.get("host", "")}}}])
        return 0
    if args[0] == "version":
        out(
            CTL.get("version")
            or {"Client": {"Version": "27.3.1"}, "Server": {"Version": "27.3.1", "ApiVersion": "1.47"}}
        )
        return 0
    if args[0] == "info":
        out(CTL.get("info") or {})
        return 0
    if sub == "image inspect":
        doc = (CTL.get("images") or {}).get(args[2])
        if doc is None:
            sys.stderr.write(f"Error: No such image: {args[2]}")
            return 1
        out([doc])
        return 0
    if sub == "volume create":
        name = args[-1]
        STATE["volumes"][name] = {
            "Name": name,
            "Driver": opt_values(args, "--driver")[0],
            "Options": dict(o.split("=", 1) for o in opt_values(args, "--opt")),
            "Labels": dict(lbl.split("=", 1) for lbl in opt_values(args, "--label")),
        }
        for dotted, value in ((CTL.get("deviations") or {}).get("volume", {})).items():
            set_path(STATE["volumes"][name], dotted, value)
        save()
        out(name)
        return 0
    if sub == "volume inspect":
        doc = STATE["volumes"].get(args[2])
        if doc is None:
            sys.stderr.write("Error: no such volume")
            return 1
        out([{k: v for k, v in doc.items() if k != "members"}])
        return 0
    if sub == "volume rm":
        STATE["volumes"].pop(args[-1], None)
        save()
        return 0
    if sub == "volume ls":
        for name, doc in list(STATE["volumes"].items()) + list((CTL.get("volumes_extra") or {}).items()):
            out({"Name": name, "Labels": ",".join(f"{k}={v}" for k, v in doc.get("Labels", {}).items())})
        return 0
    if args[:2] == ["ps", "-a"]:
        for name, doc in list(STATE["containers"].items()) + list((CTL.get("ps_extra") or {}).items()):
            labels = doc["Config"]["Labels"]
            out(
                {
                    "Names": name,
                    "State": "running" if doc["State"].get("Running") else "exited",
                    "Labels": ",".join(f"{k}={v}" for k, v in labels.items()),
                }
            )
        return 0
    if args[0] == "create":
        doc = parse_create(args[1:])
        STATE["containers"][doc["Name"][1:]] = doc
        save()
        out(doc["Id"])
        return 0
    if args[0] == "inspect":
        doc = STATE["containers"].get(args[-1])
        if doc is None:
            sys.stderr.write("Error: No such object")
            return 1
        out([doc])
        return 0
    if args[0] == "start" and "--attach" in args:
        return start_attach(args[-1])
    if args[0] == "start":
        STATE["containers"][args[-1]]["State"].update(Status="running", Running=True)
        save()
        return 0
    if args[0] == "kill":
        if args[-1] in STATE["containers"]:
            STATE["containers"][args[-1]]["State"].update(Status="exited", Running=False, ExitCode=137)
            save()
        return 0
    if args[:2] == ["rm", "-f"]:
        doc = STATE["containers"].get(args[-1]) or {}
        purpose = ((doc.get("Config") or {}).get("Labels") or {}).get("x-ipe.secure-code.purpose")
        fails = CTL.get("rm_fails")
        if not fails or (fails is not True and fails != purpose):
            STATE["containers"].pop(args[-1], None)
            save()
        return 0
    if args[0] == "cp":
        holder = args[1].split(":", 1)[0]
        doc = STATE["containers"].get(holder)
        volume = (
            next((m["Name"] for m in doc["Mounts"] if m["Destination"] == "/results"), None) if doc else None
        )
        members = (STATE["volumes"].get(volume) or {}).get("members") or [{"name": "results", "type": "dir"}]
        if CTL.get("cp_follow"):
            members = [
                dict(m, type="file", data="root:x:0:0") if m.get("type") == "symlink" else m for m in members
            ]
        sys.stdout.buffer.write(tar_stream(members))
        return 0
    sys.stderr.write(f"fake runtime: unsupported {' '.join(args)}")
    return 125


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
