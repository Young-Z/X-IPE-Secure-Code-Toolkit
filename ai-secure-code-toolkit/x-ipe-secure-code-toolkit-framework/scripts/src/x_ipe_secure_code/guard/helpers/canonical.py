"""Canonical container configuration (FR-002F-5, design §8.2/§8.3).

`create_args` builds the exact `create` arguments from toolkit constants, the registration record and
validated ids/paths only (never from script, sample or target content). `verify` reads the runtime's
own inspect output back: layer 1 checks every invariant by meaning (closed sets of spellings, no learned
values; needs no conformance record), layer 2 requires the rendering-sensitive raw values to equal the
conformance record's `rendered` snapshot. Any failure names the first failing invariant.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from .model import L06_MEMORY, L06_NANO_CPUS, L06_NOFILE, L06_PIDS, L07_TMP, L08_AREA, L08_INODES

LABEL = "x-ipe.secure-code"
TOOLKIT_ENV = {"LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
TMPFS = {"rw", "noexec", "nosuid", "nodev", f"size={L07_TMP}", "mode=1777"}
TMPFS_ARG = f"/tmp:rw,noexec,nosuid,nodev,size={L07_TMP},mode=1777"
VOLUME_OPTS = f"size={L08_AREA},nr_inodes={L08_INODES},uid=65534,gid=65534,mode=0700,nosuid,nodev,noexec"
USER = "65534:65534"
NNP = {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
UNSAFE_OPTS = re.compile(
    r"(?:seccomp|apparmor)[=:]unconfined|label[=:]disable|systempaths[=:]unconfined|"
    r"label[=:]type:[^,]*unconfined|privileged",
    re.I,
)
MOUNTS = {
    "version": {"/helper": "ro"},
    "compile": {"/helper": "ro"},
    "sample": {"/input": "ro", "/helper": "ro", "/results": "rw"},
    "target": {"/input": "ro", "/helper": "ro", "/results": "rw"},
    "holder": {"/results": "ro"},
}
HOLDER_SLACK = 30
EMPTY_HOST = {
    "Binds",
    "ContainerIDFile",
    "VolumeDriver",
    "VolumesFrom",
    "CapAdd",
    "Dns",
    "DnsOptions",
    "DnsSearch",
    "ExtraHosts",
    "GroupAdd",
    "Cgroup",
    "Links",
    "OomScoreAdj",
    "PublishAllPorts",
    "Isolation",
    "CpuShares",
    "CgroupParent",
    "BlkioWeight",
    "BlkioWeightDevice",
    "BlkioDeviceReadBps",
    "BlkioDeviceWriteBps",
    "BlkioDeviceReadIOps",
    "BlkioDeviceWriteIOps",
    "CpuRealtimePeriod",
    "CpuRealtimeRuntime",
    "CpusetCpus",
    "CpusetMems",
    "Devices",
    "DeviceCgroupRules",
    "DeviceRequests",
    "MemoryReservation",
    "OomKillDisable",
    "CpuCount",
    "CpuPercent",
    "IOMaximumIOps",
    "IOMaximumBandwidth",
    "PortBindings",
    "Sysctls",
    "KernelMemory",
    "KernelMemoryTCP",
    "Init",
    "Annotations",
}
INFORMATIONAL_HOST = {"ConsoleSize", "ShmSize", "Runtime", "MemorySwappiness", "MaskedPaths", "ReadonlyPaths"}
CHECKED_HOST = {
    "NetworkMode",
    "ReadonlyRootfs",
    "CapDrop",
    "SecurityOpt",
    "Privileged",
    "PidMode",
    "UTSMode",
    "IpcMode",
    "CgroupnsMode",
    "UsernsMode",
    "Mounts",
    "Tmpfs",
    "Memory",
    "MemorySwap",
    "NanoCpus",
    "CpuPeriod",
    "CpuQuota",
    "PidsLimit",
    "Ulimits",
    "LogConfig",
    "RestartPolicy",
    "AutoRemove",
}
RENDERING = (
    "SecurityOpt",
    "IpcMode",
    "CgroupnsMode",
    "UsernsMode",
    "Tmpfs",
    "RestartPolicy",
    "AppArmorProfile",
)


class ConfigMismatch(Exception):
    def __init__(self, invariant: str) -> None:
        super().__init__(invariant)
        self.invariant = invariant


@dataclass
class Spec:
    """Everything one container start is built from (toolkit-owned values only)."""

    purpose: str
    name: str
    image: str
    interpreter: str
    image_env: list[str]
    labels: dict[str, str]
    limit: int
    stage_input: str | None = None
    stage_helper: str | None = None
    volume: str | None = None
    holder_seconds: int = 0
    mounts: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.mounts = dict(MOUNTS["holder" if self.purpose == "holder" else self.purpose])

    @property
    def cmd(self) -> list[str]:
        if self.purpose == "holder":
            return ["-I", "-B", "-c", f"import time; time.sleep({self.holder_seconds})"]
        return ["-I", "-B", "/helper/launcher.py", self.purpose, str(self.limit)]

    @property
    def env(self) -> list[str]:
        merged = {e.split("=", 1)[0]: e for e in self.image_env}
        path = merged.get("PATH", "PATH=/usr/local/bin:/usr/bin:/bin")
        merged["PATH"] = path
        for key, value in TOOLKIT_ENV.items():
            merged[key] = f"{key}={value}"
        return sorted(merged.values())

    def env_args(self) -> list[str]:
        merged = {e.split("=", 1)[0]: e for e in self.env}
        return [merged["PATH"]] + [f"{k}={v}" for k, v in TOOLKIT_ENV.items()]


def labels(verification: str, purpose: str, deadline: int) -> dict[str, str]:
    return {
        LABEL: "helper",
        f"{LABEL}.verification": verification,
        f"{LABEL}.purpose": purpose,
        f"{LABEL}.owner-pid": str(os.getpid()),
        f"{LABEL}.deadline": str(deadline),
    }


def volume_args(name: str, label_map: dict[str, str]) -> list[str]:
    args = [
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=tmpfs",
        "--opt",
        "device=tmpfs",
        "--opt",
        f"o={VOLUME_OPTS}",
    ]
    for key, value in sorted(label_map.items()):
        args += ["--label", f"{key}={value}"]
    return [*args, name]


def verify_volume(doc: dict[str, Any] | None, label_map: dict[str, str]) -> None:
    if not doc or doc.get("Driver") != "local":
        raise ConfigMismatch("results volume driver")
    if doc.get("Options") != {"type": "tmpfs", "device": "tmpfs", "o": VOLUME_OPTS}:
        raise ConfigMismatch("results volume options")
    if (doc.get("Labels") or {}) != label_map:
        raise ConfigMismatch("results volume labels")


def create_args(spec: Spec) -> list[str]:
    """`create` arguments of the canonical configuration (the image and command come last)."""
    args = ["create", "--pull=never", "--name", spec.name]
    for key, value in sorted(spec.labels.items()):
        args += ["--label", f"{key}={value}"]
    args += [
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--ipc",
        "none",
        "--cgroupns",
        "private",
        "--pids-limit",
        str(L06_PIDS),
        "--memory",
        str(L06_MEMORY),
        "--memory-swap",
        str(L06_MEMORY),
        "--cpus",
        "1.0",
        "--ulimit",
        f"nofile={L06_NOFILE}:{L06_NOFILE}",
        "--ulimit",
        f"cpu={spec.limit}:{spec.limit}",
        "--user",
        USER,
        "--workdir",
        "/tmp",
        "--log-driver",
        "none",
        "--restart",
        "no",
        "--no-healthcheck",
    ]
    for item in spec.env_args():
        args += ["--env", item]
    args += ["--tmpfs", TMPFS_ARG]
    for source in (spec.stage_input, spec.stage_helper):
        if source is not None and any(c in source for c in ',"\n'):
            raise ConfigMismatch("staging path not representable in a mount option (comma, quote or newline)")
    if "/input" in spec.mounts:
        args += ["--mount", f"type=bind,source={spec.stage_input},target=/input,readonly"]
    if "/helper" in spec.mounts:
        args += ["--mount", f"type=bind,source={spec.stage_helper},target=/helper,readonly"]
    if "/results" in spec.mounts:
        ro = ",readonly" if spec.mounts["/results"] == "ro" else ""
        args += ["--mount", f"type=volume,source={spec.volume},target=/results{ro}"]
    return [*args, "--entrypoint", spec.interpreter, spec.image, *spec.cmd]


# --------------------------------------------------------------------------- verification
def _norm_cap(value: str) -> str:
    text = str(value).upper()
    return text[4:] if text.startswith("CAP_") else text


def _size(text: str) -> str:
    m = re.fullmatch(r"size=(\d+)([kmg]?)", text.lower())
    if not m:
        return text
    return f"size={int(m.group(1)) * {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}[m.group(2)]}"


def _empty(value: Any) -> bool:
    return value in (None, "", 0, False, [], {}, "0")


def _require(ok: bool, invariant: str) -> None:
    if not ok:
        raise ConfigMismatch(invariant)


def normalized(doc: dict[str, Any]) -> dict[str, Any]:
    """The audit view of an inspect document (AC-002F-09b)."""
    host, config = doc.get("HostConfig") or {}, doc.get("Config") or {}
    keys = sorted(
        CHECKED_HOST | {"Devices", "DeviceRequests", "ExtraHosts", "Dns", "PortBindings", "Sysctls"}
    )
    return {
        "host": {k: host.get(k) for k in keys},
        "mounts": doc.get("Mounts"),
        "networks": sorted((doc.get("NetworkSettings") or {}).get("Networks") or {}),
        "config": {
            k: config.get(k)
            for k in ("User", "Env", "Cmd", "Entrypoint", "WorkingDir", "Healthcheck", "Labels", "Volumes")
        },
        "image": doc.get("Image"),
        "apparmor": doc.get("AppArmorProfile"),
    }


def rendering(doc: dict[str, Any]) -> dict[str, Any]:
    host = doc.get("HostConfig") or {}
    out = {k: host.get(k) for k in RENDERING if k != "AppArmorProfile"}
    out["RestartPolicy"] = (host.get("RestartPolicy") or {}).get("Name")
    out["AppArmorProfile"] = doc.get("AppArmorProfile")
    return out


def verify(doc: dict[str, Any] | None, spec: Spec, rendered: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check a created (not started) container against `spec`; return its normalized configuration."""
    _require(isinstance(doc, dict), "inspect output missing")
    host, config = doc.get("HostConfig") or {}, doc.get("Config") or {}
    _require(host.get("NetworkMode") == "none", "network")
    _require(set((doc.get("NetworkSettings") or {}).get("Networks") or {}) <= {"none"}, "network")
    _require(host.get("ReadonlyRootfs") is True, "read-only root filesystem")
    _require({_norm_cap(c) for c in host.get("CapDrop") or []} == {"ALL"}, "capabilities dropped")
    _require(_empty(host.get("CapAdd")), "capabilities added")
    options = [str(o) for o in host.get("SecurityOpt") or []]
    _require(any(o in NNP for o in options), "no-new-privileges")
    for o in options:
        _require(not UNSAFE_OPTS.search(o), f"security option {o}")
        if o.startswith(("seccomp=", "seccomp:")):
            _require(o.split("=", 1)[-1].split(":", 1)[-1] in ("builtin", "default"), "seccomp profile")
    apparmor = doc.get("AppArmorProfile") or ""
    _require(
        apparmor in ("", "docker-default") or apparmor.startswith("containers-default"), "apparmor profile"
    )
    _require(host.get("Privileged") is False, "privileged")
    _require(host.get("PidMode") in ("", "private", None), "pid namespace")
    _require(host.get("UTSMode") in ("", "private", None), "uts namespace")
    _require(host.get("IpcMode") == "none", "ipc namespace")
    _require(host.get("CgroupnsMode") == "private", "cgroup namespace")
    _require(host.get("UsernsMode") in ("", None), "user namespace")
    for key, value in host.items():
        if key in EMPTY_HOST:
            _require(_empty(value), f"{key} must be empty")
        elif key not in CHECKED_HOST and key not in INFORMATIONAL_HOST and key != "Mounts":
            _require(_empty(value), f"unknown setting {key}")
    _require(bool(host.get("MaskedPaths")) or "MaskedPaths" not in host, "masked /proc paths")
    _require(_empty(config.get("Volumes")), "image volumes")
    _verify_mounts(doc, spec)
    tmpfs = host.get("Tmpfs") or {}
    _require(set(tmpfs) == {"/tmp"}, "tmpfs mounts")
    _require({_size(o) for o in str(tmpfs["/tmp"]).split(",")} == TMPFS, "tmpfs /tmp options")
    _require(host.get("Memory") == L06_MEMORY and host.get("MemorySwap") == L06_MEMORY, "memory limit")
    cpus = host.get("NanoCpus") or 0
    if not cpus and host.get("CpuPeriod"):
        cpus = int(1e9 * host.get("CpuQuota", 0) / host["CpuPeriod"])
    _require(cpus == L06_NANO_CPUS, "cpu limit")
    _require(host.get("PidsLimit") == L06_PIDS, "pids limit")
    ulimits = {(u.get("Name"), u.get("Soft"), u.get("Hard")) for u in host.get("Ulimits") or []}
    _require(ulimits == {("nofile", L06_NOFILE, L06_NOFILE), ("cpu", spec.limit, spec.limit)}, "ulimits")
    _require((host.get("LogConfig") or {}).get("Type") == "none", "log driver")
    _require((host.get("RestartPolicy") or {}).get("Name") in ("no", "", None), "restart policy")
    _require(host.get("AutoRemove") is False, "auto remove")
    _require(config.get("User") == USER, "user")
    _require(sorted(config.get("Env") or []) == spec.env, "environment")
    image = str(doc.get("Image") or "")
    _require(image == spec.image or f"sha256:{image}" == spec.image, "image")
    _require(config.get("Entrypoint") == [spec.interpreter], "entrypoint")
    _require(config.get("Cmd") == spec.cmd, "command")
    _require(config.get("WorkingDir") == "/tmp", "working directory")
    health = config.get("Healthcheck")
    _require(health in (None, {}) or (health or {}).get("Test") == ["NONE"], "healthcheck")
    found = config.get("Labels") or {}
    _require(all(found.get(k) == v for k, v in spec.labels.items()), "labels")
    if rendered is not None:
        _require(rendering(doc) == rendered, "runtime rendering differs from the conformance record")
    return normalized(doc)


def _verify_mounts(doc: dict[str, Any], spec: Spec) -> None:
    host = doc.get("HostConfig") or {}
    declared = host.get("Mounts") or []
    effective = doc.get("Mounts") or []
    _require(len(declared) == len(spec.mounts) and len(effective) == len(spec.mounts), "mounts")
    sources = {"/input": spec.stage_input, "/helper": spec.stage_helper}
    for m in effective:
        target = m.get("Destination")
        _require(target in spec.mounts, f"mount {target}")
        rw = spec.mounts[target] == "rw"
        _require(m.get("RW") is rw, f"mount {target} read-only")
        if target == "/results":
            _require(m.get("Type") == "volume" and m.get("Name") == spec.volume, "results volume mount")
        else:
            _require(m.get("Type") == "bind", f"mount {target} type")
            _require(
                os.path.realpath(str(m.get("Source"))) == os.path.realpath(str(sources[target])),
                f"mount {target} source",
            )
    for m in declared:
        target = m.get("Target")
        _require(target in spec.mounts, f"mount {target}")
        _require(bool(m.get("ReadOnly")) is (spec.mounts[target] == "ro"), f"mount {target} read-only")
