"""`secure-code tools helper-conformance` (FEATURE-002-F AC-002F-11b/11c/11f; design §12.2, DEC-7).

Maintainer-only offline probe suite on the real runtime CLI with the registered local image. Every probe
container first passes the semantic verifier (P-00; no conformance record is needed or trusted for it);
the rendering of those containers then becomes the record's `rendered` snapshot. The record lists every
probe's pass/fail bound to the runtime identity, image and toolkit version, and is written (with its MAC)
even when probes fail — a failed record never allows execution. An in-process runtime seam is refused.
"""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import time
from pathlib import Path
from typing import Any

from ... import __version__
from ...auth.service import require_maintainer
from ...projects import knowledge_root
from ...results import Result
from ..mask import mask_text
from ..model import utc_now
from . import execute_io, registry, results
from .canonical import ConfigMismatch
from .execute_io import RunSpec
from .model import HELPERS_REL, MAINTAINER_STEP
from .runtime import CliRuntime, RuntimeGap
from .snapshot import seal, unseal_remove

# Probe source: Python run only inside the probe container; kept as a non-`.py` data file so no host-side
# module of the toolkit imports a network client (002-C AC-002C-05f scan).
SUITE = Path(__file__).resolve().parent / "probes" / "suite.probe"
IFF_UP = 0x1
FLAGS = re.compile(r"0x[0-9a-fA-F]{1,8}")
ZERO_CAPS = "0000000000000000"
DECLARED = {"/", "/input", "/helper", "/results", "/tmp"}
STANDARD = {
    "/proc",
    "/dev",
    "/dev/pts",
    "/dev/mqueue",
    "/dev/shm",
    "/sys",
    "/sys/fs/cgroup",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/run/.containerenv",
}
DEVICES = {
    "null",
    "zero",
    "full",
    "random",
    "urandom",
    "tty",
    "console",
    "pts",
    "shm",
    "mqueue",
    "fd",
    "stdin",
    "stdout",
    "stderr",
    "ptmx",
    "core",
}
DENIALS = ("add_key", "request_key", "keyctl", "unshare")
P13B = (
    "link-input",
    "link-helper",
    "link-passwd",
    "link-parent",
    "hardlink",
    "extra-file",
    "extra-dir",
    "fifo",
    "many",
)
P17 = ("cpu", "churn", "sleeper", "early-exit", "attack-pid1")
NAMES = {
    "P-00": "configuration",
    "P-01": "network",
    "P-02": "read-only",
    "P-03": "mounts",
    "P-04": "namespaces",
    "P-05": "devices",
    "P-06": "user",
    "P-07": "capabilities",
    "P-08": "no-new-privileges and seccomp",
    "P-09": "pids",
    "P-10": "memory",
    "P-11": "open files",
    "P-12": "/tmp",
    "P-13": "results",
    "P-13b": "malicious results",
    "P-14": "time",
    "P-15": "output",
    "P-16": "attach",
    "P-17": "fail-safe time",
    "P-18": "cleanup",
}


class Suite:
    def __init__(self, rt: CliRuntime, root: Path, image: dict[str, Any], identity: dict[str, Any]) -> None:
        self.rt, self.root, self.image, self.identity = rt, root, image, identity
        self.stage = root / HELPERS_REL / f"conformance-stage-{secrets.token_hex(6)}"
        self.k = 0
        self.renderings: list[dict[str, Any]] = []
        self.mismatches: list[str] = []
        self.probes: list[dict[str, Any]] = []

    def container(
        self,
        probe: str,
        *,
        limit: int = 30,
        kill_client_after: float | None = None,
        self_stop_wait: float | None = None,
        should_stop=None,
    ) -> execute_io.Outcome:
        self.k += 1
        folder = self.stage / f"c{self.k}"
        (folder / "input").mkdir(parents=True)
        (folder / "input" / "probe.txt").write_text("conformance fixture\n")
        seal(folder / "input")
        script = f"PROBE = {probe!r}\n".encode() + SUITE.read_bytes()
        name = f"xsc-cf-{secrets.token_hex(3)}-{probe.lower().replace(':', '-')}-{self.k}"
        run = RunSpec(
            "target",
            name,
            "conformance",
            self.image["image"],
            self.image["interpreter"],
            self.image["env"],
            limit,
            execute_io.stage_helper(folder / "helper", script),
            str(folder / "input"),
            kill_client_after=kill_client_after,
            self_stop_wait=self_stop_wait,
        )
        out = execute_io.run_container(
            self.rt, run, should_stop or (lambda: False), lambda names, volume: None
        )
        if out.mismatch:
            self.mismatches.append(f"{probe}: {out.mismatch}")
        if out.rendering is not None:
            self.renderings.append(out.rendering)
        return out

    def notes(self, out: execute_io.Outcome) -> dict[str, Any]:
        if out.result is None:
            return {}
        try:
            doc = results.parse(out.result, "probe", "", {"probe.txt"})
            return json.loads(doc["notes"]) if doc["notes"] else {}
        except (results.ResultInvalid, ValueError):
            return {}

    def record(self, pid: str, ok: bool, detail: Any) -> None:
        text = detail if isinstance(detail, str) else json.dumps(detail, sort_keys=True)
        self.probes.append(
            {"id": pid, "name": NAMES[pid], "pass": bool(ok), "detail": mask_text(text)[0][:1000]}
        )

    # ----------------------------------------------------------------- probes
    def run_all(self) -> None:
        simple = {}
        for pid in (
            "P-01",
            "P-02",
            "P-03",
            "P-04",
            "P-05",
            "P-06",
            "P-07",
            "P-08",
            "P-09",
            "P-11",
            "P-12",
            "P-13",
        ):
            out = self.container(pid)
            simple[pid] = (out, self.notes(out))
        n = {pid: notes for pid, (_out, notes) in simple.items()}
        self.record("P-01", network_ok(n["P-01"], simple["P-01"][0].config), n["P-01"])
        self.record("P-02", readonly_ok(n["P-02"]), n["P-02"])
        mounts = set(n["P-03"].get("mounts", ["?"]))
        extra = sorted(
            m for m in mounts - DECLARED - STANDARD if not m.startswith(("/proc/", "/sys/", "/dev/"))
        )
        self.record(
            "P-03",
            bool(n["P-03"]) and not extra and not n["P-03"].get("socks"),
            {"extra_mounts": extra, "socks": n["P-03"].get("socks")},
        )
        p04 = n["P-04"]
        host_ns = _host_ns()
        private = all(p04.get("ns", {}).get(k) != v for k, v in host_ns.items()) if host_ns else True
        self.record(
            "P-04",
            "launcher.py" in p04.get("pid1", "")
            and p04.get("ppid") == 1
            and p04.get("hostname") != platform.node()
            and p04.get("cgroup", "").startswith("0::/")
            and private,
            {**p04, "host_compared": bool(host_ns)},
        )
        dev = n["P-05"].get("dev", {"?": "?"})
        self.record("P-05", all(k in DEVICES and v in ("char", "dir", "link") for k, v in dev.items()), dev)
        p06 = n["P-06"]
        self.record(
            "P-06",
            p06.get("uid") == 65534 and p06.get("gid") == 65534 and set(p06.get("groups", [0])) <= {65534},
            p06,
        )
        caps = n["P-07"]
        self.record(
            "P-07",
            bool(caps)
            and all(caps.get(k) == "0000000000000000" for k in ("CapEff", "CapPrm", "CapBnd", "CapAmb")),
            caps,
        )
        profile = [o for o in self.identity.get("security_options", []) if "seccomp" in o]
        self.record("P-08", seccomp_ok(n["P-08"], self.identity), {**n["P-08"], "profile": profile})
        self.record(
            "P-09", n["P-09"].get("error") == "EAGAIN" and 0 < n["P-09"].get("forked", 999) < 64, n["P-09"]
        )
        mem = self.container("P-10")
        self.record(
            "P-10",
            mem.oom or mem.exit == 137 or self.notes(mem).get("memory_error") is True,
            {"oom": mem.oom, "exit": mem.exit, "notes": self.notes(mem)},
        )
        self.record(
            "P-11", n["P-11"].get("error") == "EMFILE" and n["P-11"].get("opened", 999) <= 256, n["P-11"]
        )
        p12 = n["P-12"]
        self.record(
            "P-12",
            p12.get("error") == "ENOSPC"
            and p12.get("written", 1 << 30) <= 16 * 1024 * 1024
            and p12.get("exec") in ("EACCES", "EPERM"),
            p12,
        )
        p13 = n["P-13"]
        self.record(
            "P-13",
            simple["P-13"][0].result is not None
            and p13.get("error") == "ENOSPC"
            and p13.get("big", 1 << 30) <= 2 * 1024 * 1024
            and p13.get("files_error") == "ENOSPC",
            p13,
        )
        rejected = {}
        for variant in P13B:
            out = self.container(f"P-13b:{variant}")
            rejected[variant] = out.collect_error or ("accepted" if out.result is not None else out.reason)
        self.record("P-13b", all(r and r != "accepted" for r in rejected.values()), rejected)
        slow = self.container("P-14", limit=5)
        self.record(
            "P-14", slow.limit == "time" and slow.stopped, {"limit": slow.limit, "stopped": slow.stopped}
        )
        flood = self.container("P-15")
        self.record(
            "P-15",
            flood.limit == "output" and flood.stopped and len(flood.raw_stdout) <= 65536,
            {"limit": flood.limit, "kept": len(flood.raw_stdout)},
        )
        attach = self.container("P-16")
        self.record("P-16", attach.raw_stdout.startswith(b"0123456789"), {"stdout": attach.stdout[:20]})
        variants = {}
        for variant in P17:
            started = time.monotonic()
            out = self.container(f"P-17:{variant}", limit=5, kill_client_after=0.5, self_stop_wait=15)
            took = round(time.monotonic() - started, 1)
            ok = out.extra.get("self_stopped") is True
            if variant == "early-exit":
                ok = ok and out.extra.get("stopped_after", 99) < 4
            if variant == "attack-pid1":
                notes = self.notes(out)
                ok = (
                    ok
                    and notes.get("ptrace") not in (None, "ok")
                    and notes.get("process_vm_writev") not in (None, "ok")
                )
            variants[variant] = {"pass": ok, "seconds": took, "stopped_after": out.extra.get("stopped_after")}
        self.record("P-17", all(v["pass"] for v in variants.values()), variants)
        normal = self.container("P-18")
        started = time.monotonic()
        cancel = self.container("P-14", limit=20, should_stop=lambda: time.monotonic() - started > 1.0)
        self.record(
            "P-18",
            normal.cleanup and cancel.cleanup and cancel.cancelled,
            {"normal": normal.cleanup, "cancel": cancel.cleanup, "cancelled": cancel.cancelled},
        )
        same = all(r == self.renderings[0] for r in self.renderings) if self.renderings else False
        self.probes.insert(
            0,
            {
                "id": "P-00",
                "name": NAMES["P-00"],
                "pass": not self.mismatches and same,
                "detail": "; ".join(self.mismatches)
                or ("rendering identical across probe containers" if same else "rendering differs"),
            },
        )


def seccomp_ok(notes: dict[str, Any], identity: dict[str, Any]) -> bool:
    """P-08 (review M7): no-new-privileges, filter mode, the runtime's default/builtin profile and the
    behavioural denials (no capability needed, allowed without seccomp) must all hold."""
    profile = [o for o in identity.get("security_options", []) if "seccomp" in o]
    default = any("profile=builtin" in o or "profile=default" in o for o in profile)
    try:
        filters = int(notes.get("Seccomp_filters") or 0)
    except (TypeError, ValueError):
        filters = 0
    return (
        notes.get("NoNewPrivs") == "1"
        and notes.get("Seccomp") == "2"
        and filters >= 1
        and default
        and all((notes.get("denied") or {}).get(s) == "EPERM" for s in DENIALS)
    )


def readonly_ok(notes: dict[str, Any]) -> bool:
    """P-02: root, `/input`, `/helper` not writable; with `--ipc none` (DAO-005, DEC-I6) there is no
    writable `/dev/shm` either (absent → ENOENT)."""
    denied = ("EROFS", "EACCES", "EPERM")
    paths = ("/usr/x", "/input/x", "/helper/x", "/x")
    return (
        all(notes.get(p) in denied for p in paths)
        and notes.get("/dev/shm/x") in (*denied, "ENOENT")
    )


def network_ok(notes: dict[str, Any], config: dict[str, Any] | None) -> bool:
    """P-01 "network disabled" (spec v1.3.3 AC-002F-11b, DAO-005): every non-loopback interface is down
    (IFF_UP clear) and no device but lo holds an IPv4/IPv6 address or route; CapEff = CapBnd = 0 so no
    interface can be brought up; outbound connect and DNS fail; the runtime's inspect shows network
    mode `none` with all capabilities dropped. Missing or unreadable evidence fails."""
    ifaces = notes.get("ifaces")
    if not isinstance(ifaces, dict) or not ifaces:
        return False
    for name, flags in ifaces.items():
        if name == "lo":
            continue
        if not isinstance(flags, str) or not FLAGS.fullmatch(flags) or int(flags, 16) & IFF_UP:
            return False
    host = (config or {}).get("host") or {}
    return (
        all(notes.get(k) == [] for k in ("v4", "v6", "route4", "route6"))
        and notes.get("CapEff") == ZERO_CAPS
        and notes.get("CapBnd") == ZERO_CAPS
        and notes.get("connect") not in (None, "connected")
        and notes.get("dns") not in (None, "resolved")
        and host.get("NetworkMode") == "none"
        and bool((config or {}).get("networks"))
        and set((config or {}).get("networks") or []) <= {"none"}
        and "ALL" in [str(c).upper() for c in host.get("CapDrop") or []]
    )


def _host_ns() -> dict[str, str]:
    """The toolkit process's own namespace ids (Linux hosts only; VM-backed runtimes record the boundary)."""
    out = {}
    for name in ("pid", "ipc", "uts", "net", "cgroup"):
        try:
            out[name] = os.readlink(f"/proc/self/ns/{name}")
        except OSError:
            return {}
    return out


def run(project: str | None, trust_paths: Any = None, runtime: Any = None) -> Result:
    """Run the offline conformance suite and write the record (Maintainer)."""
    command = "tools helper-conformance"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    decision = require_maintainer("tools.helper_conformance", paths=trust_paths)
    if not decision.allowed:
        refused = decision.to_result()
        refused.command = command
        return refused
    image = registry.image(root)
    if image is None:
        return Result.refused(
            command,
            "HELPER_IMAGE_UNAVAILABLE",
            "no valid helper image registration",
            "Register the image first: secure-code tools register-helper-image",
        )
    try:
        rt = runtime if runtime is not None else CliRuntime.discover()
        if type(rt) is not CliRuntime:
            return Result.refused(
                command,
                "HELPER_CONFORMANCE_REFUSED",
                "conformance needs the real runtime CLI",
                MAINTAINER_STEP,
            )
        execute_io.sweep(rt)
        identity = rt.identity()
        if rt.image(image["image"]) is None:
            return Result.refused(
                command,
                "HELPER_IMAGE_UNAVAILABLE",
                "the registered image is not present locally",
                MAINTAINER_STEP,
            )
        suite = Suite(rt, root, image, identity)
        try:
            suite.run_all()
        finally:
            unseal_remove(suite.stage)
    except (RuntimeGap, ConfigMismatch) as exc:
        reason = exc.reason if isinstance(exc, RuntimeGap) else exc.invariant
        return Result.refused(
            command, getattr(exc, "code", "HELPER_CONFIG_MISMATCH"), reason, MAINTAINER_STEP
        )
    passed = all(p["pass"] for p in suite.probes)
    p08 = next(p for p in suite.probes if p["id"] == "P-08")
    record = registry.write_conformance(
        root,
        {
            "id": registry.conformance_id(identity, image["image"]),
            "identity": identity,
            "image": image["image"],
            "toolkit_version": __version__,
            "ran_at": utc_now(),
            "seccomp": {
                "runtime_profile": [o for o in identity["security_options"] if "seccomp" in o],
                "denied_syscalls_proven": list(DENIALS) if p08["pass"] else [],
                "filters": None,
            },
            "rendered": suite.renderings[0] if suite.renderings and suite.probes[0]["pass"] else None,
            "probes": suite.probes,
            "passed": passed,
        },
    )
    data = {
        "record": record["id"],
        "passed": passed,
        "identity": identity,
        "probes": [{k: p[k] for k in ("id", "name", "pass", "detail")} for p in suite.probes],
    }
    step = (
        "Helpers can run on this runtime"
        if passed
        else "Helpers will not run on this runtime (non-execution path); fix the runtime outside the toolkit "
        "and re-run"
    )
    return Result(command, True, data, [], [step])
