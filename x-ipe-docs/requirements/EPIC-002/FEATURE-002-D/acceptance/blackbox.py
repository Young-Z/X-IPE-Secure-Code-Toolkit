"""Black-box acceptance scenarios for FEATURE-002-D Trivy Adapter (TASK-058).

Calls the real CLI (`uvx --from <framework>/scripts secure-code ...`) and the real Trivy v0.76.1 binary.
Never imports toolkit code. Prints one JSON line per case; never prints secret values.

  python3 blackbox.py host        # macOS: never-authorized User path; Linux-only refusal (AC-002D-01c)
  FAT_ISOLATED=1 TRIVY=/tv/ARM64/trivy python3 blackbox.py container
      # disposable Linux container: Maintainer path; attached only to a Docker --internal network whose only
      # peer is the loopback OCI registry (registry.py) impersonating mirror.gcr.io / ghcr.io /
      # pkg-containers.githubusercontent.com via --add-host; the disposable test CA is trusted only inside
      # this container. Components reach each project only through `secure-code tools provision`.

Observation inside the container (harness, not toolkit):
  * Sniffer: AF_PACKET capture of every frame this container sends on any interface (incl. loopback and
    DNS to Docker's resolver) per window -> "zero outbound attempts" for scans;
  * ProcWatch: /proc scan (1 ms) of every process whose executable is named `trivy` (argv, environment,
    working folder, --cache-dir entries) -> exact argv/environment evidence and "never executed" checks;
  * Registry log (/reglog/requests.jsonl): TLS SNI and every HTTP request the loopback registry received.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

TOOLKIT = (Path(os.environ["TOOLKIT_ROOT"]) if "TOOLKIT_ROOT" in os.environ
           else Path(__file__).resolve().parents[5] / "ai-secure-code-toolkit")
SCRIPTS = TOOLKIT / "x-ipe-secure-code-toolkit-framework" / "scripts"
FRAMEWORK = TOOLKIT / "x-ipe-secure-code-toolkit-framework"
GUARD_SKILL = TOOLKIT / "x-ipe-secure-code-toolkit-guard"
DOCS = Path(os.environ.get("FAT_DOCS", Path(__file__).resolve().parents[1]))  # FEATURE-002-D folder
SAMPLES = Path(os.environ.get("SAMPLES", "/samples"))
IMAGES = Path(os.environ.get("IMAGES", "/img"))
FIXTURES = Path(os.environ.get("FIXTURES", "/fixtures"))
REGLOG = Path(os.environ.get("REGLOG", "/reglog"))
HANDOFF = Path(os.environ.get("HANDOFF", "/handoff"))
TRIVY = os.environ.get("TRIVY", "/tv/ARM64/trivy")
TRIVY_X86 = "/tv/64bit/trivy"
ARCHIVE_ARM = "/tv/trivy_0.76.1_Linux-ARM64.tar.gz"
REGIP = os.environ.get("REGIP", "")
WORK = Path(os.environ.get("FAT_WORK", tempfile.gettempdir()))
PRIVATE = ".x-ipe/private/secure-code"
GUARD = f"{PRIVATE}/guard"
CACHE = f"{PRIVATE}/tools/trivy-cache"
STAGE_ROOT = f"{PRIVATE}/adapter-stage/trivy"
RECORD = f"{PRIVATE}/tools/trivy.json"
REPORTS = "x-ipe-docs/secure-code/reports/guard"
PASS = "acceptance passphrase 42"
R1, R2 = "CWE/4.14/CWE-89", "CWE/4.14/CWE-79"
OFFICIAL_ARM = "sha256:b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85"
OFFICIAL_X86 = "sha256:d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83"
ARCHIVES = {"trivy_0.76.1_Linux-ARM64.tar.gz": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
            "trivy_0.76.1_Linux-64bit.tar.gz": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"}
PLATFORM_GAP = "Trivy execution is supported only on Linux x86-64 and Linux arm64 in this version"
OFFLINE = ["--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan",
           "--skip-version-check", "--disable-telemetry"]
FORBIDDEN = ["--exit-code", "--severity", "--ignore-unfixed", "--skip-files", "--skip-dirs", "--vex", "--compliance",
             "--server", "--db-repository", "--java-db-repository", "--checks-bundle-repository",
             "--include-non-failures"]
MINIMAL_ENV = {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "PATH", "LANG", "TZ"}
COMPONENTS = ("vulnerability_db", "java_db", "checks_bundle")
REPOS = {
    "mirror.gcr.io": {"vulnerability_db": "mirror.gcr.io/aquasec/trivy-db:2",
                      "java_db": "mirror.gcr.io/aquasec/trivy-java-db:1",
                      "checks_bundle": "mirror.gcr.io/aquasec/trivy-checks:2"},
    "ghcr.io": {"vulnerability_db": "ghcr.io/aquasecurity/trivy-db:2",
                "java_db": "ghcr.io/aquasecurity/trivy-java-db:1",
                "checks_bundle": "ghcr.io/aquasecurity/trivy-checks:2"},
}
BLOB = "pkg-containers.githubusercontent.com"
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "unknown"}
V0761_TYPES = {"azure-arm", "cloudformation", "dockerfile", "helm", "kubernetes", "terraform", "terraformplan-json",
               "terraformplan-snapshot", "ansible"}  # `trivy fs --help` of the real v0.76.1 binary (FF-01)
RESULTS: list[dict] = []
SECRET_VALUES: list[str] = []  # generated at run time, never printed, never written outside the disposable container


# ---------------------------------------------------------------- CLI helpers
def sc(*args: str, timeout: int = 1800):
    proc = subprocess.run(["uvx", "--from", str(SCRIPTS), "secure-code", *args], capture_output=True, text=True,
                          env=dict(os.environ), stdin=subprocess.DEVNULL, timeout=timeout)
    try:
        data = json.loads(proc.stdout) if "--json" in args else None
    except json.JSONDecodeError:
        data = None
    return proc.returncode, data, proc.stdout, proc.stderr


def sc_bg(*args: str) -> subprocess.Popen:
    return subprocess.Popen(["uvx", "--from", str(SCRIPTS), "secure-code", *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL, start_new_session=True)


def finish(proc: subprocess.Popen, timeout: int = 900):
    out, err = proc.communicate(timeout=timeout)
    try:
        return proc.returncode, json.loads(out), out, err
    except json.JSONDecodeError:
        return proc.returncode, None, out, err


def sc_pty(answers: list[str], *args: str, marker: bytes = b"passphrase") -> int:
    import pty

    cmd = ["uvx", "--from", str(SCRIPTS), "secure-code", *args]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, dict(os.environ))
    out, sent, end = b"", 0, time.time() + 120
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if sent < len(answers) and out.lower().count(marker) > sent:
            os.write(fd, answers[sent].encode() + b"\n")
            sent += 1
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status)


def code_of(out):
    return out["problems"][0]["code"] if out and out.get("problems") else None


def msg_of(out) -> str:
    return " ".join(p.get("message", "") for p in (out or {}).get("problems") or []) + " " + \
        " ".join((out or {}).get("next_steps") or [])


def case(tc: str, acs: list[str], fn) -> None:
    t0 = time.time()
    try:
        checks = fn()
        failed = [n for n, ok in checks if not ok]
        detail = {"status": "Pass" if not failed else "Fail", "checks": [n for n, _ in checks], "failed": failed}
    except Exception as exc:  # noqa: BLE001 - every unexpected error is a failed case
        import traceback

        detail = {"status": "Fail", "error": f"{type(exc).__name__}: {exc}"[:3000],
                  "where": traceback.format_exc()[-2000:]}
    detail["seconds"] = round(time.time() - t0, 1)
    RESULTS.append({"tc": tc, "acs": acs, **detail})
    line = json.dumps(RESULTS[-1])
    for value in SECRET_VALUES:  # defence in depth: the evidence never carries a fake credential
        line = line.replace(value, "<redacted-fake-secret>")
    print(line, flush=True)


def note(tc: str, data: dict) -> None:
    """Observed facts attached to the evidence (diagnostic, not assertions)."""
    line = json.dumps({"note": tc, **data})
    for value in SECRET_VALUES:
        line = line.replace(value, "<redacted-fake-secret>")
    print(line, flush=True)


def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def tree(root: Path, skip: tuple[str, ...] = ()) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if any(rel == s or rel.startswith(s + "/") for s in skip):
            continue
        out[rel] = "link" if p.is_symlink() else ("dir" if p.is_dir() else sha_file(p))
    return out


def jfile(project: Path, doc: dict) -> str:
    path = Path(tempfile.mkstemp(suffix=".json", dir=project.parent)[1])
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def item(rule: str) -> dict:
    ns, ver, rid = rule.split("/")
    return {"namespace": ns, "version": ver, "rule_id": rid, "content": "Rule body.\n",
            "source_location": f"https://example.org/{rid}"}


def parse_time(text: str) -> datetime:
    text = re.sub(r"\.(\d{6})\d*", r".\1", text.replace("Z", "+00:00"))
    return datetime.fromisoformat(text)


# ---------------------------------------------------------------- observation (harness)
class Sniffer(threading.Thread):
    """Every frame this container sends (PACKET_OUTGOING) on any interface, with IP/port/DNS details."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.frames: list[dict] = []
        self.ok = False
        self.error = None

    def run(self) -> None:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.ok = True
        except OSError as exc:
            self.error = repr(exc)
            return
        while True:
            data, addr = s.recvfrom(65535)
            if addr[2] != 4:  # PACKET_OUTGOING only
                continue
            self.frames.append(self._parse(addr[0], data))

    @staticmethod
    def _parse(ifname: str, data: bytes) -> dict:
        rec = {"t": round(time.time(), 3), "if": ifname}
        etype = struct.unpack("!H", data[12:14])[0] if len(data) >= 14 else 0
        rec["etype"] = hex(etype)
        payload = data[14:]
        proto, l4 = None, b""
        if etype == 0x0800 and len(payload) >= 20:
            ihl = (payload[0] & 0x0F) * 4
            proto = payload[9]
            rec.update(src=socket.inet_ntoa(payload[12:16]), dst=socket.inet_ntoa(payload[16:20]), proto=proto)
            l4 = payload[ihl:]
        elif etype == 0x86DD and len(payload) >= 40:
            proto = payload[6]
            rec.update(src=socket.inet_ntop(socket.AF_INET6, payload[8:24]),
                       dst=socket.inet_ntop(socket.AF_INET6, payload[24:40]), proto=proto)
            l4 = payload[40:]
        if proto in (6, 17) and len(l4) >= 4:
            rec["sport"], rec["dport"] = struct.unpack("!HH", l4[:4])
            if proto == 6 and len(l4) >= 14:
                rec["flags"] = l4[13]
            if proto == 17 and (53 in (rec["sport"], rec["dport"]) or rec.get("dst") == "127.0.0.11") \
                    and len(l4) > 20:
                try:
                    pos, labels = 20, []
                    while l4[pos]:
                        labels.append(l4[pos + 1: pos + 1 + l4[pos]].decode("ascii", "replace"))
                        pos += 1 + l4[pos]
                    rec["dns"] = ".".join(labels)
                except IndexError:
                    rec["dns"] = "<malformed>"
        return rec


class ProcWatch(threading.Thread):
    """Processes whose executable is named `trivy`: argv, environment, cwd and --cache-dir entries."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.seen: dict[int, dict] = {}
        self.order: list[int] = []

    def run(self) -> None:
        while True:
            live = set()
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                pid = int(name)
                live.add(pid)
                if pid in self.seen and self.seen[pid]["alive"]:
                    continue
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                except OSError:
                    continue
                if os.path.basename(exe.replace(" (deleted)", "")) != "trivy":
                    continue
                rec = {"pid": pid, "exe": exe, "t0": time.time(), "alive": True}
                try:
                    raw = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")[:-1]
                    rec["argv"] = [a.decode("utf-8", "replace") for a in raw]
                    env = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
                    rec["env"] = dict(e.decode("utf-8", "replace").split("=", 1) for e in env if b"=" in e)
                    rec["cwd"] = os.readlink(f"/proc/{pid}/cwd")
                    stat = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
                    rec["ppid"], rec["pgid"] = int(stat[1]), int(stat[2])
                    try:
                        rec["cwd_entries"] = sorted(os.listdir(rec["cwd"]))
                    except OSError:
                        rec["cwd_entries"] = None
                    if "--cache-dir" in rec["argv"]:
                        cdir = rec["argv"][rec["argv"].index("--cache-dir") + 1]
                        rec["cache_dir"] = cdir
                        rec["cache_entries"] = {e: (os.readlink(os.path.join(cdir, e))
                                                    if os.path.islink(os.path.join(cdir, e)) else "real")
                                                for e in sorted(os.listdir(cdir))}
                except (OSError, ValueError, IndexError):
                    pass
                if pid in self.seen:  # pid reused
                    self.order.append(pid)
                else:
                    self.order.append(pid)
                self.seen[pid] = rec
            for pid in list(self.seen)[-128:]:
                if self.seen[pid]["alive"] and pid not in live:
                    self.seen[pid]["alive"] = False
                    self.seen[pid]["t1"] = time.time()
            time.sleep(0.001)

    def since(self, n: int) -> list[dict]:
        return [self.seen[p] for p in self.order[n:]]

    @staticmethod
    def alive() -> list[int]:
        out = []
        for name in os.listdir("/proc"):
            if name.isdigit():
                try:
                    if os.path.basename(os.readlink(f"/proc/{name}/exe")) == "trivy":
                        out.append(int(name))
                except OSError:
                    pass
        return out


SNIFF: Sniffer | None = None
PROCS: ProcWatch | None = None


class Window:
    """One observation window: frames sent, trivy processes started, loopback registry requests."""

    def __enter__(self) -> "Window":
        time.sleep(0.2)
        self.f0 = len(SNIFF.frames)
        self.p0 = len(PROCS.order)
        log = REGLOG / "requests.jsonl"
        self.r0 = log.stat().st_size if log.exists() else 0
        return self

    def __exit__(self, *exc) -> None:
        time.sleep(0.5)
        self.frames = SNIFF.frames[self.f0:]
        self.procs = PROCS.since(self.p0)
        log = REGLOG / "requests.jsonl"
        self.reg = []
        if log.exists():
            with open(log, "rb") as f:
                f.seek(self.r0)
                self.reg = [json.loads(x) for x in f.read().decode().splitlines() if x.strip()]

    def ip_frames(self) -> list[dict]:
        return [f for f in self.frames if f["etype"] in ("0x800", "0x86dd")]

    def silent(self) -> bool:
        """No IP frame (IPv4/IPv6, any protocol/port, incl. DNS on loopback) and no registry request.
        Link-layer ARP housekeeping (neighbour probes/replies) is reported in the summary, not an attempt."""
        return self.ip_frames() == [] and [f for f in self.frames if f["etype"] != "0x806"] == [] and self.reg == []

    def snis(self) -> set[str]:
        return {r["sni"] for r in self.reg if r.get("event") == "tls_hello"}

    def hosts(self) -> set[str]:
        return {r["host"] for r in self.reg if r.get("host")}

    def dsts(self) -> set[tuple]:
        return {(f.get("dst"), f.get("dport")) for f in self.ip_frames()}

    def dns(self) -> list[str]:
        return [f["dns"] for f in self.frames if "dns" in f]

    def summary(self) -> dict:
        return {"frames": len(self.frames), "arp": sum(f["etype"] == "0x806" for f in self.frames), "ip_dsts": sorted(map(str, self.dsts())), "dns": self.dns(),
                "registry_requests": len(self.reg), "sni": sorted(self.snis()), "trivy_processes": len(self.procs)}


def registry_mode(**mode) -> None:
    (REGLOG / "mode.json").write_text(json.dumps(mode))


def only_registry(w: Window) -> bool:
    """Every IP frame went to the loopback registry on 443 (no DNS, no other host or port)."""
    return all(d == (REGIP, 443) for d in w.dsts()) and w.dns() == []


# ---------------------------------------------------------------- project and Guard helpers
def new_project(name: str = "proj ü", knowledge: bool = True, where: Path | None = None) -> Path:
    base = where if where is not None else Path(tempfile.mkdtemp(prefix="fat-2d-", dir=WORK))
    root = base / name
    root.mkdir(parents=True)
    assert sc("init", "--project", str(root), "--env", "github-copilot", "--json")[0] == 0
    if knowledge:
        batch = {"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": [item(R1), item(R2)]}
        code, out, _, _ = sc("knowledge", "import", "--project", str(root), "--batch", jfile(root, batch), "--json")
        assert code == 0, out
    return root


def save_scope(p: Path) -> str:
    code, prop, _, _ = sc("policy", "resolve", "--project", str(p), "--rule", R1, "--rule", R2, "--json")
    doc = {"schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": "clues", "considered": [R1, R2],
           "proposal_digest": prop["data"]["proposal_digest"], "clues": "dependencies, containers, secrets",
           "language_context": ["java", "python"], "confirmation_note": "user confirmed",
           "decisions": [{"ref": e["requested"], "decision": "adopted",
                          "state_digest": e["source_evidence"]["state_digest"]} for e in prop["data"]["entries"]]}
    code, out, _, _ = sc("scope", "save", "--project", str(p), "--decisions", jfile(p, doc), "--confirmed", "--json")
    assert code == 0, out
    return out["data"]["scope_id"]


def register(p: Path, path: str = TRIVY, tool: str = "trivy"):
    return sc("tools", "register", "--project", str(p), "--tool", tool, "--path", path, "--json")


def g(p: Path, cmd: str, vid: str | None = None, doc: dict | None = None, *extra: str):
    args = ["guard", cmd, "--project", str(p)]
    if vid:
        args += ["--run", vid]
    if doc is not None:
        args += ["--request", jfile(p, doc)]
    return sc(*args, *extra, "--json")


TRIVY_M = {"name": "trivy", "kind": "runtime", "required": True}
READ_M = {"name": "semantic-review", "kind": "reading", "required": True}


def chk(cid, obj, rule=R1, methods=(TRIVY_M,), selected=("trivy",), minimum=("runtime",)):
    c = {"id": cid, "rule": rule, "object": list(obj), "methods": [dict(m) for m in methods],
         "minimum_evidence": list(minimum)}
    if selected is not None:
        c["method_choice"] = {"considered": ["semantic-review", "trivy"],
                              "cost": "trivy offline scan about 1 s; semantic review minutes",
                              "selected": list(selected),
                              "reason": "Trivy covers declared dependencies, configuration files and secrets offline"}
    return c


def open_v(p: Path, scope: str, targets: list, context=(), budget=None) -> tuple[str, dict]:
    doc = {"schema": "ai-secure-code-toolkit/guard-open/v1", "scope_id": scope,
           "targets": [t if isinstance(t, dict) else {"path": t} for t in targets]}
    if context:
        doc["context"] = [{"path": c} for c in context]
    if budget:
        doc["budget"] = budget
    code, out, _, err = g(p, "open", doc=doc)
    assert code == 0, (out, err)
    return out["data"]["verification_id"], {t["path"]: t["digest"] for t in out["data"]["targets"]}


def plan(p: Path, vid: str, checks: list[dict], na=(R2,)):
    code, out, _, _ = g(p, "plan", vid, {"schema": "ai-secure-code-toolkit/guard-plan/v1", "checks": checks,
                                        "not_applicable": [{"rule": r, "reason": "not in this change"} for r in na]})
    assert code == 0, out
    return out


def setup(p: Path, scope: str, targets: list, checks: list[dict], **kw) -> tuple[str, dict]:
    vid, digests = open_v(p, scope, targets, **kw)
    covered = {c["rule"] for c in checks}
    plan(p, vid, checks, na=[r for r in (R1, R2) if r not in covered])
    return vid, digests


def tchk(cid, scanners, mode, targets, config_types=None) -> dict:
    c = {"check": cid, "scanners": list(scanners), "mode": mode, "targets": list(targets)}
    if config_types is not None:
        c["config_types"] = config_types
    return c


def tool(p: Path, vid: str, checks: list[dict], time_limit=600, raw: dict | None = None):
    doc = raw if raw is not None else {"schema": "ai-secure-code-toolkit/guard-tool/v1", "adapter": "trivy",
                                       "time_limit_seconds": time_limit, "checks": checks}
    return g(p, "tool", vid, doc)


def tool_bg(p: Path, vid: str, checks: list[dict], time_limit=600) -> subprocess.Popen:
    doc = {"schema": "ai-secure-code-toolkit/guard-tool/v1", "adapter": "trivy", "time_limit_seconds": time_limit,
           "checks": checks}
    return sc_bg("guard", "tool", "--project", str(p), "--run", vid, "--request", jfile(p, doc), "--json")


def grant(p: Path, vid: str, recipient: str, scopes: list[str], purpose="tool_update", data="metadata") -> int:
    args = ["guard", "allow-egress", "--project", str(p), "--run", vid, "--purpose", purpose, "--recipient",
            recipient, "--data", data]
    for s in scopes:
        args += ["--scope", s]
    return sc_pty([vid], *args, "--reason", "Trivy components for dependency and configuration checks", "--json",
                  marker=b"verification id")


def extend(p: Path, vid: str, attempts="17", minutes="120") -> int:  # default 3 + 17 = 20 (maximum)
    return sc_pty([vid], "guard", "extend", "--project", str(p), "--run", vid, "--attempts", attempts,
                  "--minutes", minutes, "--reason", "acceptance scenario", "--json", marker=b"verification id")


def provision(p: Path, vid: str, comps, registry=None, time_limit=None, extra=()):
    args = ["tools", "provision", "--project", str(p), "--tool", "trivy", "--run", vid]
    for c in comps:
        args += ["--component", c]
    if registry:
        args += ["--registry", registry]
    if time_limit is not None:
        args += ["--time-limit", str(time_limit)]
    return sc(*args, *extra, "--json")


def provision_bg(p: Path, vid: str, comps, time_limit=None) -> subprocess.Popen:
    args = ["tools", "provision", "--project", str(p), "--tool", "trivy", "--run", vid]
    for c in comps:
        args += ["--component", c]
    if time_limit is not None:
        args += ["--time-limit", str(time_limit)]
    return sc_bg(*args, "--json")


def mirror_grants(p: Path, vid: str, comps=COMPONENTS) -> bool:
    return grant(p, vid, "https://mirror.gcr.io", [f"https://{REPOS['mirror.gcr.io'][c]}" for c in comps]) == 0


def state(p: Path, vid: str) -> dict:
    return json.loads((p / GUARD / vid / "state.json").read_text())


def state_bytes(p: Path, vid: str) -> bytes:
    return (p / GUARD / vid / "state.json").read_bytes()


def run_of(p: Path, vid: str, n: int = -1) -> dict:
    return state(p, vid)["adapter_runs"][n]


def ev_of(p: Path, vid: str, cid: str) -> dict:
    return [e for e in state(p, vid)["evidence"] if cid in e["checks"] and e["method"] == "trivy"][-1]


def stored(p: Path, vid: str, run: dict) -> tuple[dict, dict]:
    base = p / GUARD / vid
    raw = (base / run["manifest"]["path"]).read_bytes()
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == run["manifest"]["digest"], "manifest digest"
    return json.loads(raw), json.loads((base / f"evidence/trivy-{run['n']}-output.json").read_text())


def status(p: Path) -> dict:
    return sc("status", "--project", str(p), "--json")[1]["data"]["tools"]


def staging_empty(p: Path) -> bool:
    roots = [p / STAGE_ROOT, p / CACHE / "staging"]
    return all(not r.exists() or not list(r.iterdir()) for r in roots)


def gaps(entry: dict, cid: str) -> str:
    return json.dumps(entry["checks"][cid].get("gaps", []))


def acc(entry: dict, cid: str, scanner: str) -> dict:
    return next(a for a in entry["checks"][cid]["accounting"] if a["scanner"] == scanner)


def by_scanner(procs: list[dict], scanner: str) -> list[dict]:
    return [x for x in procs if "--scanners" in (x.get("argv") or [])
            and x["argv"][x["argv"].index("--scanners") + 1] == scanner]


def scan_argv_checks(proc: dict, label: str) -> list[tuple[str, bool]]:
    argv = proc.get("argv") or []
    i = argv.index("--cache-dir") if "--cache-dir" in argv else -1
    return [
        (f"{label}: argv carries every validated offline flag", all(f in argv for f in OFFLINE)),
        (f"{label}: project configuration, ignore and secret configuration disabled (empty --config, "
         f"--ignorefile, --secret-config)", all(o in argv and argv[argv.index(o) + 1] == ""
                                                 for o in ("--config", "--ignorefile", "--secret-config"))),
        (f"{label}: no forbidden option (exit-code, severity, skip, vex, repositories, ...)",
         not any(f in argv for f in FORBIDDEN)),
        (f"{label}: disposable scan cache under the ephemeral staging (not the provisioned cache)",
         i > 0 and "/adapter-stage/trivy/stage-" in argv[i + 1]),
        (f"{label}: minimal environment (HOME/XDG/TMPDIR/PATH/LANG/TZ only, HOME disposable)",
         set(proc.get("env", {})) == MINIMAL_ENV and "/adapter-stage/trivy/stage-" in proc["env"].get("HOME", "")
         and proc["env"].get("TZ") == "UTC"),
        (f"{label}: working folder disposable and empty", "/adapter-stage/trivy/stage-" in proc.get("cwd", "")
         and proc.get("cwd_entries") == []),
        (f"{label}: executed binary is the private staged snapshot", proc["exe"] != TRIVY
         and "/adapter-stage/trivy/stage-" in proc["exe"]),
    ]


def links_ok(proc: dict, p: Path, expected: set[str]) -> bool:
    """The per-scan cache folder holds only symlinks to the current generations of the needed components."""
    entries = proc.get("cache_entries")
    if entries is None or set(entries) != expected:
        return False
    sub = {"db": "vulnerability_db", "java-db": "java_db", "policy": "checks_bundle"}
    for name, target in entries.items():
        if target == "real" or f"/{CACHE}/gen/{sub[name]}/" not in target:
            return False
    return True


def secret_free(paths: list[Path]) -> tuple[bool, list[str]]:
    hits = []
    for base in paths:
        if not base.exists():
            continue
        for f in base.rglob("*"):
            if f.is_file() and not f.is_symlink():
                data = f.read_bytes()
                if any(v.encode() in data for v in SECRET_VALUES):
                    hits.append(str(f))
    return not hits, hits


def fake_secrets() -> tuple[str, str]:
    aws = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    pat = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    SECRET_VALUES.extend([aws, pat])
    return aws, pat


# ---------------------------------------------------------------- image archive fixtures (runner-generated)
def _tar(entries: list[tuple], fmt=tarfile.USTAR_FORMAT) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        for e in entries:
            info = tarfile.TarInfo(e[0])
            kind = e[1]
            if kind == "file":
                info.size = len(e[2])
                t.addfile(info, io.BytesIO(e[2]))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            elif kind == "sym":
                info.type, info.linkname = tarfile.SYMTYPE, e[2]
                t.addfile(info)
            elif kind == "hard":
                info.type, info.linkname = tarfile.LNKTYPE, e[2]
                t.addfile(info)
            elif kind == "chr":
                info.type, info.devmajor, info.devminor = tarfile.CHRTYPE, 1, 3
                t.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                t.addfile(info)
    return buf.getvalue()


def make_archives(folder: Path) -> dict[str, str]:
    """Malformed and edge-case `docker save` archives built from the hello-world archive's own members."""
    src = tarfile.open(IMAGES / "hello-world.tar")
    members = {m.name: (m, src.extractfile(m).read() if m.isfile() else None) for m in src.getmembers()}
    manifest = json.loads(members["manifest.json"][1])
    cfg, layers = manifest[0]["Config"], manifest[0]["Layers"]
    base = [(n, "file", d) for n, (m, d) in members.items() if m.isfile() and n in [cfg, *layers]]
    good_manifest = ("manifest.json", "file", json.dumps(manifest).encode())
    cases = {
        "classic-docker-save.tar": (_tar([good_manifest, *base]), None),
        "pure-oci.tar": (_tar([(n, "file", d) for n, (m, d) in members.items() if m.isfile()
                               and n != "manifest.json"]), "pure OCI"),
        "symlink-member.tar": (_tar([good_manifest, *base, ("evil", "sym", "/etc/passwd")]), "link"),
        "hardlink-member.tar": (_tar([good_manifest, *base, ("evil", "hard", cfg)]), "link"),
        "device-member.tar": (_tar([good_manifest, *base, ("dev", "chr")]), "special"),
        "fifo-member.tar": (_tar([good_manifest, *base, ("fifo", "fifo")]), "special"),
        "dotdot-member.tar": (_tar([good_manifest, *base, ("../escape", "file", b"x")]), ".."),
        "absolute-member.tar": (_tar([good_manifest, *base, ("/abs", "file", b"x")]), "absolute"),
        "duplicate-member.tar": (_tar([good_manifest, *base, (cfg, "file", b"{}")]), "duplicate"),
        "dangling-config.tar": (_tar([("manifest.json", "file", json.dumps(
            [{"Config": "blobs/sha256/" + "0" * 64, "Layers": layers}]).encode()), *base]), "Config"),
        "dangling-layer.tar": (_tar([("manifest.json", "file", json.dumps(
            [{"Config": cfg, "Layers": ["blobs/sha256/" + "f" * 64]}]).encode()), *base]), "Layers"),
        "not-a-manifest.tar": (_tar([("manifest.json", "file", b'{"hello": 1}'), *base]), "manifest"),
        "not-a-tar.tar": (b"this is not a tar archive\n" * 40, "tar"),
    }
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as z:
        z.write(cases["classic-docker-save.tar"][0])
    cases["gzip-compressed.tar"] = (gz.getvalue(), "compress")
    whole = cases["classic-docker-save.tar"][0]
    cases["truncated.tar"] = (whole[: len(whole) // 2 + 100], "truncat")
    pax = io.BytesIO()
    with tarfile.open(fileobj=pax, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": "global"}) as t:
        for n, kind, d in [good_manifest, *base]:
            info = tarfile.TarInfo(n)
            info.size = len(d)
            t.addfile(info, io.BytesIO(d))
    cases["global-pax.tar"] = (pax.getvalue(), "global pax")
    folder.mkdir(parents=True, exist_ok=True)
    expected = {}
    for name, (data, violation) in cases.items():
        (folder / name).write_bytes(data)
        expected[name] = violation
    with open(folder / "huge.tar", "wb") as f:  # sparse: 8 GiB + 1 byte
        f.truncate(8 * 1024 ** 3 + 1)
    expected["huge.tar"] = "TOO_LARGE"
    return expected


# ================================================================ container cases
def tc_controls():
    with Window() as idle:
        time.sleep(10)
    with Window() as hosts:
        mapped = {h: subprocess.run(["getent", "ahostsv4", h], capture_output=True, text=True).stdout.split()[:1]
                  for h in ("mirror.gcr.io", "ghcr.io", BLOB)}
    with Window() as dns:
        unknown = subprocess.run(["getent", "hosts", "check.trivy.dev"], capture_output=True, text=True)
    with Window() as tcp:
        try:
            socket.create_connection((REGIP, 443), timeout=5).close()
        except OSError:
            pass
    note("TC-D-00", {"idle": idle.summary(), "dns_control": dns.summary(), "tcp_control": tcp.summary()})
    return [
        ("packet sniffer (AF_PACKET, all interfaces) and /proc watcher running", SNIFF.ok and PROCS.is_alive()),
        ("idle 10 s window: zero IP frames sent and zero registry requests", idle.silent()),
        ("registry names resolve from /etc/hosts to the loopback registry only, without DNS frames",
         all(v == [REGIP] for v in mapped.values()) and hosts.silent()),
        ("positive control: an unknown name is captured as a DNS frame and does not resolve (no route out)",
         "check.trivy.dev" in dns.dns() and unknown.returncode != 0),
        ("positive control: a TCP connection attempt is captured with its destination",
         (REGIP, 443) in tcp.dsts()),
    ]


def tc_registration():
    p0 = new_project("unauth ü", knowledge=False)
    with Window() as w0:
        c0, o0, _, _ = register(p0)
    unauth = [
        ("01b without Maintainer authorization: refused NOT_AUTHORIZED, nothing recorded, never executed",
         c0 == 1 and code_of(o0) == "NOT_AUTHORIZED" and not (p0 / RECORD).exists() and w0.procs == []),
    ]
    assert sc_pty([PASS, PASS], "auth", "init") == 0
    p = new_project("reg ü")
    tools = Path(tempfile.mkdtemp(prefix="tools-", dir=WORK))
    marker = tools / "executed"
    fake = tools / "fake" / "trivy"
    fake.parent.mkdir()
    fake.write_text(f"#!/bin/sh\ntouch {marker}\necho 'Version: 0.76.1'\n")
    fake.chmod(0o755)
    modified = tools / "modified" / "trivy"
    modified.parent.mkdir()
    shutil.copy(TRIVY, modified)
    with open(modified, "ab") as f:
        f.write(b"\0")
    link = tools / "link" / "trivy"
    link.parent.mkdir()
    os.symlink(TRIVY, link)
    refusals = {
        "custom build / other version (script printing 0.76.1)": (str(fake), "TOOL_DIGEST_UNKNOWN"),
        "modified official binary": (str(modified), "TOOL_DIGEST_UNKNOWN"),
        "release archive instead of the binary": (ARCHIVE_ARM, "TOOL_DIGEST_UNKNOWN"),
        "x86-64 official binary on an arm64 host": (TRIVY_X86, "TOOL_PLATFORM_MISMATCH"),
        "symbolic link to the official binary": (str(link), "TOOL_PATH_INVALID"),
        "missing path": (str(tools / "missing" / "trivy"), "TOOL_PATH_INVALID"),
        "folder": (str(tools), "TOOL_PATH_INVALID"),
        "relative path": ("trivy", "TOOL_PATH_INVALID"),
    }
    out = []
    for label, (path, code) in refusals.items():
        with Window() as w:
            c, o, _, _ = register(p, path)
        out.append((f"01b {label}: refused {code} with reason and next step, nothing recorded, not executed",
                    c == 1 and code_of(o) == code and bool(o.get("next_steps")) and not (p / RECORD).exists()
                    and w.procs == [] and not marker.exists()))
    with Window() as w:
        c_ok, o_ok, _, _ = register(p)
    record = json.loads((p / RECORD).read_text())
    st = status(p)["trivy"]
    c_again, o_again, _, _ = register(p)
    note("TC-D-01", {"record": record, "result": o_ok["data"], "status": st})
    return unauth + out + [
        ("01a official v0.76.1 linux/arm64 binary registered without executing it (no trivy process seen)",
         c_ok == 0 and w.procs == []),
        ("01a registration record: path, digest, version, asset (official archive), platform (libc none), "
         "validated platform", record["digest"] == OFFICIAL_ARM and record["version"] == "0.76.1"
         and record["path"] == TRIVY and record["platform"] == {"os": "linux", "arch": "aarch64", "libc": None}
         and record["platform_validated"] is True and o_ok["data"]["asset"] == "trivy_0.76.1_Linux-ARM64.tar.gz"),
        ("01f static entry (no C-library value) matches this glibc Linux host", record["platform"]["libc"] is None
         and c_ok == 0),
        ("01e refusals name the Maintainer action (register the official binary)",
         "register" in msg_of(register(p, str(modified))[1]).lower()),
        ("08a status: provided, registered, digest pre-check ok, validated platform, execution supported",
         st["state"] == "provided" and st["registered"] is True and st["check"] == "ok"
         and st["platform_validated"] is True and st["execution"] == "supported"),
        ("re-registration replaces the record explicitly", c_again == 0 and o_again["data"]["digest"] == OFFICIAL_ARM),
    ]


def _accepted_refusal(p, vid, before, w, c, o, code, missing=None, host=None, n_decl=1) -> bool:
    st = state(p, vid)
    new = [d for d in st["egress"]["declarations"] if d not in before["egress"]["declarations"]]
    return (c == 1 and code_of(o) == code and bool(o.get("next_steps")) and len(new) == n_decl
            and all(d["decision"] == "refused" and d["used"] is False and d["by"] == "toolkit"
                    and d["purpose"] == "tool_update" for d in new)
            and (missing is None or any(d.get("missing") == missing for d in new))
            and (host is None or any(d.get("host") == host for d in new))
            and st["attempts"] == before["attempts"] and st.get("tool_provisioning") == before.get("tool_provisioning")
            and w.procs == [] and w.silent() and not (p / CACHE / "components.json").exists())


def tc_provision_refusals():
    p = new_project("refuse ü")
    (p / "app").mkdir()
    (p / "app" / "requirements.txt").write_text("six==1.17.0\n")
    assert register(p)[0] == 0
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["app/requirements.txt"], [chk("C1", ["app/requirements.txt"])])
    out = []

    def attempt(label, comps, code, missing=None, host=None, n=None, **kw):
        before = state(p, vid)
        with Window() as w:
            c, o, _, _ = provision(p, vid, comps, **kw)
        ok = _accepted_refusal(p, vid, before, w, c, o, code, missing, host, n or max(1, len(comps)))
        out.append((f"02a {label}: refused {code} before execution, used:false declaration per component "
                    f"(missing {missing}), no attempt/budget/process/download, cache unchanged", ok))
        return o

    attempt("no grant", ["vulnerability_db", "java_db"], "EGRESS_NOT_AUTHORIZED", "purpose", "mirror.gcr.io")
    grant(p, vid, "https://ghcr.io", ["https://ghcr.io/aquasecurity/trivy-db:2"])
    attempt("grant for another origin (ghcr.io)", ["vulnerability_db"], "EGRESS_NOT_AUTHORIZED", "recipient")
    grant(p, vid, "https://mirror.gcr.io", ["https://mirror.gcr.io/aquasec/trivy-db:2"], purpose="reference_fetch")
    attempt("grant with another purpose (reference_fetch)", ["vulnerability_db"], "EGRESS_NOT_AUTHORIZED",
            "recipient")
    grant(p, vid, "https://mirror.gcr.io", ["https://mirror.gcr.io/aquasec/trivy-db:2"], data="public_query")
    attempt("tool_update grant without data category metadata", ["vulnerability_db"], "EGRESS_NOT_AUTHORIZED",
            "data")
    grant(p, vid, "https://mirror.gcr.io", ["https://mirror.gcr.io/aquasec/trivy-db:1",
                                            "https://mirror.gcr.io/aquasec/trivy-checks"])
    attempt("scope not covering the exact repository path and tag", ["vulnerability_db", "checks_bundle"],
            "EGRESS_NOT_AUTHORIZED", "scope")
    grant(p, vid, "https://mirror.gcr.io", ["https://mirror.gcr.io/aquasec/trivy-db:2"])
    o = attempt("scope covers the database but not the Java database (one component uncovered)",
                ["vulnerability_db", "java_db"], "EGRESS_NOT_AUTHORIZED", "scope", n=2)
    out.append(("02a refusal names the missing element per component (java_db scope; vulnerability_db refused "
                 "with the request)", o["data"]["components"].get("java_db", {}).get("missing") == "scope"))
    attempt("unknown component", ["license_db"], "PROVISION_REQUEST_INVALID", "component")
    attempt("invalid time limit 0", ["vulnerability_db"], "PROVISION_REQUEST_INVALID", "argument", time_limit=0)
    attempt("invalid time limit 3601", ["vulnerability_db"], "PROVISION_REQUEST_INVALID", "argument",
            time_limit=3601)
    attempt("unknown registry docker.io", ["vulnerability_db"], "PROVISION_REQUEST_INVALID", "argument",
            registry="docker.io")
    trust = Path.home() / ".config" / "ai-secure-code-toolkit"
    aside = trust.with_name("ai-secure-code-toolkit.aside")
    trust.rename(aside)
    try:
        attempt("no valid Maintainer authorization (trust folder missing)", ["vulnerability_db"], "NOT_AUTHORIZED",
                "maintainer")
    finally:
        aside.rename(trust)
    # verifications that are not accepted: nothing is recorded at all
    unaccepted = []
    v_done, _ = setup(p, scope, ["app/requirements.txt"], [chk("C1", ["app/requirements.txt"])])
    g(p, "conclude", v_done)
    v_cancel, _ = setup(p, scope, ["app/requirements.txt"], [chk("C1", ["app/requirements.txt"])])
    g(p, "cancel", v_cancel, None, "--reason", "user stopped")
    v_pause, _ = setup(p, scope, ["app/requirements.txt"], [chk("C1", ["app/requirements.txt"])])
    g(p, "pause", v_pause, None, "--reason", "waiting for the user")
    v_time, _ = open_v(p, scope, ["app/requirements.txt"], budget={"minutes": 1})
    plan(p, v_time, [chk("C1", ["app/requirements.txt"])])
    time.sleep(62)
    for label, v, code in (("unknown verification", "gv-20260101T000000Z-0000abcd", "RUN_NOT_FOUND"),
                           ("concluded verification", v_done, "RUN_FINISHED"),
                           ("cancelled verification", v_cancel, "RUN_CANCELLED"),
                           ("paused verification", v_pause, "RUN_PAUSED"),
                           ("verification out of time", v_time, "BUDGET_TIME_EXHAUSTED")):
        sfile = p / GUARD / v / "state.json"
        before = sfile.read_bytes() if sfile.exists() else None
        with Window() as w:
            c, o, _, _ = provision(p, v, ["vulnerability_db"])
        after = sfile.read_bytes() if sfile.exists() else None
        unaccepted.append((label, c, code_of(o)))
        out.append((f"02a {label}: refused {code}, nothing recorded (state byte-identical), nothing executed",
                    c == 1 and code_of(o) == code and before == after and w.procs == [] and w.silent()))
    p2 = new_project("unregistered ü")
    (p2 / "a.txt").write_text("x\n")
    s2 = save_scope(p2)
    v2, _ = setup(p2, s2, ["a.txt"], [chk("C1", ["a.txt"])])
    mirror_grants(p2, v2)
    before = state(p2, v2)
    with Window() as w:
        c, o, _, _ = provision(p2, v2, ["vulnerability_db"])
    out.append(("02a binary pre-check gap (tool not registered): refused, recorded used:false (missing binary), "
                "next step names registration", _accepted_refusal(p2, v2, before, w, c, o, "TOOL_NOT_REGISTERED",
                                                                   "binary")
                and "register" in msg_of(o).lower()))
    note("TC-D-02", {"unaccepted": unaccepted, "declarations": state(p, vid)["egress"]["declarations"][-3:]})
    REF["p"], REF["v_done"] = p, v_done
    return out


REF: dict = {}


# ---------------------------------------------------------------- main project (provisioned through the CLI)
MAIN: dict = {}
T_MAIN = ["WebGoat/pom.xml", "WebGoat/Dockerfile", "WebGoat/Dockerfile_desktop", "WebGoat/src", "marathon",
          "fixtures", "images/redis-6-alpine.tar", "images/hello-world.tar", "images/jar-only.tar",
          "images/big-600m.tar", "bundle"]
OBJ = {
    "C1": ["WebGoat/pom.xml"], "C2": ["WebGoat/Dockerfile"], "C3": ["WebGoat/Dockerfile_desktop"],
    "C4": ["WebGoat/Dockerfile_desktop"], "C5": ["WebGoat/src"], "C6": ["marathon"], "C7": ["fixtures/secret"],
    "C8": ["fixtures/req"], "C9": ["fixtures/misconfig"], "C10": ["fixtures/misconfig"],
    "C11": ["fixtures/misconfig/Dockerfile", "fixtures/misconfig/deployment.yaml", "fixtures/misconfig/main.tf"],
    "C12": ["fixtures/tf-clean/clean.tf"], "C13": ["images/redis-6-alpine.tar"], "C14": ["images/hello-world.tar"],
    "C15": ["images/jar-only.tar"], "C16": ["images/big-600m.tar"], "C17": ["fixtures/cfgfiles"], "C18": ["bundle"],
    "C19": ["fixtures/npm"], "C20": ["fixtures/gomod"], "C21": ["fixtures/composer"], "C22": ["fixtures/pipvuln"],
    "C23": ["fixtures/ansible/site.yml"],
}
PIP_WARN = "[pip] Unable to find python `site-packages` directory. License detection is skipped."
VENDOR_WARN = "Using severities from other vendors for some vulnerabilities."
ANSIBLE_PLAYBOOK = ("- name: Provision storage\n  hosts: localhost\n  tasks:\n    - name: Create a public bucket\n"
                    "      amazon.aws.s3_bucket:\n        name: fat-demo-bucket\n        state: present\n"
                    "        public_access:\n          block_public_acls: false\n          block_public_policy: false\n"
                    "          ignore_public_acls: false\n          restrict_public_buckets: false\n")
NPM_LOCK = {"name": "demo", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "demo", "version": "1.0.0", "dependencies": {"ms": "2.1.3"}},
    "node_modules/ms": {"version": "2.1.3", "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
                        "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/"
                                     "tXtF3WRTlA=="}}}


def populate(p: Path) -> None:
    shutil.copytree(SAMPLES / "test-projects" / "WebGoat", p / "WebGoat", symlinks=True,
                    ignore=shutil.ignore_patterns(".x-ipe", ".git"))
    shutil.copytree(SAMPLES / "shanghai-marathon-registration", p / "marathon", symlinks=True)
    aws, pat = fake_secrets()
    f = p / "fixtures"
    (f / "secret").mkdir(parents=True)
    (f / "secret" / "settings.env").write_text(f"APP_NAME=demo\nAWS_ACCESS_KEY_ID={aws}\nGITHUB_TOKEN={pat}\n")
    (f / "secret" / "clean.txt").write_text("nothing secret here\n")
    shutil.copytree(FIXTURES / "misconfig", f / "misconfig")
    (f / "tf-clean").mkdir()
    (f / "tf-clean" / "clean.tf").write_text('variable "region" {\n  type    = string\n  default = "eu-west-1"\n}\n')
    (f / "req").mkdir()
    (f / "req" / "requirements.txt").write_text("six==1.17.0\n")
    (f / "npm").mkdir()
    (f / "npm" / "package-lock.json").write_text(json.dumps(NPM_LOCK))
    (f / "composer").mkdir()
    (f / "composer" / "composer.lock").write_text(json.dumps(
        {"packages": [{"name": "guzzlehttp/guzzle", "version": "6.5.0"}], "packages-dev": []}))
    (f / "pipvuln").mkdir()
    (f / "pipvuln" / "requirements.txt").write_text("requests==2.19.0\n")
    (f / "ansible").mkdir()
    (f / "ansible" / "site.yml").write_text(ANSIBLE_PLAYBOOK)  # self-authored Ansible playbook (FF-06)
    (f / "gomod").mkdir()
    (f / "gomod" / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n\nrequire golang.org/x/text v0.21.0\n")
    cfg = f / "cfgfiles"
    cfg.mkdir()
    for d in (cfg, p):  # project-supplied Trivy configuration that would suppress findings if it were loaded
        (d / "trivy.yaml").write_text("severity: CRITICAL\nscan:\n  skip-files:\n    - '**/*.env'\n")
        (d / ".trivyignore").write_text("aws-access-key-id\ngithub-pat\nCVE-2013-7285\n")
        (d / "trivy-secret.yaml").write_text("disable-rules:\n  - aws-access-key-id\n  - github-pat\n")
    (cfg / "app.env").write_text(f"AWS_ACCESS_KEY_ID={aws}\n")
    (p / "images").mkdir()
    for name in ("redis-6-alpine.tar", "hello-world.tar", "jar-only.tar", "big-600m.tar"):
        shutil.copy(IMAGES / name, p / "images" / name)
    (p / "bundle").mkdir()
    shutil.copy(IMAGES / "hello-world.tar", p / "bundle" / "nested.tar")
    (p / "bundle" / "requirements.txt").write_text("six==1.17.0\n")
    (p / "README.md").write_text("# acceptance project\n")


def tc_provision_mirror():
    p = new_project("proj ü")
    assert register(p)[0] == 0
    populate(p)
    scope = save_scope(p)
    vid, digests = setup(p, scope, T_MAIN, [chk(c, o) for c, o in OBJ.items()], context=["README.md"])
    MAIN.update(p=p, vid=vid, digests=digests, scope=scope, original=tree(p, (".x-ipe", "x-ipe-docs")))
    extend(p, vid)
    st0 = state(p, vid)
    granted = mirror_grants(p, vid)
    registry_mode()
    with Window() as w:
        c, o, _, err = provision(p, vid, list(COMPONENTS), time_limit=1800)
    st = state(p, vid)
    ops = {op["component"]: op for op in o["data"]["operations"]}
    new_decl = [d for d in st["egress"]["declarations"] if d not in st0["egress"]["declarations"]]
    new_att = [a for a in st["attempts"] if a not in st0["attempts"]]
    entry = st["tool_provisioning"][-1]
    procs = {x["argv"][1] + ("-java" if "--download-java-db-only" in x["argv"] else ""): x for x in w.procs}
    pv, pj, pc = procs.get("image"), procs.get("image-java"), procs.get("fs")
    comp_json = json.loads((p / CACHE / "components.json").read_text())
    meta_files = {n: json.loads((p / CACHE / "gen" / n / comp_json["components"][n]["generation"] / sub /
                                 "metadata.json").read_text())
                  for n, sub in (("vulnerability_db", "db"), ("java_db", "java-db"), ("checks_bundle", "policy"))}
    st_tools = status(p)["trivy"]
    MAIN["prov_window"], MAIN["ops"] = w.summary(), ops
    note("TC-D-03", {"window": w.summary(), "operations": o["data"]["operations"], "attempt": new_att,
                     "declarations": new_decl, "argv": {k: v.get("argv") for k, v in procs.items()},
                     "registry_paths": sorted({r.get("path") for r in w.reg if r.get("path")})})

    def one_repo(proc, flag, repo):
        a = proc.get("argv") or []
        return a.count(flag) == 1 and a[a.index(flag) + 1] == repo and not any(
            x in a for x in ("--db-repository", "--java-db-repository", "--checks-bundle-repository") if x != flag)

    return [
        ("grants given by the user at a terminal (tool_update, metadata, exact repository scopes)", granted),
        ("02b/02c every component provisioned, one operation each, outcome completed, previous missing",
         c == 0 and set(ops) == set(COMPONENTS) and all(x["outcome"] == "completed" and x["previous"] == "missing"
                                                        for x in ops.values())),
        ("02b vulnerability DB argv: image --download-db-only with exactly one --db-repository "
         "mirror.gcr.io/aquasec/trivy-db:2, version check and telemetry off",
         pv is not None and pv["argv"][1:3] == ["image", "--download-db-only"]
         and one_repo(pv, "--db-repository", "mirror.gcr.io/aquasec/trivy-db:2")
         and "--skip-version-check" in pv["argv"] and "--disable-telemetry" in pv["argv"]),
        ("02b Java DB argv: image --download-java-db-only with exactly one --java-db-repository :1",
         pj is not None and one_repo(pj, "--java-db-repository", "mirror.gcr.io/aquasec/trivy-java-db:1")
         and "--skip-version-check" in pj["argv"] and "--disable-telemetry" in pj["argv"]),
        ("02b checks bundle argv: fs --scanners misconfig on an empty folder with exactly one "
         "--checks-bundle-repository :2 and all update/lookup skips",
         pc is not None and one_repo(pc, "--checks-bundle-repository", "mirror.gcr.io/aquasec/trivy-checks:2")
         and all(f in pc["argv"] for f in ("--skip-db-update", "--skip-java-db-update", "--offline-scan",
                                            "--skip-version-check", "--disable-telemetry"))
         and pc["argv"][-1].endswith("/empty")),
        ("02b no project file passed; minimal environment; private operation folder as working folder",
         all(no_project_path(x.get("argv", []), p) and set(x.get("env", {})) == MINIMAL_ENV
             and f"/{CACHE}/staging/op-" in x.get("cwd", "") for x in w.procs) and len(w.procs) == 3),
        ("02b observed (loopback registry): TLS SNI and HTTP Host only mirror.gcr.io, only the three exact "
         "repositories, no fallback registry",
         w.snis() == {"mirror.gcr.io"} and w.hosts() == {"mirror.gcr.io"}
         and {r["path"].split("/manifests/")[0] for r in w.reg if "/manifests/" in r.get("path", "")}
         == {"/v2/aquasec/trivy-db", "/v2/aquasec/trivy-java-db", "/v2/aquasec/trivy-checks"}),
        ("02b observed: every frame sent went to the registry on 443; no DNS query, no other host or port",
         only_registry(w)),
        ("02b one allowed declaration per operation, used:true, listing every known host with its grant",
         len(new_decl) == 3 and all(d["decision"] == "allowed" and d["used"] is True
                                    and [h["host"] for h in d["known_hosts"]] == ["mirror.gcr.io"]
                                    and d["known_hosts"][0]["grant"] for d in new_decl)),
        ("02b provisioning registered as one tool_update attempt of the verification, finished",
         len(new_att) == 1 and new_att[0]["kind"] == "tool_update" and new_att[0]["status"] != "running"),
        ("02c result: repository, tag, outcome, size, time, metadata per component (DB: Version/UpdatedAt/"
         "NextUpdate/DownloadedAt; bundle: MajorVersion/Digest/DownloadedAt), content digest",
         all(ops[n]["repository"] and ops[n]["tag"] and ops[n]["size_bytes"] > 0 and ops[n]["seconds"] is not None
             and ops[n]["content_digest"].startswith("sha256:") for n in COMPONENTS)
         and set(ops["vulnerability_db"]["metadata"]) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
         and set(ops["java_db"]["metadata"]) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
         and set(ops["checks_bundle"]["metadata"]) >= {"MajorVersion", "Digest", "DownloadedAt"}
         and ops["checks_bundle"]["metadata"]["MajorVersion"] == 2),
        ("02c recorded metadata equals the provisioned metadata.json files",
         all(all(meta_files[n].get(k) == v or k == "DownloadedAt" for k, v in ops[n]["metadata"].items())
             for n in COMPONENTS)),
        ("02c result records the Maintainer action, grant used and the configuration-level limit",
         entry["maintainer"]["action"] == "tools.provision" and all(ops[n]["grants"] for n in COMPONENTS)
         and "configuration-level" in entry["limit"] and "not network enforcement" in entry["limit"]),
        ("components stored per project in the private cache; staging removed",
         staging_empty(p) and set(comp_json["components"]) == set(COMPONENTS)),
        ("08a status reports each component present with registry, repository:tag and digest",
         all(st_tools["components"][n]["state"] == "present" and st_tools["components"][n]["registry"]
             == "mirror.gcr.io" for n in COMPONENTS)),
    ]


def tc_ghcr_known_hosts():
    p = new_project("ghcr ü")
    (p / "a.txt").write_text("x\n")
    assert register(p)[0] == 0
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["a.txt"], [chk("C1", ["a.txt"])])
    comps = ["checks_bundle", "vulnerability_db"]
    grant(p, vid, "https://ghcr.io", [f"https://{REPOS['ghcr.io'][c]}" for c in comps])
    out = []
    before = state(p, vid)
    with Window() as w1:
        c1, o1, _, _ = provision(p, vid, comps, registry="ghcr.io")
    out.append(("02b ghcr.io without a grant for its blob host: refused before launch, used:false naming "
                "pkg-containers.githubusercontent.com, no attempt/budget/process/contact",
                _accepted_refusal(p, vid, before, w1, c1, o1, "EGRESS_NOT_AUTHORIZED", None, BLOB, 2)
                and BLOB in msg_of(o1)))
    grant(p, vid, f"https://{BLOB}", [f"https://{BLOB}/ghcr1/"])
    before = state(p, vid)
    with Window() as w2:
        c2, o2, _, _ = provision(p, vid, comps, registry="ghcr.io")
    out.append(("02b narrower blob-host grant (path prefix) does not cover the origin root: refused",
                _accepted_refusal(p, vid, before, w2, c2, o2, "EGRESS_NOT_AUTHORIZED", "scope", BLOB, 2)))
    grant(p, vid, f"https://{BLOB}", [f"https://{BLOB}"])
    st0 = state(p, vid)
    with Window() as w3:
        c3, o3, _, _ = provision(p, vid, comps, registry="ghcr.io")
    st = state(p, vid)
    new_decl = [d for d in st["egress"]["declarations"] if d not in st0["egress"]["declarations"]]
    tools = status(p)["trivy"]["components"]
    note("TC-D-04", {"window": w3.summary(), "declarations": new_decl, "operations": (o3 or {}).get("data")})
    out += [
        ("02b with grants for every known host: executed, outcome completed for each component",
         c3 == 0 and all(op["outcome"] == "completed" for op in o3["data"]["operations"])),
        ("02b egress record: allowed, used:true, lists both known hosts (ghcr.io and its blob host) with grants",
         len(new_decl) == 2 and all(d["decision"] == "allowed" and d["used"] is True
                                    and [h["host"] for h in d["known_hosts"]] == ["ghcr.io", BLOB]
                                    and all(h["grant"] for h in d["known_hosts"]) for d in new_decl)),
        ("02b observed (loopback): SNI exactly {ghcr.io, pkg-containers.githubusercontent.com}; no mirror.gcr.io",
         w3.snis() == {"ghcr.io", BLOB} and "mirror.gcr.io" not in w3.hosts() and only_registry(w3)),
        ("02b registries not interchangeable: status records registry ghcr.io, repository and content digest",
         all(tools[n]["registry"] == "ghcr.io" and tools[n]["repository"].startswith("ghcr.io/aquasecurity/")
             and tools[n]["content_digest"].startswith("sha256:") for n in comps)
         and tools["java_db"]["state"] == "missing"),
    ]
    return out


def no_project_path(argv: list[str], p: Path) -> bool:
    return all(not a.startswith(str(p)) or a.startswith(str(p / PRIVATE)) for a in argv)


def _scan(group: str, checks: list[dict], time_limit=600):
    p, vid = MAIN["p"], MAIN["vid"]
    before = tree(p, (".x-ipe", "x-ipe-docs"))
    with Window() as w:
        c, o, _, err = tool(p, vid, checks, time_limit)
    entry = run_of(p, vid)
    manifest, output = stored(p, vid, entry)
    after = tree(p, (".x-ipe", "x-ipe-docs"))
    MAIN.setdefault("windows", {})[group] = w.summary()
    common = [
        (f"{group}: guard tool recorded (exit 0)", c == 0 and o["ok"]),
        (f"{group}: zero outbound attempts during the scan (no frame on any interface, no registry request)",
         w.silent()),
        (f"{group}: originals and context byte-identical; staging and disposable folders removed",
         before == after and staging_empty(p) and all(not Path(x.get("cache_dir", "/nonexistent")).exists()
                                                       and not Path(x.get("cwd", "/nonexistent")).exists()
                                                       for x in w.procs)),
        (f"{group}: no Trivy process left running", PROCS.alive() == []),
        (f"{group}: post-scan re-hash of every used component unchanged",
         all(v == "unchanged" for v in entry["rehash"].values())),
    ]
    for x in w.procs:
        if "--scanners" in (x.get("argv") or []):
            common += scan_argv_checks(x, f"{group} {x['argv'][1]} {x['argv'][x['argv'].index('--scanners') + 1]}")
    return c, o, w, entry, manifest, output, common


def tc_scans_mvp():
    p, vid, digests = MAIN["p"], MAIN["vid"], MAIN["digests"]
    out = []
    # --- dependency vulnerabilities of WebGoat/pom.xml (spec outcome scenario)
    c, o, w, e, man, outp, common = _scan("G1 pom.xml", [tchk("C1", ["vuln"], "filesystem", ["WebGoat/pom.xml"])])
    out += common
    f1 = [f for f in state(p, vid)["findings"] if f["check"] == "C1"]
    tool_vulns = [v for r in outp["C1"]["vuln"]["Results"] if r["Target"] == "WebGoat/pom.xml"
                  for v in r.get("Vulnerabilities") or []] if isinstance(outp.get("C1"), dict) and "vuln" in outp["C1"] \
        else None
    a = acc(e, "C1", "vuln")
    ev = ev_of(p, vid, "C1")
    vdb = e["components"]["vulnerability_db"]
    updated = parse_time(vdb["metadata"]["UpdatedAt"])
    proc = by_scanner(w.procs, "vuln")
    note("TC-D-06 C1", {"findings": len(f1), "tool_vulns": None if tool_vulns is None else len(tool_vulns),
                        "status": e["checks"]["C1"]["status"], "method_status": e["checks"]["C1"]["method_status"],
                        "skipped_packages": len(a["skipped_packages"]), "gaps": e["checks"]["C1"]["gaps"][:5],
                        "messages": e["checks"]["C1"]["processes"][0].get("messages"), "analysed": a["analysed"],
                        "summary": ev["summary"][:600], "output_keys": list(outp.get("C1", {}))[:5]})
    out += [
        ("05a pom.xml analysed as a manifest with its packages (tool's lang-pkgs result)",
         "WebGoat/pom.xml" in a["analysed"] and sum(a["packages"].values()) > 0),
        ("05d findings: source trivy, scanner vuln, tool id, package name/installed/fixed, tool severity and the "
         "fixed Guard mapping, project-relative location, attributed to C1 / its Policy",
         len(f1) > 0 and all(f["source"] == "trivy" and f["tool"]["scanner"] == "vuln" and f["tool"]["rule_id"]
                             and f["tool"]["package"]["name"] and "installed" in f["tool"]["package"]
                             and f["severity"] == SEVERITY.get(f["tool"]["tool_severity"], "unknown")
                             and f["location"]["path"] == "WebGoat/pom.xml" and f["rule"] == R1
                             and f["evidence"] == [ev["id"]] for f in f1)),
        ("05d every vulnerability in the retained tool output is a finding (independent count)",
         tool_vulns is not None and len(tool_vulns) == len(f1)),
        ("05a/05b/05f packages skipped offline are named gaps; transitive note; check fails (spec scenario)",
         len(a["skipped_packages"]) > 0 and ev["method_status"] == "failed"
         and "transitive" in json.dumps(a).lower()),
        ("05f analysis-degrading WARN (dependency version cannot be determined) -> completed_with_errors",
         e["checks"]["C1"]["status"] == "completed_with_errors"),
        ("05e evidence provenance: version, binary digest, validation state, scanners, mode, staged digest = "
         "digest at open, component state, exit status, duration, accounting, shared output",
         e["version"] == "0.76.1" and e["binary_digest"] == OFFICIAL_ARM and e["platform_validated"] is True
         and e["staged_digests"].get("WebGoat/pom.xml") == digests["WebGoat/pom.xml"]
         and e["checks"]["C1"]["scanners"] == ["vuln"] and e["checks"]["C1"]["mode"] == "filesystem"
         and e["checks"]["C1"]["processes"][0]["exit"] == 0 and e["checks"]["C1"]["processes"][0]["seconds"] >= 0
         and ev["kind"] == "runtime" and ev["method"] == "trivy" and ev["stored"].endswith("-output.json")
         and "accounting" in man["checks"]["C1"]),
        ("02f component state in evidence: Version/UpdatedAt/NextUpdate/DownloadedAt and age = scan time - "
         "UpdatedAt; no staleness verdict", vdb["state"] == "present"
         and set(vdb["metadata"]) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
         and abs(vdb["age_seconds"] - (datetime.now(timezone.utc) - updated).total_seconds()) < 900
         and "UpdatedAt" in ev["summary"] and "stale" not in json.dumps(e).lower()),
        ("02g components read in place: per-scan cache holds only a symlink db -> current generation",
         len(proc) == 1 and links_ok(proc[0], p, {"db"})),
        ("02d vuln scan argv: --list-all-pkgs, fs on the per-check tree", len(proc) == 1
         and "--list-all-pkgs" in proc[0]["argv"] and proc[0]["argv"][1] == "fs"),
        ("06a/06c run accepted for planned checks with a selected trivy runtime method; method choice recorded",
         state(p, vid)["plan"]["checks"][0]["method_choice"]["selected"] == ["trivy"]),
    ]
    # --- misconfigurations of WebGoat Dockerfiles (override)
    c, o, w, e, man, outp, common = _scan("G2 Dockerfiles", [
        tchk("C2", ["misconfig"], "filesystem", ["WebGoat/Dockerfile"]),
        tchk("C3", ["misconfig"], "filesystem", ["WebGoat/Dockerfile_desktop"]),
        tchk("C4", ["misconfig"], "filesystem", ["WebGoat/Dockerfile_desktop"],
             [{"path": "WebGoat/Dockerfile_desktop", "type": "dockerfile"}])])
    out += common
    a2, a3, a4 = acc(e, "C2", "misconfig"), acc(e, "C3", "misconfig"), acc(e, "C4", "misconfig")
    f4 = [f for f in state(p, vid)["findings"] if f["check"] == "C4"]
    procs = by_scanner(w.procs, "misconfig")
    pat = [x for x in procs if "--file-patterns" in x["argv"]]
    note("TC-D-06 G2", {"C2": a2, "C3": a3, "C4": a4, "status": {k: e["checks"][k]["method_status"]
                                                               for k in ("C2", "C3", "C4")}})
    out += [
        ("05a Dockerfile analysed with pass/fail counts from the provisioned checks bundle; check ok",
         "WebGoat/Dockerfile" in a2["analysed"] and "WebGoat/Dockerfile" in a2["misconf"]
         and a2["checks_source"] == "provisioned" and e["checks"]["C2"]["method_status"] == "ok"),
        ("05a Dockerfile_desktop without override: named gap (not recognized), failed method",
         a3["unrecognized"] and e["checks"]["C3"]["method_status"] == "failed"),
        ("03d override reaches the tool as --file-patterns dockerfile:<path>; analysed; findings recorded; ok",
         len(pat) == 1 and any(v.startswith("dockerfile:") for v in pat[0]["argv"])
         and "WebGoat/Dockerfile_desktop" in a4["analysed"] and len(f4) > 0
         and e["checks"]["C4"]["method_status"] == "ok"
         and all(f["tool"]["scanner"] == "misconfig" and f["tool"]["rule_id"] for f in f4)),
        ("02g misconfig scans link only policy -> current checks-bundle generation",
         procs and all(links_ok(x, p, {"policy"}) for x in procs)),
    ]
    # --- secrets in WebGoat/src and the marathon sample (skipped files named)
    c, o, w, e, man, outp, common = _scan("G3 secrets samples", [
        tchk("C5", ["secret"], "filesystem", ["WebGoat/src"]),
        tchk("C6", ["secret"], "filesystem", ["marathon"])])
    out += common
    a5, a6 = acc(e, "C5", "secret"), acc(e, "C6", "secret")
    n_src = sum(1 for x in (p / "WebGoat" / "src").rglob("*") if x.is_file())
    n_mar = sum(1 for x in (p / "marathon").rglob("*") if x.is_file())
    note("TC-D-06 G3", {"C5": {"analysed": len(a5["analysed"]), "unaccounted": len(a5["unaccounted"]),
                               "skipped": len(a5["skipped"]), "files": n_src},
                        "C6": {"analysed": a6["analysed"], "unaccounted": a6["unaccounted"], "files": n_mar}})
    out += [
        ("05a secret coverage only from the tool's streaming-scanner lines; every other file a named gap "
         "(WebGoat/src incl. test files)", len(a5["analysed"]) + len(a5["unaccounted"]) + len(a5["skipped"])
         == n_src and any("/test/" in json.dumps(x) for x in a5["unaccounted"] + a5["skipped"])
         and e["checks"]["C5"]["method_status"] == "failed"),
        ("05a marathon: tests/, data/ and the image not scanned -> named gaps, failed method",
         len(a6["analysed"]) + len(a6["unaccounted"]) + len(a6["skipped"]) == n_mar
         and any("tests/" in json.dumps(x) for x in a6["unaccounted"] + a6["skipped"])
         and e["checks"]["C6"]["method_status"] == "failed"),
        ("02g secret scans need no component: empty per-scan cache", all(x.get("cache_entries") == {}
                                                                         for x in by_scanner(w.procs, "secret"))),
    ]
    return out


def tc_secrets_and_config_files():
    p, vid = MAIN["p"], MAIN["vid"]
    c, o, w, e, man, outp, common = _scan("G4 secrets/clean/config files", [
        tchk("C7", ["secret"], "filesystem", ["fixtures/secret"]),
        tchk("C8", ["vuln", "secret"], "filesystem", ["fixtures/req"]),
        tchk("C17", ["secret"], "filesystem", ["fixtures/cfgfiles"]),
        tchk("C18", ["vuln", "secret"], "filesystem", ["bundle"]),
        tchk("C19", ["vuln"], "filesystem", ["fixtures/npm"]),
        tchk("C20", ["vuln"], "filesystem", ["fixtures/gomod"]),
        tchk("C21", ["vuln"], "filesystem", ["fixtures/composer"]),
        tchk("C22", ["vuln"], "filesystem", ["fixtures/pipvuln"])])
    st = state(p, vid)
    f7 = [f for f in st["findings"] if f["check"] == "C7"]
    f17 = [f for f in st["findings"] if f["check"] == "C17"]
    raw7 = outp["C7"]["secret"]
    secrets_raw = [s for r in raw7.get("Results") or [] for s in r.get("Secrets") or []]
    a8v, a8s, a18v = acc(e, "C8", "vuln"), acc(e, "C8", "secret"), acc(e, "C18", "vuln")
    images = [x for x in w.procs if (x.get("argv") or [None, None])[1] == "image"]
    MAIN["secret_findings"] = f7
    note("TC-D-07 G4", {"C7": [(f["tool"]["rule_id"], f["tool"].get("secret"), f["description"]) for f in f7],
                        "C8": {"status": e["checks"]["C8"]["method_status"], "gaps": e["checks"]["C8"]["gaps"]},
                        "C19": {"status": e["checks"]["C19"]["method_status"], "gaps": e["checks"]["C19"]["gaps"]},
                        "C20": {"status": e["checks"]["C20"]["method_status"], "gaps": e["checks"]["C20"]["gaps"],
                                "findings": len([f for f in st["findings"] if f["check"] == "C20"])},
                        "C21": {"status": e["checks"]["C21"]["method_status"], "gaps": e["checks"]["C21"]["gaps"],
                                "processes": e["checks"]["C21"]["processes"]},
                        "C22": {"status": e["checks"]["C22"]["method_status"], "gaps": e["checks"]["C22"]["gaps"],
                                "processes": e["checks"]["C22"]["processes"]},
                        "C8_processes": e["checks"]["C8"]["processes"],
                        "C17": [f["tool"]["rule_id"] for f in f17],
                        "C18": {"vuln": a18v, "status": e["checks"]["C18"]["method_status"]}})
    return common + [
        ("05b fixture folder fully analysed by the secret scanner, no tool error: successful method",
         e["checks"]["C7"]["method_status"] == "ok" and set(acc(e, "C7", "secret")["analysed"])
         == {"fixtures/secret/settings.env", "fixtures/secret/clean.txt"}),
        ("05c/05d secret findings: rule id, category, tool severity, location and line, masked representation "
         "(length only) - no value", {f["tool"]["rule_id"] for f in f7} == {"aws-access-key-id", "github-pat"}
         and all(f["tool"]["secret"]["representation"] == "masked" and f["tool"]["secret"]["length"] > 0
                 and f["tool"]["category"] and f["location"]["line"] and f["severity"] == "critical"
                 and "value masked" in f["description"] for f in f7)),
        ("05c stored tool output keeps no Match/Code/Offset of secrets", secrets_raw
         and all(not ({"Match", "Code", "Offset"} & set(s)) for s in secrets_raw)),
        ("05g complete clean run with zero results (npm lockfile): successful evidence, no findings",
         e["checks"]["C19"]["method_status"] == "ok" and not [f for f in st["findings"] if f["check"] == "C19"]
         and acc(e, "C19", "vuln")["analysed"] == ["fixtures/npm/package-lock.json"]),
        ("F-2 precondition: Trivy runs with the minimal PATH /bin:/usr/bin and no Python there (the real license "
         "WARN can occur)", all(x.get("env", {}).get("PATH") == "/bin:/usr/bin" for x in w.procs)
         and not any(os.path.exists(f"{d}/{n}") for d in ("/bin", "/usr/bin") for n in ("python", "python3"))),
        ("05b pip requirements.txt fully analysed by vuln and secret; the real WARN 'Unable to find python "
         "site-packages directory. License detection is skipped.' occurred for both scanners and is recorded as "
         "benign: successful method", a8v["analysed"] == ["fixtures/req/requirements.txt"]
         and a8s["analysed"] == ["fixtures/req/requirements.txt"] and e["checks"]["C8"]["method_status"] == "ok"
         and e["checks"]["C8"]["status"] == "completed"
         and sum(PIP_WARN in json.dumps(pr.get("messages")) for pr in e["checks"]["C8"]["processes"]) == 2),
        ("05b vulnerable pip manifest (requests 2.19.0) with the same real license WARN: analysed, findings "
         "recorded, successful method", acc(e, "C22", "vuln")["analysed"] == ["fixtures/pipvuln/requirements.txt"]
         and [f for f in st["findings"] if f["check"] == "C22"] and e["checks"]["C22"]["method_status"] == "ok"
         and PIP_WARN in json.dumps(e["checks"]["C22"]["processes"])),
        ("05b composer.lock (guzzle 6.5.0) with the real WARN 'Using severities from other vendors for some "
         "vulnerabilities…' and no other gap: analysed, findings recorded, successful method",
         acc(e, "C21", "vuln")["analysed"] == ["fixtures/composer/composer.lock"]
         and [f for f in st["findings"] if f["check"] == "C21"] and e["checks"]["C21"]["method_status"] == "ok"
         and VENDOR_WARN in json.dumps(e["checks"]["C21"]["processes"])),
        ("05b/05f fail-closed: an unlisted real WARN ('[pom] Dependency version cannot be determined…', TC-D-06 run) "
         "still makes the process completed_with_errors and is named as a gap", (lambda r: r["checks"]["C1"]["status"]
         == "completed_with_errors" and "tool WARN: [pom] Dependency version cannot be determined" in
         json.dumps(r["checks"]["C1"]["gaps"]))(next(r for r in st["adapter_runs"] if "C1" in r["checks"]))),
        ("05a/05b go.mod analysed with findings recorded; the package the tool skipped (the module itself, no "
         "version offline) is a named gap, so the check is a failed method",
         acc(e, "C20", "vuln")["analysed"] == ["fixtures/gomod/go.mod"]
         and [f for f in st["findings"] if f["check"] == "C20"] and acc(e, "C20", "vuln")["skipped_packages"]
         and e["checks"]["C20"]["method_status"] == "failed"),
        ("04a project-supplied trivy.yaml/.trivyignore/trivy-secret.yaml never loaded: the AWS key in the same "
         "folder is still reported", "aws-access-key-id" in {f["tool"]["rule_id"] for f in f17}),
        ("03i .tar inside a folder target in filesystem mode is an ordinary file: no image scan, named gap",
         images == [] and any(x["path"] == "bundle/nested.tar" for x in a18v["unrecognized"])
         and "bundle/requirements.txt" in a18v["analysed"]),
    ]


def tc_misconfig_fixtures():
    p, vid = MAIN["p"], MAIN["vid"]
    c, o, w, e, man, outp, common = _scan("G5 misconfig fixtures", [
        tchk("C9", ["misconfig"], "filesystem", ["fixtures/misconfig"]),
        tchk("C10", ["secret"], "filesystem", ["fixtures/misconfig"]),
        tchk("C11", ["misconfig"], "filesystem", OBJ["C11"]),
        tchk("C12", ["misconfig"], "filesystem", ["fixtures/tf-clean/clean.tf"]),
        tchk("C23", ["misconfig"], "filesystem", ["fixtures/ansible/site.yml"],
             [{"path": "fixtures/ansible/site.yml", "type": "ansible"}])])
    st = state(p, vid)
    a9, a10, a11, a12 = (acc(e, "C9", "misconfig"), acc(e, "C10", "secret"), acc(e, "C11", "misconfig"),
                         acc(e, "C12", "misconfig"))
    f9 = [f for f in st["findings"] if f["check"] == "C9"]
    compose = "fixtures/misconfig/docker-compose.yml"
    a23 = acc(e, "C23", "misconfig")
    f23 = [f for f in st["findings"] if f["check"] == "C23"]
    p23 = [x for x in by_scanner(w.procs, "misconfig") if "--file-patterns" in x["argv"]]
    note("TC-D-08 ansible", {"acc": a23, "status": e["checks"]["C23"]["status"],
                             "method_status": e["checks"]["C23"]["method_status"],
                             "findings": sorted(f["tool"]["rule_id"] for f in f23),
                             "argv_patterns": [x["argv"][x["argv"].index("--file-patterns") + 1] for x in p23]})
    note("TC-D-08 G5", {"C9": a9, "C10": a10["analysed"], "C11": {"analysed": a11["analysed"],
                                                                "status": e["checks"]["C11"]["method_status"],
                                                                "gaps": e["checks"]["C11"]["gaps"]},
                        "C12": {"acc": a12, "status": e["checks"]["C12"]["method_status"],
                                "results": [r.get("Target") for r in outp["C12"]["misconfig"].get("Results") or []]}})
    return common + [
        ("05h compose file in a misconfig check: named gap 'configuration type not supported by Trivy v0.76.1' "
         "with next step to use another method; failed method", any(x["path"] == compose for x in a9["unsupported"])
         and "configuration type not supported by Trivy v0.76.1" in gaps(e, "C9")
         and "semantic review" in gaps(e, "C9").lower() and e["checks"]["C9"]["method_status"] == "failed"),
        ("05h/05i findings of the other files in the same check are still recorded", len(f9) > 0
         and {f["location"]["path"] for f in f9} >= {"fixtures/misconfig/Dockerfile",
                                                     "fixtures/misconfig/deployment.yaml"}),
        ("05h secret check including the compose file treats it as an ordinary text file", compose in a10["analysed"]),
        ("05a Dockerfile, Kubernetes manifest and Terraform file analysed with pass/fail counts; check ok",
         set(a11["analysed"]) == set(OBJ["C11"]) and e["checks"]["C11"]["method_status"] == "ok"
         and all(set(v) >= {"successes", "failures"} or set(v) >= {"Successes", "Failures"}
                 for v in a11["misconf"].values())),
        ("03d actual `ansible` override on the real binary: request accepted; the tool receives "
         "--file-patterns ansible:<path>; the playbook is analysed with pass/fail counts; AWS findings recorded; "
         "successful method; zero outbound attempts", c == 0 and any(
             x["argv"][x["argv"].index("--file-patterns") + 1].startswith("ansible:") for x in p23)
         and a23["analysed"] == ["fixtures/ansible/site.yml"] and f23
         and all(f["tool"]["rule_id"].startswith("AWS-") and f["severity"] in SEVERITY.values() for f in f23)
         and e["checks"]["C23"]["method_status"] == "ok" and w.silent()),
        ("05a clean .tf (no failures): the tool names no per-file result (module-level '.' only), so the file "
         "is a named gap and the check a failed method (tool-statement accounting)",
         a12["analysed"] == [] and (a12["unaccounted"] or a12["unrecognized"])
         and e["checks"]["C12"]["method_status"] == "failed"),
    ]


def tc_image_archives():
    p, vid = MAIN["p"], MAIN["vid"]
    c, o, w, e, man, outp, common = _scan("G6 image archives", [
        tchk("C13", ["vuln"], "image_archive", ["images/redis-6-alpine.tar"]),
        tchk("C14", ["vuln"], "image_archive", ["images/hello-world.tar"]),
        tchk("C15", ["vuln"], "image_archive", ["images/jar-only.tar"]),
        tchk("C16", ["vuln"], "image_archive", ["images/big-600m.tar"])], time_limit=900)
    st = state(p, vid)
    a = {k: acc(e, k, "vuln") for k in ("C13", "C14", "C15", "C16")}
    f13 = [f for f in st["findings"] if f["check"] == "C13"]
    imgs = [x for x in w.procs if (x.get("argv") or [None, None])[1] == "image"]
    note("TC-D-09 G6", {k: {"image": v["image"], "status": e["checks"][k]["method_status"],
                            "gaps": e["checks"][k]["gaps"][:3]} for k, v in a.items()}
         | {"archives": e["archives"], "f13": len(f13)})
    return common + [
        ("03c/04a image scans: `image --input <staged snapshot> --cache-backend memory`, vuln only",
         len(imgs) == 4 and all("--input" in x["argv"] and "/adapter-stage/trivy/stage-" in
                                x["argv"][x["argv"].index("--input") + 1] and "--cache-backend" in x["argv"]
                                and x["argv"][x["argv"].index("--scanners") + 1] == "vuln" for x in imgs)),
        ("02g image scans link db and java-db to the current generations (read in place)",
         all(links_ok(x, p, {"db", "java-db"}) for x in imgs)),
        ("03h Docker >= 25 archive (manifest.json + oci-layout/index.json/blobs) accepted; structure recorded",
         all(k in e["archives"] for k in OBJ["C13"]) and c == 0),
        ("05a redis archive analysed with detected OS and package types; findings with layer and package path",
         a["C13"]["analysed"] == ["images/redis-6-alpine.tar"] and isinstance(a["C13"]["image"]["os"], dict)
         and a["C13"]["image"]["package_types"] and len(f13) > 0
         and all(f["location"]["path"] == "images/redis-6-alpine.tar" and f["tool"].get("layer") is not None
                 for f in f13)),
        ("05a hello-world: gap 'OS not detected', failed method", "OS not detected" in gaps(e, "C14")
         and e["checks"]["C14"]["method_status"] == "failed"),
        ("05a jar-only image: Java archive analysed inside the image with the Java DB (jar package type)",
         "jar" in a["C15"]["image"]["package_types"]),
        ("03g 600 MB docker save archive staged within the 8 GiB maximum (no staging-limit gap)",
         "STAGE_TOO_LARGE" not in gaps(e, "C16") and "too large" not in gaps(e, "C16").lower()
         and e["checks"]["C16"]["processes"]),
        ("03c nothing pulled or read from a runtime: no registry request and no frame during image scans",
         w.silent()),
    ]


def _disk_bytes(folder: Path) -> int:
    total = os.lstat(folder).st_blocks * 512
    for x in folder.rglob("*"):
        total += os.lstat(x).st_blocks * 512
    return total


def tc_status_main():
    p = MAIN["p"]
    with Window() as w:
        code, out, _, _ = sc("status", "--project", str(p), "--json")
    t = out["data"]["tools"]
    tv, comps = t["trivy"], t["trivy"]["components"]
    pointer = json.loads((p / CACHE / "components.json").read_text())["components"]
    disk = {n: _disk_bytes(p / CACHE / "gen" / n / pointer[n]["generation"]) for n in COMPONENTS}
    now = datetime.now(timezone.utc)
    note("TC-D-17", {"trivy": tv, "disk_independent": disk, "strix": t["strix"]})
    return [
        ("08a status runs without executing the tool or any network use", code == 0 and w.procs == [] and w.silent()),
        ("08a Trivy provided, registered, digest pre-check ok with validation state, execution supported",
         tv["state"] == "provided" and tv["registered"] is True and tv["check"] == "ok"
         and tv["platform_validated"] is True and tv["execution"] == "supported"),
        ("08a databases: present, Version/UpdatedAt/NextUpdate/DownloadedAt and age (now - UpdatedAt)",
         all(comps[n]["state"] == "present" and set(comps[n]["metadata"]) >= {"Version", "UpdatedAt", "NextUpdate",
                                                                               "DownloadedAt"}
             and abs(comps[n]["age_seconds"] - (now - parse_time(comps[n]["metadata"]["UpdatedAt"])).total_seconds())
             < 900 for n in ("vulnerability_db", "java_db"))),
        ("08a checks bundle: MajorVersion/Digest/DownloadedAt and source repository, no age",
         comps["checks_bundle"]["state"] == "present"
         and set(comps["checks_bundle"]["metadata"]) >= {"MajorVersion", "Digest", "DownloadedAt"}
         and "age_seconds" not in comps["checks_bundle"]
         and "mirror.gcr.io/aquasec/trivy-checks" in json.dumps(comps["checks_bundle"])),
        ("08c on-disk size per component equals the independently summed st_blocks of its generation; total",
         all(comps[n]["disk_bytes"] == disk[n] for n in COMPONENTS)
         and t["trivy"]["cache_disk_bytes_total"] == sum(disk.values())),
        ("08b Strix still reported as not provided by this toolkit version",
         t["strix"]["state"] == "adapter not provided by this toolkit version"),
        ("AC-002B-06b superseded part re-checked per AC-002D-08a: Trivy provided; Strix part unchanged",
         t["trivy"]["state"] == "provided" and t["strix"]["state"] == "adapter not provided by this toolkit version"),
    ]


def tc_report_and_masking():
    p, vid = MAIN["p"], MAIN["vid"]
    st = state(p, vid)
    tf = [f for f in st["findings"] if f["source"] == "trivy"]
    fake_ev = {"schema": "ai-secure-code-toolkit/guard-record/v1",
               "evidence": [{"id": "E9", "kind": "runtime", "method": "trivy", "method_status": "ok",
                             "checks": ["C8"], "paths": ["fixtures/req"], "summary": "I ran trivy myself"}]}
    c_ev, o_ev, _, _ = g(p, "record", vid, fake_ev)
    fake_f = {"schema": "ai-secure-code-toolkit/guard-record/v1",
              "findings": [{"id": tf[0]["id"], "rule": R1, "check": tf[0]["check"], "location": tf[0]["location"],
                            "title": "rewritten", "source": "trivy", "severity": "low", "evidence": ["E1"]}]}
    c_f, o_f, _, _ = g(p, "record", vid, fake_f)
    c_led, o_led, _, _ = g(p, "record", vid, {"schema": "ai-secure-code-toolkit/guard-record/v1", "ledger": [
        {"check": "C3", "state": "met", "evidence": [ev_of(p, vid, "C3")["id"]]}]})
    after = state(p, vid)
    with Window() as w:
        _, concl, _, _ = g(p, "conclude", vid)
    md = (p / REPORTS / f"{vid}.md").read_text()
    res = json.loads((p / REPORTS / f"{vid}.json").read_text())
    reasons = json.dumps(concl["data"]["reasons"])
    clean_md = (REF["p"] / REPORTS / f"{REF['v_done']}.md").read_text()
    ok_secret, hits = secret_free([p / ".x-ipe", p / "x-ipe-docs", Path(tempfile.gettempdir())])
    ctx_line = "APP_NAME=demo"
    ctx_free = not any(ctx_line in x.read_text(errors="replace") for x in (p / GUARD / vid).rglob("*") if x.is_file()) \
        and ctx_line not in md
    note("TC-D-18", {"verdict": concl["data"]["verdict"], "reason_codes": [r["code"] for r in concl["data"]["reasons"]],
                     "record_refusals": [code_of(o_ev), code_of(o_f), code_of(o_led), c_led], "secret_hits": hits,
                     "md_sections": re.findall(r"^## .*$", md, re.M)})
    return [
        ("06b agent cannot record trivy evidence (tool evidence only by guard tool)", c_ev == 1
         and "recorded only by secure-code guard tool" in msg_of(o_ev)),
        ("06b agent cannot rewrite or add a trivy finding", c_f == 1
         and "recorded only by secure-code guard tool" in msg_of(o_f)
         and [f for f in after["findings"] if f["id"] == tf[0]["id"]] == [tf[0]]),
        ("05g a failed trivy method never satisfies a check (ledger met on failed required evidence refused or "
         "not counted)", c_led == 1 or "C3" in reasons),
        ("05g/06b verdict decided by FEATURE-002-A rules: not Pass with unreviewed verdict-affecting trivy "
         "findings and zero-finding checks without a met ledger", concl["data"]["verdict"] != "pass"
         and any(f["id"] in reasons for f in tf) and w.procs == []),
        ("06c report shows the method choice per check with its reason", "## Method Choices and Changes" in md
         and "Trivy covers declared dependencies" in md),
        ("02b/02f report: Adapter Runs with Scanners/Mode, Trivy Component State, Tool Provisioning (repository, "
         "tag, known hosts, grants, outcome, budget), egress known hosts",
         "## Adapter Runs" in md and "Scanners" in md and "Mode" in md and "Trivy Component State" in md
         and "Tool Provisioning" in md and "mirror.gcr.io/aquasec/trivy-db" in md and "Known hosts" in md),
        ("02b/02g report states the limits: configuration-level known hosts (not enforcement); read in place, "
         "detection not prevention; no staleness threshold",
         "configuration-level" in md and "not prevented" in md.replace("\n", " ") and "staleness" in md),
        ("report JSON carries the Trivy runs and the provisioning entry", any(r.get("adapter") == "trivy"
                                                                              for r in res["adapter_runs"])
         and res.get("tool_provisioning")),
        ("Trivy report sections only when used: a verification without Trivy runs has none",
         "Trivy Component State" not in clean_md and "Tool Provisioning" not in clean_md
         and "Known hosts" not in clean_md),
        ("05c end to end: no fake credential plaintext in the private data, run folder, evidence, findings, "
         "reports or temporary folder", ok_secret),
        ("05c the tool's surrounding source line (context) is not stored in the run folder or report", ctx_free),
    ]


def _wait(pred, timeout=120, step=0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def _comp(p: Path, name: str) -> dict:
    return status(p)["trivy"]["components"][name]


def tc_provision_failures():
    p = new_project("fail ü")
    (p / "app").mkdir()
    (p / "app" / "requirements.txt").write_text("six==1.17.0\n")
    assert register(p)[0] == 0
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["app/requirements.txt"], [chk("C1", ["app/requirements.txt"])])
    extend(p, vid)
    mirror_grants(p, vid)
    registry_mode()
    c0, o0, _, _ = provision(p, vid, ["vulnerability_db", "checks_bundle"])
    prev_db, prev_cb = _comp(p, "vulnerability_db"), _comp(p, "checks_bundle")
    out = [("baseline: vulnerability DB and checks bundle provisioned from the loopback registry",
            c0 == 0 and prev_db["state"] == prev_cb["state"] == "present")]
    registry_mode(refuse=["mirror.gcr.io"])
    with Window() as w1:
        c1, o1, _, _ = provision(p, vid, ["vulnerability_db", "checks_bundle", "java_db"])
    registry_mode()
    ops = {x["component"]: x for x in o1["data"]["operations"]}
    note("TC-D-05 refused", {"ops": o1["data"]["operations"], "window": w1.summary(),
                             "tls": [r for r in w1.reg if r.get("event")][:6]})
    out += [
        ("02c repository unreachable: vulnerability DB operation failed, previous complete state kept",
         c1 == 0 and ops["vulnerability_db"]["outcome"] == "failed" and ops["vulnerability_db"]["previous"] == "kept"
         and _comp(p, "vulnerability_db")["content_digest"] == prev_db["content_digest"]),
        ("02c checks bundle: the tool exits 0 with its embedded fallback, the toolkit still records failed; "
         "previous kept", ops["checks_bundle"]["outcome"] == "failed" and ops["checks_bundle"]["previous"] == "kept"
         and _comp(p, "checks_bundle")["content_digest"] == prev_cb["content_digest"]),
        ("02c no previous Java DB: failed operation leaves it missing", ops["java_db"]["outcome"] == "failed"
         and _comp(p, "java_db")["state"] == "missing"),
        ("02b no automatic fallback to another registry: only mirror.gcr.io was contacted (and refused)",
         w1.snis() == {"mirror.gcr.io"} and only_registry(w1)),
        ("02c failed operations leave no partial data (staging removed)", staging_empty(p)),
    ]
    registry_mode(slow_bps=4_000_000)
    with Window() as w2:
        c2, o2, _, _ = provision(p, vid, ["vulnerability_db"], time_limit=5)
    registry_mode()
    op2 = o2["data"]["operations"][0]
    out += [("02c time limit reached during download: timed_out, previous kept, tool stopped, staging removed",
             op2["outcome"] == "timed_out" and op2["previous"] == "kept"
             and _comp(p, "vulnerability_db")["content_digest"] == prev_db["content_digest"]
             and PROCS.alive() == [] and staging_empty(p))]
    # toolkit killed during a download -> recovery keeps the previous state; the partial download is never used
    registry_mode(slow_bps=2_000_000)
    n0 = len(PROCS.order)
    killed = provision_bg(p, vid, ["vulnerability_db"], time_limit=600)
    started = _wait(lambda: any(PROCS.seen[x]["alive"] for x in PROCS.order[n0:]))
    time.sleep(2)
    os.killpg(killed.pid, signal.SIGKILL)
    killed.wait()
    for x in PROCS.since(n0):
        if x["alive"]:
            try:
                os.kill(x["pid"], signal.SIGKILL)  # the orphaned tool (its owner was killed)
            except ProcessLookupError:
                pass
    registry_mode()
    time.sleep(1)
    after_kill = _comp(p, "vulnerability_db")
    with Window() as w3:
        c3, o3, _, _ = tool(p, vid, [tchk("C1", ["vuln"], "filesystem", ["app/requirements.txt"])])
    e3 = run_of(p, vid)
    leftover = sorted(x.name for x in (p / CACHE / "staging").iterdir()) if (p / CACHE / "staging").exists() else []
    c3b, o3b, _, _ = provision(p, vid, ["checks_bundle"])
    note("TC-D-05 kill", {"after_kill": after_kill, "scan_component": e3["components"].get("vulnerability_db"),
                          "scan_gap": e3.get("gap"), "leftover_after_scan": leftover,
                          "stage_after_scan": staging_empty(p), "next_provision": c3b})
    out += [
        ("02c toolkit killed during a download: status still shows the previous complete component",
         started and after_kill["state"] == "present" and after_kill["content_digest"] == prev_db["content_digest"]),
        ("02c the next scan uses the previous complete generation (the partial download is never used); offline",
         c3 == 0 and e3["components"]["vulnerability_db"]["content_digest"] == prev_db["content_digest"]
         and w3.silent()),
        ("02c the interrupted operation's partial folder is swept by the next provisioning under the Guard lock",
         c3b == 0 and staging_empty(p)),
    ]
    # cancellation of a running provisioning (FEATURE-002-C)
    registry_mode(slow_bps=2_000_000)
    n1 = len(PROCS.order)
    st0 = state(p, vid)
    runner = provision_bg(p, vid, ["vulnerability_db"], time_limit=600)
    started = _wait(lambda: any(PROCS.seen[x]["alive"] for x in PROCS.order[n1:]))
    time.sleep(2)
    cc, cancelled, _, _ = g(p, "cancel", vid, None, "--reason", "user stopped the provisioning")
    rc, ro, _, _ = finish(runner)
    registry_mode()
    st = state(p, vid)
    res = json.loads((p / REPORTS / f"{vid}.json").read_text())
    new_att = [a for a in res.get("attempts", []) if a["id"] not in {x["id"] for x in st0["attempts"]}]
    note("TC-D-05 cancel", {"cancel": (cancelled or {}).get("data", {}).get("cancellation"), "provision": ro,
                            "attempts": new_att})
    out += [
        ("04e cancel stops the provisioning tool (owner confirms termination) and the command reports "
         "RUN_CANCELLED", started and cc == 0 and code_of(ro) == "RUN_CANCELLED" and PROCS.alive() == []),
        ("04e cancelled provisioning: previous complete component state kept, staging removed, no new "
         "provisioning entry", _comp(p, "vulnerability_db")["content_digest"] == prev_db["content_digest"]
         and staging_empty(p) and len(st.get("tool_provisioning", [])) == len(st0.get("tool_provisioning", []))
         and [a["status"] for a in new_att] == ["cancelled"]),
    ]
    return out


def tc_request_refusals():
    p, scope = MAIN["p"], MAIN["scope"]
    expected = make_archives(p / "bad")
    (p / "outside.txt").write_text("not a target\n")
    files = [f"bad/{n}" for n in expected]
    objs = {f"I{i}": [f] for i, f in enumerate(files)}
    checks = [chk(k, v) for k, v in objs.items()]
    checks += [chk("F1", ["fixtures/misconfig"]), chk("F2", ["WebGoat/pom.xml"]),
               chk("F3", ["fixtures/req"], methods=(READ_M, TRIVY_M), selected=("semantic-review",),
                   minimum=("reading", "runtime")),
               chk("F4", ["bundle"]), chk("F5", ["bundle/nested.tar"]), chk("F6", ["images/hello-world.tar"]),
               chk("F7", ["WebGoat/Dockerfile_desktop"])]
    vid, _ = setup(p, scope, ["fixtures", "WebGoat/pom.xml", "bundle", "images/hello-world.tar",
                              "WebGoat/Dockerfile_desktop", *files], checks, context=["README.md"])
    MAIN["vid_ref"] = vid
    extend(p, vid)
    out = []
    base = {"schema": "ai-secure-code-toolkit/guard-tool/v1", "adapter": "trivy", "time_limit_seconds": 600}
    ok_check = tchk("F2", ["vuln"], "filesystem", ["WebGoat/pom.xml"])

    def refused(label, doc, codes, text=None):
        before = state_bytes(p, vid)
        with Window() as w:
            c, o, _, _ = tool(p, vid, [], raw=doc)
        ok = (c == 1 and code_of(o) in codes and state_bytes(p, vid) == before and w.procs == [] and w.silent()
              and bool(o.get("next_steps")) and (text is None or text.lower() in msg_of(o).lower()))
        out.append((f"{label}: refused {'/'.join(codes)}; nothing recorded, no attempt, not executed", ok))
        return o

    TRI = ("TOOL_REQUEST_INVALID",)
    refused("03a unknown top-level field", {**base, "checks": [ok_check], "include_ignored": False}, TRI)
    refused("03a free-form argument field", {**base, "checks": [ok_check], "args": ["--severity", "HIGH"]}, TRI)
    refused("03a severity filter on a check", {**base, "checks": [{**ok_check, "severity": ["HIGH"]}]}, TRI)
    refused("03a ignore file on a check", {**base, "checks": [{**ok_check, "ignorefile": ".trivyignore"}]}, TRI)
    refused("03a VEX source on a check", {**base, "checks": [{**ok_check, "vex": "vex.json"}]}, TRI)
    refused("03a file-skip pattern on a check", {**base, "checks": [{**ok_check, "skip_files": ["*.xml"]}]}, TRI)
    refused("03a license scanner (out of scope)", {**base, "checks": [{**ok_check, "scanners": ["license"]}]}, TRI,
            "license")
    refused("03a empty scanners", {**base, "checks": [{**ok_check, "scanners": []}]}, TRI)
    refused("03a scanners as a string", {**base, "checks": [{**ok_check, "scanners": "vuln"}]}, TRI)
    refused("03a unknown mode", {**base, "checks": [{**ok_check, "mode": "rootfs"}]}, TRI)
    refused("03a missing targets", {**base, "checks": [{k: v for k, v in ok_check.items() if k != "targets"}]}, TRI)
    refused("03a shell text in a target", {**base, "checks": [{**ok_check, "targets": ["WebGoat/pom.xml; rm -rf /"]}]},
            TRI + ("TARGETS_MISMATCH",))
    refused("03a duplicate check entries", {**base, "checks": [ok_check, ok_check]}, TRI)
    refused("03a wrong adapter name", {**base, "adapter": "Trivy", "checks": [ok_check]}, TRI + ("TOOL_UNKNOWN",))
    for label, tl in (("missing", None), ("zero", 0), ("negative", -5), ("above 1800", 1801), ("text", "600"),
                      ("fraction", 10.5), ("boolean", True)):
        doc = {**base, "checks": [ok_check]}
        if tl is None:
            doc.pop("time_limit_seconds")
        else:
            doc["time_limit_seconds"] = tl
        refused(f"03e time limit {label}", doc, TRI)
    TM = TRI + ("TARGETS_MISMATCH",)
    refused("03b targets not covering the check object", {**base, "checks": [
        tchk("F1", ["misconfig"], "filesystem", ["fixtures/misconfig/Dockerfile"])]}, TM)
    refused("03b context file as target", {**base, "checks": [tchk("F2", ["vuln"], "filesystem", ["README.md"])]}, TM)
    refused("03b unrelated path as target", {**base, "checks": [tchk("F2", ["vuln"], "filesystem", ["outside.txt"])]},
            TM)
    refused("03c image_archive with secret scanner", {**base, "checks": [
        tchk("F6", ["vuln", "secret"], "image_archive", ["images/hello-world.tar"])]}, TRI)
    refused("03c image_archive with misconfig scanner", {**base, "checks": [
        tchk("F6", ["misconfig"], "image_archive", ["images/hello-world.tar"])]}, TRI)
    refused("03c image_archive with a folder target", {**base, "checks": [
        tchk("F4", ["vuln"], "image_archive", ["bundle"])]}, TRI + ("IMAGE_ARCHIVE_INVALID",))
    for ref in ("redis:6-alpine", "docker.io/library/redis:6-alpine", "sha256:" + "a" * 64,
                "/var/run/docker.sock", "https://example.org/app.tar", "oci-archive:images/hello-world.tar"):
        refused(f"03c image reference {ref!r} as target", {**base, "checks": [
            tchk("F6", ["vuln"], "image_archive", [ref])]}, TM + ("IMAGE_ARCHIVE_INVALID",))
    refused("03i .tar only inside a declared folder target is not an image archive", {**base, "checks": [
        tchk("F5", ["vuln"], "image_archive", ["bundle/nested.tar"])]}, TRI + ("IMAGE_ARCHIVE_INVALID",))
    for i, (name, violation) in enumerate(expected.items()):
        f = f"bad/{name}"
        req = {**base, "checks": [tchk(f"I{i}", ["vuln"], "image_archive", [f])]}
        if violation is None:
            continue
        if violation == "TOO_LARGE":
            o = refused("03g archive larger than 8 GiB", req, ("IMAGE_ARCHIVE_TOO_LARGE",))
            out.append(("03g refusal names the size and the 8 GiB maximum",
                        str(8 * 1024 ** 3 + 1) in msg_of(o) and "8 GiB" in msg_of(o)))
        else:
            label = "03c pure OCI layout" if name == "pure-oci.tar" else f"03h {name}"
            refused(f"{label} (violation: {violation})", req, ("IMAGE_ARCHIVE_INVALID",), violation)
    D = [{"path": "WebGoat/Dockerfile_desktop", "type": "dockerfile"}]
    refused("03d override for a path outside the check object", {**base, "checks": [
        tchk("F1", ["misconfig"], "filesystem", ["fixtures/misconfig"], D)]}, TRI)
    refused("03d override without the misconfig scanner", {**base, "checks": [
        tchk("F7", ["secret"], "filesystem", ["WebGoat/Dockerfile_desktop"], D)]}, TRI)
    for t in ("compose", "docker-compose", "yaml"):
        refused(f"03d unsupported configuration type {t!r}", {**base, "checks": [
            tchk("F7", ["misconfig"], "filesystem", ["WebGoat/Dockerfile_desktop"],
                 [{"path": "WebGoat/Dockerfile_desktop", "type": t}])]}, TRI)
    refused("03d duplicate override for one path", {**base, "checks": [
        tchk("F7", ["misconfig"], "filesystem", ["WebGoat/Dockerfile_desktop"], D + D)]}, TRI)
    # 03d: every misconfiguration type of the verified tool version is an accepted override type
    accepted, ran = {}, {}
    for t in sorted(V0761_TYPES):
        doc = {**base, "checks": [tchk("F7", ["misconfig"], "filesystem", ["WebGoat/Dockerfile_desktop"],
                                       [{"path": "WebGoat/Dockerfile_desktop", "type": t}])]}
        c, o, _, _ = tool(p, vid, [], raw=doc)
        accepted[t] = c == 0 or code_of(o) != "TOOL_REQUEST_INVALID"
        if c != 0:
            ran[t] = [(None, code_of(o), msg_of(o)[:300])]
        else:
            r = run_of(p, vid)["checks"]["F7"]
            ran[t] = [(pr["exit"], pr["status"], pr.get("messages")) for pr in r["processes"]] + [
                {"check_status": r["status"], "analysed": r["accounting"][0]["analysed"] if r["accounting"] else None,
                 "gaps": r["gaps"][:3]}]
    note("TC-D-10 override types", {"accepted": accepted, "process_exit_status_messages_analysed": ran})
    out.append(("03d every misconfiguration type supported by v0.76.1 (`trivy fs --help`: " +
                ", ".join(sorted(V0761_TYPES)) + ") is accepted as an override type",
                all(accepted.values())))
    out.append(("03d each of the 9 override types reached the real binary as --file-patterns <type>:<path> and the "
                "tool used it as that type (no unknown-type error; a FATAL, if any, comes from that type's own "
                "scanner parsing the Dockerfile, e.g. 'terraformplan-json scan error')", set(ran) == V0761_TYPES
                and all("unknown" not in json.dumps(v[0][2]).lower()
                        and ("FATAL" not in json.dumps(v[0][2]) or f"{t} scan error" in json.dumps(v[0][2]))
                        for t, v in ran.items())))
    out.append(("05b/05f content that does not match the override type is never a successful method: only the "
                "dockerfile override analysed the file; parser errors recorded as failed methods",
                all((v[-1]["analysed"] == ["WebGoat/Dockerfile_desktop"]) == (t == "dockerfile") for t, v in ran.items())
                and all(v[-1]["check_status"] in ("completed", "completed_with_errors", "failed") for v in ran.values())
                and all(v[-1]["check_status"] != "completed" or not v[-1]["gaps"] or t != "dockerfile"
                        for t, v in ran.items())))
    out.append(("03d dockerfile override analysed the non-default-named file (effect)",
                (ran.get("dockerfile") or [None, {}])[-1].get("analysed") == ["WebGoat/Dockerfile_desktop"]))
    # 03f / 06a: verification state and plan conditions
    refused("03f/06a check not planned", {**base, "checks": [tchk("C99", ["vuln"], "filesystem",
                                                                   ["WebGoat/pom.xml"])]}, ("METHOD_NOT_PLANNED",))
    refused("03f/06a planned trivy method not selected", {**base, "checks": [
        tchk("F3", ["vuln"], "filesystem", ["fixtures/req"])]}, ("METHOD_NOT_SELECTED",))
    v_np, _ = open_v(p, scope, ["fixtures/req"])
    before = state_bytes(p, v_np)
    c, o, _, _ = tool(p, v_np, [tchk("F2", ["vuln"], "filesystem", ["fixtures/req"])])
    out.append(("03f/06a verification without a plan: PLAN_REQUIRED, nothing recorded",
                c == 1 and code_of(o) == "PLAN_REQUIRED" and state_bytes(p, v_np) == before))
    c, o, _, _ = g(p, "plan", v_np, {"schema": "ai-secure-code-toolkit/guard-plan/v1", "checks": [
        chk("X1", ["fixtures/req"], methods=({"name": "trivy", "kind": "reading", "required": True},))],
        "not_applicable": [{"rule": R2, "reason": "x"}]})
    out.append(("06a plan refuses a trivy method that is not of kind runtime", c == 1
                and "kind runtime" in msg_of(o)))
    c, o, _, _ = tool(p, MAIN["vid"], [tchk("C8", ["vuln"], "filesystem", ["fixtures/req"])])
    out.append(("03f concluded verification: RUN_FINISHED, nothing executed", c == 1 and code_of(o) == "RUN_FINISHED"))
    return out


def tc_components_missing():
    p = new_project("missing ü")
    aws, _ = fake_secrets()
    (p / "fx" / "secret").mkdir(parents=True)
    (p / "fx" / "secret" / "app.env").write_text(f"AWS_ACCESS_KEY_ID={aws}\n")
    (p / "fx" / "req").mkdir()
    (p / "fx" / "req" / "requirements.txt").write_text("requests==2.19.0\n")
    shutil.copytree(FIXTURES / "misconfig", p / "fx" / "misconfig")
    (p / "images").mkdir()
    shutil.copy(IMAGES / "redis-6-alpine.tar", p / "images" / "redis.tar")
    assert register(p)[0] == 0
    scope = save_scope(p)
    objs = {"M1": ["fx/req"], "M2": ["fx/secret"], "M3": ["fx/misconfig/Dockerfile"], "M4": ["images/redis.tar"]}
    vid, _ = setup(p, scope, ["fx", "images/redis.tar"], [chk(k, v) for k, v in objs.items()])
    extend(p, vid)
    with Window() as w:
        c, o, _, _ = tool(p, vid, [tchk("M1", ["vuln"], "filesystem", ["fx/req"]),
                                   tchk("M2", ["secret"], "filesystem", ["fx/secret"]),
                                   tchk("M3", ["misconfig"], "filesystem", ["fx/misconfig/Dockerfile"])])
    e = run_of(p, vid)
    chk_ = e["checks"]
    scanners_run = sorted(x["argv"][x["argv"].index("--scanners") + 1] for x in w.procs)
    note("TC-D-11 a", {k: {"status": v["status"], "gaps": v["gaps"][:2]} for k, v in chk_.items()})
    out = [
        ("02e/01d no vulnerability DB: the vuln check fails at pre-check naming the component, its state and the "
         "Maintainer provisioning step under a tool_update grant", chk_["M1"]["status"] == "precheck_failed"
         and "vulnerability_db missing" in gaps(e, "M1") and "tools provision" in gaps(e, "M1")
         and "tool_update" in gaps(e, "M1")),
        ("02e/05i no checks bundle: misconfig check failed naming the checks bundle and its provisioning step",
         chk_["M3"]["status"] == "precheck_failed" and "checks_bundle missing" in gaps(e, "M3")
         and "--component checks_bundle" in gaps(e, "M3")),
        ("02e the secret check of the same request runs unaffected (ok, finding recorded)",
         chk_["M2"]["method_status"] == "ok" and scanners_run == ["secret"]
         and [f for f in state(p, vid)["findings"] if f["check"] == "M2"]),
        ("01e/02e nothing downloaded or installed automatically (no registry contact, no frames, no cache)",
         w.silent() and not (p / CACHE / "components.json").exists()),
    ]
    mirror_grants(p, vid, ["vulnerability_db"])
    assert provision(p, vid, ["vulnerability_db"])[0] == 0
    with Window() as w:
        c, o, _, _ = tool(p, vid, [tchk("M4", ["vuln"], "image_archive", ["images/redis.tar"]),
                                   tchk("M1", ["vuln"], "filesystem", ["fx/req"]),
                                   tchk("M3", ["misconfig"], "filesystem", ["fx/misconfig/Dockerfile"])])
    e = run_of(p, vid)
    note("TC-D-11 b", {k: {"status": v["status"], "gaps": v["gaps"][:2]} for k, v in e["checks"].items()})
    out += [
        ("02e image_archive without the Java DB: that check fails naming java_db; the filesystem vuln check of "
         "the same request runs", e["checks"]["M4"]["status"] == "precheck_failed"
         and "java_db missing" in gaps(e, "M4") and e["checks"]["M1"]["status"] in ("completed",
                                                                                 "completed_with_errors")
         and len(by_scanner(w.procs, "vuln")) == 1),
        ("05i misconfig without the provisioned checks bundle is never complete evidence: failed, next step "
         "'provision the checks bundle'", e["checks"]["M3"]["method_status"] == "failed"
         and "checks_bundle" in gaps(e, "M3")),
        ("02d scans stay offline", w.silent()),
    ]
    return out


def tc_precheck_failures():
    p = new_project("precheck ü")
    (p / "src").mkdir()
    (p / "src" / "requirements.txt").write_text("six==1.17.0\n")
    (p / "src" / "notes.txt").write_text("plain\n")
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["src/requirements.txt", "src/notes.txt"],
                   [chk("P1", ["src/requirements.txt"]), chk("P2", ["src/notes.txt"])])
    extend(p, vid)
    req = [tchk("P1", ["secret"], "filesystem", ["src/requirements.txt"]),
           tchk("P2", ["secret"], "filesystem", ["src/notes.txt"])]
    with Window() as w1:
        c1, o1, _, _ = tool(p, vid, req)
    e1 = run_of(p, vid)
    nothing_after_1 = not (p / RECORD).exists() and not (p / CACHE / "components.json").exists()
    copy = Path(tempfile.mkdtemp(prefix="binc-", dir=WORK)) / "trivy"
    shutil.copy(TRIVY, copy)
    assert register(p, str(copy))[0] == 0
    with open(copy, "ab") as f:
        f.write(b"\0")
    with Window() as w2:
        c2, o2, _, _ = tool(p, vid, req)
    e2 = run_of(p, vid)
    st = status(p)["trivy"]
    shutil.copy(TRIVY, copy)
    (p / "src" / "notes.txt").write_text("changed after open\n")
    with Window() as w3:
        c3, o3, _, _ = tool(p, vid, [tchk("P2", ["secret"], "filesystem", ["src/notes.txt"])])
    e3 = run_of(p, vid)
    note("TC-D-12", {"unregistered": e1["gap"], "run_result": o1, "changed": e2["gap"], "status": st,
                     "target_changed": e3["checks"]["P2"]})
    return [
        ("01d unregistered tool: accepted request recorded, every requested check failed at pre-check with the "
         "reason; nothing executed", c1 == 0 and all(v["status"] == "precheck_failed" for v in e1["checks"].values())
         and e1["gap"]["code"] == "TOOL_NOT_REGISTERED" and w1.procs == [] and w1.silent()),
        ("01e next step names the Maintainer registration; nothing registered or downloaded automatically",
         "tools register" in (json.dumps(e1) + json.dumps(o1)).lower() and nothing_after_1),
        ("01d binary replaced after registration: digest of the private snapshot differs -> not executed, "
         "failed evidence for every check", c2 == 0 and e2["gap"]["code"] == "TOOL_DIGEST_MISMATCH"
         and all(v["status"] == "precheck_failed" for v in e2["checks"].values()) and w2.procs == []),
        ("08a status reports the failing digest pre-check with the reason and a next step", st["check"] != "ok"
         and "digest changed" in st["check"] and "register" in st.get("next_step", "").lower()),
        ("04b target changed since the verification was opened: not scanned, failed method naming the change",
         c3 == 0 and e3["checks"]["P2"]["method_status"] == "failed" and "changed" in gaps(e3, "P2").lower()
         and w3.procs == []),
        ("01e a successful pre-check/run is never presented as a security pass",
         "pass" not in json.dumps([v["method_status"] for v in e1["checks"].values()])),
    ]


def tc_outdated_db():
    p = new_project("old ü")
    (p / "app").mkdir()
    (p / "app" / "requirements.txt").write_text("requests==2.19.0\n")
    assert register(p)[0] == 0
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["app/requirements.txt"], [chk("C1", ["app/requirements.txt"])])
    mirror_grants(p, vid, ["vulnerability_db"])
    registry_mode(variant={"vulnerability_db": "old"})
    c0, o0, _, _ = provision(p, vid, ["vulnerability_db"])
    registry_mode()
    with Window() as w:
        c, o, _, _ = tool(p, vid, [tchk("C1", ["vuln"], "filesystem", ["app/requirements.txt"])])
    e = run_of(p, vid)
    vdb = e["components"]["vulnerability_db"]
    st = status(p)["trivy"]["components"]["vulnerability_db"]
    f = [x for x in state(p, vid)["findings"] if x["check"] == "C1"]
    note("TC-D-13", {"metadata": vdb.get("metadata"), "age": vdb.get("age"), "status_age": st.get("age"),
                     "findings": len(f), "check": e["checks"]["C1"]["status"]})
    return [
        ("04c provisioned DB outdated by its own metadata (NextUpdate 2019): provisioning accepted as is",
         c0 == 0 and vdb["metadata"]["NextUpdate"].startswith("2019-")),
        ("04c the scan still runs offline on it, no update attempt (zero frames, no registry request)",
         c == 0 and e["checks"]["C1"]["status"] in ("completed", "completed_with_errors") and w.silent()
         and len(f) > 0),
        ("02f/04c age reported (> 7 years) in evidence and status; no threshold or stale verdict applied",
         vdb["age_seconds"] > 7 * 365 * 86400 and st["age_seconds"] > 7 * 365 * 86400
         and "stale" not in json.dumps(e).lower()),
    ]


def _flip_same_size(path: Path, offset: int) -> None:
    fd = os.open(path, os.O_RDWR)
    try:
        b = os.pread(fd, 1, offset)
        os.pwrite(fd, bytes([b[0] ^ 0x20 if chr(b[0]).isalpha() else b[0] ^ 0x01]), offset)
    finally:
        os.close(fd)


def tc_rehash_invalidation():
    p, scope = MAIN["p"], MAIN["scope"]
    vid, _ = setup(p, scope, ["WebGoat/Dockerfile", "fixtures/req"],
                   [chk("R1c", ["WebGoat/Dockerfile"]), chk("R2c", ["fixtures/req"])])
    extend(p, vid)
    mirror_grants(p, vid)
    ptr = json.loads((p / CACHE / "components.json").read_text())["components"]
    gen_cb = p / CACHE / "gen" / "checks_bundle" / ptr["checks_bundle"]["generation"]
    rego = sorted((gen_cb / "policy" / "content").rglob("*.rego"), key=lambda x: -x.stat().st_size)[0]
    text = rego.read_bytes()
    pos = text.index(b"# ") + 2  # a comment letter: same size, still valid Rego
    _flip_same_size(rego, pos)
    pre = status(p)["trivy"]["components"]["checks_bundle"]["state"]
    with Window() as w1:
        c1, o1, _, _ = tool(p, vid, [tchk("R1c", ["misconfig"], "filesystem", ["WebGoat/Dockerfile"])])
    e1 = run_of(p, vid)
    st1 = status(p)["trivy"]["components"]["checks_bundle"]
    c2, o2, _, _ = tool(p, vid, [tchk("R1c", ["misconfig"], "filesystem", ["WebGoat/Dockerfile"])])
    e2 = run_of(p, vid)
    cp, op_, _, _ = provision(p, vid, ["checks_bundle"])
    c3, o3, _, _ = tool(p, vid, [tchk("R1c", ["misconfig"], "filesystem", ["WebGoat/Dockerfile"])])
    e3 = run_of(p, vid)
    # the tool itself reports an invalid vulnerability DB (content corrupted, size unchanged)
    gen_db = p / CACHE / "gen" / "vulnerability_db" / ptr["vulnerability_db"]["generation"] / "db" / "trivy.db"
    fd = os.open(gen_db, os.O_RDWR)
    os.pwrite(fd, b"\0" * 16384, 0)  # both bolt meta pages
    os.close(fd)
    with Window() as w4:
        c4, o4, _, _ = tool(p, vid, [tchk("R2c", ["vuln"], "filesystem", ["fixtures/req"])])
    e4 = run_of(p, vid)
    st4 = status(p)["trivy"]["components"]["vulnerability_db"]
    msgs = json.dumps(e4["checks"]["R2c"]["processes"])
    cpv, opv, _, _ = provision(p, vid, ["vulnerability_db"])
    st5 = status(p)["trivy"]["components"]["vulnerability_db"]
    note("TC-D-14", {"pre": pre, "rehash1": e1["rehash"], "gaps1": e1["checks"]["R1c"]["gaps"][:3],
                     "status1": st1, "gaps2": e2["checks"]["R1c"]["gaps"][:2], "rehash3": e3["rehash"],
                     "gaps4": e4["checks"]["R2c"]["gaps"][:3], "proc4": e4["checks"]["R2c"]["processes"],
                     "status4": st4.get("state"), "reason4": st4.get("reason")})
    return [
        ("02g change keeping size passes the stat-level pre-check; the scan reads the component in place",
         pre == "present" and c1 == 0 and e1["checks"]["R1c"]["processes"]),
        ("02g post-scan re-hash detects the change: the check that used it is a failed method naming the change",
         e1["rehash"].get("checks_bundle", "unchanged") != "unchanged"
         and e1["checks"]["R1c"]["method_status"] == "failed" and "changed since provisioning" in gaps(e1, "R1c")),
        ("02g component marked invalid: status reports it unreadable with the reason until re-provisioned",
         st1["state"] == "unreadable" and "invalid" in st1.get("reason", "")),
        ("02g later pre-check reports the component unreadable (TRIVY_COMPONENT_UNREADABLE), not run",
         e2["checks"]["R1c"]["status"] == "precheck_failed" and "unreadable" in gaps(e2, "R1c")),
        ("02g re-provisioning restores a present component; the next scan is complete again",
         cp == 0 and e3["checks"]["R1c"]["method_status"] == "ok" and set(e3["rehash"].values()) == {"unchanged"}),
        ("02e the tool reports an invalid database: failed method naming the component, state and re-provision "
         "step; component marked invalid", c4 == 0 and e4["checks"]["R2c"]["method_status"] == "failed"
         and "vulnerability_db" in gaps(e4, "R2c") and "provision" in gaps(e4, "R2c")
         and ("invalid" in msgs.lower() or "failed to open" in msgs.lower()) and st4["state"] == "unreadable"),
        ("02g/02d even failing scans stay offline", w1.silent() and w4.silent()),
        ("02e re-provisioning the database makes it present again", cpv == 0 and st5["state"] == "present"),
    ]


def _k8s(folder: Path, n: int = 2000) -> None:
    """2,000 Kubernetes manifests: a misconfiguration scan of about 20 s with the real binary (FF probe)."""
    folder.mkdir(parents=True, exist_ok=True)
    body = (FIXTURES / "misconfig" / "deployment.yaml").read_text()
    for i in range(n):
        (folder / f"d{i}.yaml").write_text(body)


def tc_timeouts_and_cancel():
    p = new_project("time ü")
    _k8s(p / "big")
    (p / "toolarge").mkdir()
    with open(p / "toolarge" / "blob.bin", "wb") as f:
        f.write(os.urandom(1 << 20) * 600)
    (p / "small.txt").write_text("hello\n")
    assert register(p)[0] == 0
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["big", "toolarge", "small.txt"],
                   [chk("T1", ["big"]), chk("T2", ["toolarge"]), chk("T3", ["small.txt"])])
    extend(p, vid)
    mirror_grants(p, vid, ["checks_bundle"])
    assert provision(p, vid, ["checks_bundle"])[0] == 0
    with Window() as w1:
        c1, o1, _, _ = tool(p, vid, [tchk("T1", ["misconfig"], "filesystem", ["big"])], time_limit=5)
    e1 = run_of(p, vid)
    left1 = PROCS.alive()
    c2, o2, _, _ = tool(p, vid, [tchk("T2", ["secret"], "filesystem", ["toolarge"])])
    e2 = run_of(p, vid)
    v_cap, _ = open_v(p, scope, ["small.txt"], budget={"minutes": 1})
    plan(p, v_cap, [chk("T3", ["small.txt"])])
    c3, o3, _, _ = tool(p, v_cap, [tchk("T3", ["secret"], "filesystem", ["small.txt"])], time_limit=600)
    e3 = run_of(p, v_cap)
    n0 = len(PROCS.order)
    runs_before = len(state(p, vid)["adapter_runs"])
    runner = tool_bg(p, vid, [tchk("T1", ["misconfig"], "filesystem", ["big"])], time_limit=600)
    started = _wait(lambda: any(PROCS.seen[x]["alive"] for x in PROCS.order[n0:]), timeout=60)
    time.sleep(1)
    cc, co, _, _ = g(p, "cancel", vid, None, "--reason", "user stopped the scan")
    rc, ro, _, _ = finish(runner)
    st = state(p, vid)
    term = (co or {}).get("data", {}).get("cancellation", {}).get("tool_termination", {})
    note("TC-D-15", {"timeout": {"status": e1["checks"]["T1"]["status"], "procs": e1["checks"]["T1"]["processes"],
                                 "gaps": e1["checks"]["T1"]["gaps"][:3], "window": w1.summary()},
                     "stage_limit": e2["checks"]["T2"], "cap": {k: e3.get(k) for k in ("time_limit",
                                                                                       "requested_time_limit",
                                                                                       "time_limit_capped")},
                     "cancel": co, "tool_result": ro})
    return [
        ("04d adapter time limit reached: status timed_out, failed method, tool and children stopped",
         c1 == 0 and e1["checks"]["T1"]["status"] == "timed_out" and e1["checks"]["T1"]["method_status"] == "failed"
         and left1 == [] and all(not x["alive"] for x in w1.procs)),
        ("04d staging and disposable folders removed after the timeout; offline", staging_empty(p) and w1.silent()),
        ("03g non-archive staging limit unchanged: a 600 MB folder target fails staging (not executed)",
         e2["checks"]["T2"]["status"] == "precheck_failed" and "STAGE_TOO_LARGE" in json.dumps(e2)),
        ("03e accepted time limit capped by the verification's remaining budget",
         c3 == 0 and e3["time_limit"] <= 60 and e3.get("time_limit_capped") is True),
        ("04e cancel during a scan: the owning process stops Trivy (termination confirmed), the run reports "
         "RUN_CANCELLED, no new evidence, staging removed", started and cc == 0 and term.get("tool") == "confirmed"
         and code_of(ro) == "RUN_CANCELLED" and len(st["adapter_runs"]) == runs_before and PROCS.alive() == []
         and staging_empty(p)),
    ]


def tc_removal():
    p, scope = MAIN["p"], MAIN["scope"]
    _k8s(p / "busy")
    vid, _ = setup(p, scope, ["busy", "fixtures/req"], [chk("B1", ["busy"]), chk("B2", ["fixtures/req"])])
    extend(p, vid)
    mirror_grants(p, vid)
    private_state = {x: x.read_bytes() for x in (p / GUARD).rglob("state.json")}
    record = (p / RECORD).read_bytes()
    original = tree(p, (".x-ipe", "x-ipe-docs", "busy"))
    pointer0 = (p / CACHE / "components.json").read_bytes()
    out = []
    trust = Path.home() / ".config" / "ai-secure-code-toolkit"
    aside = trust.with_name("ai-secure-code-toolkit.aside")
    trust.rename(aside)
    try:
        c, o, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--all", "--json")
    finally:
        aside.rename(trust)
    out.append(("02h without Maintainer authorization: refused, nothing removed",
                c == 1 and code_of(o) == "NOT_AUTHORIZED" and (p / CACHE / "components.json").read_bytes() == pointer0))
    c, o, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--component", "foo_db",
                    "--json")
    out.append(("02h unknown component: refused, nothing removed", c == 1 and code_of(o) == "PROVISION_REQUEST_INVALID"
                and (p / CACHE / "components.json").read_bytes() == pointer0))
    n0 = len(PROCS.order)
    runner = tool_bg(p, vid, [tchk("B1", ["misconfig"], "filesystem", ["busy"])], time_limit=600)
    _wait(lambda: any(PROCS.seen[x]["alive"] for x in PROCS.order[n0:]), timeout=60)
    c, o, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--component", "java_db",
                    "--json")
    finish(runner)
    out.append(("02h while a scan of the project runs: refused TRIVY_CACHE_BUSY, nothing removed",
                c == 1 and code_of(o) == "TRIVY_CACHE_BUSY" and (p / CACHE / "components.json").read_bytes() == pointer0))
    registry_mode(slow_bps=2_000_000)
    n0 = len(PROCS.order)
    prov = provision_bg(p, vid, ["vulnerability_db"], time_limit=60)
    _wait(lambda: any(PROCS.seen[x]["alive"] for x in PROCS.order[n0:]), timeout=60)
    c, o, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--component", "java_db",
                    "--json")
    registry_mode()
    finish(prov)
    out.append(("02h while a provisioning of the project runs: refused TRIVY_CACHE_BUSY, nothing removed",
                c == 1 and code_of(o) == "TRIVY_CACHE_BUSY"
                and status(p)["trivy"]["components"]["java_db"]["state"] == "present"))
    private_state = {x: x.read_bytes() for x in (p / GUARD).rglob("state.json")}
    before_disk = status(p)["trivy"]["components"]["java_db"]["disk_bytes"]
    with Window() as w:
        c, o, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--component",
                        "java_db", "--json")
    st = status(p)["trivy"]["components"]
    removed = (o or {}).get("data", {}).get("removed", [])
    out += [
        ("02h remove one component: listed with bytes freed; status reports it missing; others present",
         c == 0 and [r["component"] for r in removed] == ["java_db"] and removed[0]["freed_disk_bytes"] == before_disk
         and st["java_db"]["state"] == "missing" and st["vulnerability_db"]["state"] == "present"),
        ("02h no project file, registration record or verification record changed; nothing executed or "
         "downloaded", tree(p, (".x-ipe", "x-ipe-docs", "busy")) == original and (p / RECORD).read_bytes() == record
         and all(x.read_bytes() == b for x, b in private_state.items()) and w.procs == [] and w.silent()),
    ]
    c, o, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--all", "--json")
    st = status(p)["trivy"]
    out.append(("02h remove all: every component missing, total bytes freed reported, cache generations gone",
                c == 0 and all(v["state"] == "missing" for v in st["components"].values())
                and o["data"].get("freed_disk_bytes_total", 0) > 0
                and not any((p / CACHE / "gen").rglob("*.db")) and st["cache_disk_bytes_total"] == 0))
    note("TC-D-16", {"removed_all": o["data"]})
    return out


def _norm(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").lower().split())


def tc_skill_and_records():
    skill = _norm(GUARD_SKILL / "SKILL.md")
    records = (GUARD_SKILL / "references" / "guard-records.md").read_text(encoding="utf-8")
    readme = (DOCS / "tool-validation" / "README.md").read_text(encoding="utf-8")
    driver = DOCS / "tool-validation" / "validate.py"
    digests_src = (SCRIPTS / "src" / "x_ipe_secure_code" / "adapters" / "digests.py").read_text(encoding="utf-8")
    trivy_block = digests_src[digests_src.index("TRIVY: dict"):]
    entries = re.findall(r'"sha256:([0-9a-f]{64})":\s*ToolBuild\(([^)]*)\)', trivy_block)
    rows = {d: [x.strip().strip('"') for x in args.split(",")] for d, args in entries}
    phrases = ["never run trivy by default", "cheapest sufficient method",
               "dependency vulnerabilities, misconfigurations (dockerfile, kubernetes, iac) and secrets in "
               "`filesystem` mode", "vulnerabilities only for `docker save` image archives",
               "no compose misconfiguration analysis", "no registry or daemon images", "no license scanning",
               "list only files the chosen scanner analyses as a check's object",
               "use another method (e.g. semantic review) for compose files",
               "judge and record whether the reported database age is sufficient",
               "ask the user for `tool_update` grants covering every known host",
               "ask the maintainer to provision it", "never proceed without it"]
    missing = [x for x in phrases if x not in skill]
    note("TC-D-19", {"missing_phrases": missing, "digest_rows": rows})
    return [
        ("06d Guard SKILL.md step 5b covers scope, object listing, compose, DB-age judgement, grants and "
         "Maintainer provisioning, never by default", missing == []),
        ("06d guard-records documents the Trivy request, image-archive rules, override types and provisioning "
         "grants per known host", "## Trivy run" in records and '"adapter": "trivy"' in records
         and "image_archive" in records and BLOB in records),
        ("07a tool-level validation dated before the implementation with version, archive digests (release "
         "metadata + checksums), binary digests, signature state, environment, DB sources/sizes/metadata, "
         "commands, results on both samples, fixtures and image archives, timings, known issues",
         "Date: 2026-10-22" in readme and "v0.76.1" in readme and all(d in readme for d in ARCHIVES.values())
         and OFFICIAL_ARM[7:] in readme and OFFICIAL_X86[7:] in readme and "not verified" in readme
         and "## Component Provisioning" in readme and "## Observed Results" in readme
         and "shanghai-marathon-registration" in readme and "WebGoat" in readme and "redis:6-alpine" in readme
         and "## Known Issues" in readme),
        ("07a all phases bound to one committed driver revision whose SHA-256 is the driver file's",
         "All phases ran with this one committed driver revision" in readme
         and sha_file(driver) in readme),
        ("07b exactly two Trivy table entries (linux aarch64 validated, linux x86 not validated), libc None, "
         "asset = the official archive recorded in the validation",
         set(rows) == {OFFICIAL_ARM[7:], OFFICIAL_X86[7:]}
         and rows[OFFICIAL_ARM[7:]][2:] == ["linux", "aarch64", "None", "trivy_0.76.1_Linux-ARM64.tar.gz", "True"]
         and rows[OFFICIAL_X86[7:]][2:] == ["linux", "x86", "None", "trivy_0.76.1_Linux-64bit.tar.gz", "False"]),
        ("07b archive digests in the toolkit equal the validation record; AC-28 stated pending in FEATURE-003-C",
         all(d in digests_src for d in ARCHIVES.values()) and "FEATURE-003-C" in readme),
    ]


def prepare_handoff() -> None:
    """A Linux-registered project with an open, planned verification for the macOS pre-check (AC-002D-01c)."""
    HANDOFF.mkdir(parents=True, exist_ok=True)
    p = new_project("handoff ü", where=Path(tempfile.mkdtemp(prefix="h-", dir=HANDOFF)))
    (p / "app").mkdir()
    (p / "app" / "requirements.txt").write_text("six==1.17.0\n")
    (p / "app" / "notes.txt").write_text("plain\n")
    assert register(p)[0] == 0
    scope = save_scope(p)
    vid, _ = setup(p, scope, ["app/requirements.txt", "app/notes.txt"],
                   [chk("H1", ["app/requirements.txt"]), chk("H2", ["app/notes.txt"])])
    (HANDOFF / "handoff.json").write_text(json.dumps({"project": str(p.relative_to(HANDOFF)), "vid": vid}))


# ================================================================ host case (macOS, never-authorized User)
def tc_host_platform():
    info = json.loads((HANDOFF / "handoff.json").read_text())
    p = HANDOFF / info["project"]
    vid = info["vid"]
    q = Path(tempfile.mkdtemp(prefix="fat-2d-host-", dir=WORK)) / "host ü"
    q.mkdir()
    assert sc("init", "--project", str(q), "--env", "github-copilot", "--json")[0] == 0
    marker = q.parent / "executed"
    fake = q.parent / "trivy"
    fake.write_text(f"#!/bin/sh\ntouch '{marker}'\necho 0.76.1\n")
    fake.chmod(0o755)
    c1, o1, _, _ = sc("tools", "register", "--project", str(q), "--tool", "trivy", "--path", str(fake), "--json")
    before = state_bytes(p, vid)
    c2, o2, _, _ = sc("tools", "provision", "--project", str(p), "--tool", "trivy", "--run", vid, "--component",
                      "vulnerability_db", "--json")
    after_prov = state_bytes(p, vid)
    c3, o3, _, _ = tool(p, vid, [tchk("H1", ["vuln"], "filesystem", ["app/requirements.txt"]),
                                 tchk("H2", ["secret"], "filesystem", ["app/notes.txt"])])
    st = state(p, vid)
    e = st["adapter_runs"][-1] if st.get("adapter_runs") else {}
    evs = [x for x in st["evidence"] if x["method"] == "trivy"]
    t = status(p)
    c4, o4, _, _ = sc("tools", "remove-components", "--project", str(p), "--tool", "trivy", "--all", "--json")
    note("TC-H-01", {"register": o1, "provision": o2, "run_gap": e.get("gap"), "status_trivy": t["trivy"],
                     "remove": code_of(o4)})
    return [
        ("01c macOS: Trivy registration refused before anything is executed, with the platform gap and a next "
         "step; nothing recorded", c1 == 1 and code_of(o1) == "ADAPTER_PLATFORM_UNSUPPORTED"
         and PLATFORM_GAP in msg_of(o1) and bool(o1.get("next_steps")) and not marker.exists()
         and not (q / RECORD).exists()),
        ("01c macOS: provisioning refused with the platform gap before anything; nothing recorded",
         c2 == 1 and code_of(o2) == "ADAPTER_PLATFORM_UNSUPPORTED" and before == after_prov),
        ("01c macOS: an otherwise valid run request is accepted and its pre-check fails with the platform gap; "
         "nothing executed; failed trivy method recorded for each requested check",
         c3 == 0 and e.get("gap", {}).get("code") == "ADAPTER_PLATFORM_UNSUPPORTED"
         and PLATFORM_GAP in e["gap"]["reason"] and all(v["status"] == "precheck_failed" for v in e["checks"].values())
         and sorted(x["checks"][0] for x in evs) == ["H1", "H2"] and all(x["method_status"] == "failed" for x in evs)),
        ("08a macOS status: Trivy provided, execution not supported on this platform, components read without "
         "executing", t["trivy"]["state"] == "provided"
         and t["trivy"]["execution"] == "not supported on this platform in this version"
         and set(t["trivy"]["components"]) == set(COMPONENTS)),
        ("08b Strix still reported as not provided", t["strix"]["state"] == "adapter not provided by this toolkit version"),
        ("02h removal works without executing anything but needs the Maintainer (never-authorized user refused)",
         c4 == 1 and code_of(o4) == "NOT_AUTHORIZED"),
    ]


# ================================================================ main
def main() -> int:
    global SNIFF, PROCS
    mode = sys.argv[1] if len(sys.argv) > 1 else "host"
    if mode == "container":
        if os.environ.get("FAT_ISOLATED") != "1":
            print("refusing: container mode writes the trust store; use a disposable HOME and FAT_ISOLATED=1")
            return 2
        ca = Path(os.environ.get("CA", "/certs/ca.pem"))
        with open("/etc/ssl/certs/ca-certificates.crt", "ab") as f:  # disposable container only
            f.write(b"\n" + ca.read_bytes())
        shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
        WORK.mkdir(parents=True, exist_ok=True)
        registry_mode()
        SNIFF, PROCS = Sniffer(), ProcWatch()
        SNIFF.start()
        PROCS.start()
        time.sleep(1)
        only = set(os.environ.get("FAT_ONLY", "").split(",")) - {""}
        plan_ = [
            ("TC-D-00", ["AC-002D-02d"], tc_controls),
            ("TC-D-01", ["AC-002D-01a", "AC-002D-01b", "AC-002D-01e", "AC-002D-01f", "AC-002D-08a"], tc_registration),
            ("TC-D-02", ["AC-002D-02a", "AC-002D-01e"], tc_provision_refusals),
            ("TC-D-03", ["AC-002D-02b", "AC-002D-02c", "AC-002D-08a"], tc_provision_mirror),
            ("TC-D-06", ["AC-002D-02d", "AC-002D-02f", "AC-002D-02g", "AC-002D-04a", "AC-002D-05a", "AC-002D-05b",
                         "AC-002D-05d", "AC-002D-05e", "AC-002D-05f", "AC-002D-06a", "AC-002D-06c", "AC-002D-03d"],
             tc_scans_mvp),
            ("TC-D-07", ["AC-002D-05b", "AC-002D-05c", "AC-002D-05d", "AC-002D-05f", "AC-002D-05g", "AC-002D-04a",
                         "AC-002D-03i"],
             tc_secrets_and_config_files),
            ("TC-D-08", ["AC-002D-03d", "AC-002D-05a", "AC-002D-05h", "AC-002D-05i"], tc_misconfig_fixtures),
            ("TC-D-09", ["AC-002D-03c", "AC-002D-03g", "AC-002D-03h", "AC-002D-05a", "AC-002D-02g", "AC-002D-04a"],
             tc_image_archives),
            ("TC-D-17", ["AC-002D-08a", "AC-002D-08b", "AC-002D-08c", "AC-002D-02f"], tc_status_main),
            ("TC-D-18", ["AC-002D-05c", "AC-002D-05g", "AC-002D-06b", "AC-002D-06c", "AC-002D-02b", "AC-002D-02f",
                         "AC-002D-02g"], tc_report_and_masking),
            ("TC-D-04", ["AC-002D-02b"], tc_ghcr_known_hosts),
            ("TC-D-05", ["AC-002D-02b", "AC-002D-02c", "AC-002D-04e"], tc_provision_failures),
            ("TC-D-10", ["AC-002D-03a", "AC-002D-03b", "AC-002D-03c", "AC-002D-03d", "AC-002D-03e", "AC-002D-03f",
                         "AC-002D-03g", "AC-002D-03h", "AC-002D-03i", "AC-002D-06a"], tc_request_refusals),
            ("TC-D-11", ["AC-002D-02e", "AC-002D-01d", "AC-002D-01e", "AC-002D-05i"], tc_components_missing),
            ("TC-D-12", ["AC-002D-01d", "AC-002D-01e", "AC-002D-04b", "AC-002D-08a"], tc_precheck_failures),
            ("TC-D-13", ["AC-002D-04c", "AC-002D-02f"], tc_outdated_db),
            ("TC-D-14", ["AC-002D-02g", "AC-002D-02e"], tc_rehash_invalidation),
            ("TC-D-15", ["AC-002D-04d", "AC-002D-04e", "AC-002D-03e", "AC-002D-03g"], tc_timeouts_and_cancel),
            ("TC-D-16", ["AC-002D-02h"], tc_removal),
            ("TC-D-19", ["AC-002D-06d", "AC-002D-07a", "AC-002D-07b"], tc_skill_and_records),
        ]
        for tc, acs, fn in plan_:
            if not only or tc in only:
                case(tc, acs, fn)
        if not only or "handoff" in only:
            prepare_handoff()
    else:
        case("TC-H-01", ["AC-002D-01c", "AC-002D-08a", "AC-002D-08b"], tc_host_platform)
        case("TC-D-19", ["AC-002D-06d", "AC-002D-07a", "AC-002D-07b"], tc_skill_and_records)
    passed = sum(r["status"] == "Pass" for r in RESULTS)
    print(json.dumps({"summary": {"mode": mode, "platform": sys.platform, "python": sys.version.split()[0],
                                  "passed": passed, "total": len(RESULTS),
                                  "checks": sum(len(r.get("checks", [])) for r in RESULTS)}}))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
