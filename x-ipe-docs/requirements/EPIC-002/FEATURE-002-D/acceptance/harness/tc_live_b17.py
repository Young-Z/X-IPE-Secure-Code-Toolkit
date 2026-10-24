"""TC-L-01 (B9 = A, B17 = A): live provisioning of the Trivy components from the real `mirror.gcr.io` through the
implemented adapter (`secure-code tools provision`, real Trivy v0.76.1 linux/arm64), ONE provisioning request,
inside a disposable container on Docker's default bridge network. Harness only; never imports toolkit code.

Real-host observation inside the container (no iptables, no proxy, no DNS sinkhole):
  * AF_PACKET capture of every frame the container sends, plus incoming DNS responses: destination IP/port of
    every IP frame, every DNS query name, DNS answers (name -> addresses, CNAME chain), and the TLS ClientHello
    server name (SNI) of every TLS connection the container opens. HTTP Host headers and redirect targets inside
    TLS are NOT observable; a redirect to another host would surface as a new DNS query and a new SNI.
  * /proc watcher (blackbox.ProcWatch): argv, environment, working folder of every `trivy` process.
After the operation the provisioned generations are copied (no new download) to /export for the loopback
registry of the offline black-box run, and one offline scan is run with the live-provisioned components.

  FAT_ISOLATED=1 TRIVY=/tv/ARM64/trivy python3 tc_live_b17.py     # JSON lines on stdout
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, os.environ.get("FAT_RUNNER", "/fat"))
import blackbox as bb  # noqa: E402  (the unchanged acceptance runner; helpers only)

EXPORT = Path(os.environ.get("EXPORT", "/export"))
SUBS = {"vulnerability_db": "db", "java_db": "java-db", "checks_bundle": "policy"}


def _name(buf: bytes, pos: int) -> tuple[str, int]:
    labels, jumped, end = [], False, pos
    for _ in range(64):
        n = buf[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = pos + 2
            pos, jumped = ((n & 0x3F) << 8) | buf[pos + 1], True
            continue
        labels.append(buf[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if jumped else pos)


def parse_dns(msg: bytes) -> dict:
    qd, an = struct.unpack("!HH", msg[4:8])
    pos, qs, answers = 12, [], []
    for _ in range(qd):
        name, pos = _name(msg, pos)
        qtype = struct.unpack("!H", msg[pos:pos + 2])[0]
        qs.append((name, qtype))
        pos += 4
    for _ in range(an):
        name, pos = _name(msg, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        rd = msg[pos:pos + rdlen]
        if rtype == 1 and rdlen == 4:
            answers.append((name, "A", socket.inet_ntoa(rd)))
        elif rtype == 28 and rdlen == 16:
            answers.append((name, "AAAA", socket.inet_ntop(socket.AF_INET6, rd)))
        elif rtype == 5:
            answers.append((name, "CNAME", _name(msg, pos)[0]))
        pos += rdlen
    return {"questions": qs, "answers": answers}


def parse_sni(p: bytes) -> str | None:
    try:
        if len(p) < 6 or p[0] != 0x16 or p[5] != 0x01:
            return None
        pos = 9 + 2 + 32
        pos += 1 + p[pos]
        pos += 2 + struct.unpack("!H", p[pos:pos + 2])[0]
        pos += 1 + p[pos]
        end = pos + 2 + struct.unpack("!H", p[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", p[pos:pos + 4])
            if etype == 0:
                n = struct.unpack("!H", p[pos + 7:pos + 9])[0]
                return p[pos + 9:pos + 9 + n].decode("ascii", "replace")
            pos += 4 + elen
    except (IndexError, struct.error):
        return "<unparsed-clienthello>"
    return None


class LiveSniffer(bb.Sniffer):
    """Outgoing frames (as blackbox.Sniffer) + SNI of ClientHellos + incoming DNS responses."""

    def run(self) -> None:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.ok = True
        except OSError as exc:
            self.error = repr(exc)
            return
        self.dns_answers: list[dict] = []
        while True:
            data, addr = s.recvfrom(65535)
            if addr[2] not in (0, 4):
                continue
            rec = self._parse(addr[0], data)
            ip = data[14:]
            if rec.get("etype") != "0x800" or len(ip) < 20:
                if addr[2] == 4:
                    self.frames.append(rec)
                continue
            ihl = (ip[0] & 0x0F) * 4
            l4 = ip[ihl:]
            if addr[2] == 0:  # incoming: keep DNS responses only
                if rec.get("proto") == 17 and rec.get("sport") == 53 and len(l4) > 8:
                    try:
                        self.dns_answers.append({"t": rec["t"], **parse_dns(l4[8:])})
                    except (IndexError, struct.error):
                        pass
                continue
            if rec.get("proto") == 6 and len(l4) >= 20:
                payload = l4[(l4[12] >> 4) * 4:]
                if payload:
                    sni = parse_sni(payload)
                    if sni is not None:
                        rec["sni"] = sni
            self.frames.append(rec)


def main() -> int:
    if os.environ.get("FAT_ISOLATED") != "1":
        print("refusing: needs a disposable container (FAT_ISOLATED=1)")
        return 2
    shutil.rmtree(Path.home() / ".config/ai-secure-code-toolkit", ignore_errors=True)
    bb.WORK.mkdir(parents=True, exist_ok=True)
    bb.SNIFF, bb.PROCS = LiveSniffer(), bb.ProcWatch()
    bb.SNIFF.start()
    bb.PROCS.start()
    time.sleep(1)
    bb.case("TC-L-01", ["AC-002D-02b", "AC-002D-02c", "AC-002D-08a"], tc_live)
    passed = sum(r["status"] == "Pass" for r in bb.RESULTS)
    print(json.dumps({"summary": {"mode": "live", "passed": passed, "total": len(bb.RESULTS),
                                  "checks": sum(len(r.get("checks", [])) for r in bb.RESULTS)}}))
    return 0 if passed == len(bb.RESULTS) else 1


def tc_live():
    assert bb.sc_pty([bb.PASS, bb.PASS], "auth", "init") == 0
    p = bb.new_project("live ü")
    (p / "app").mkdir()
    (p / "app" / "requirements.txt").write_text("requests==2.19.0\n")
    assert bb.register(p)[0] == 0
    scope = bb.save_scope(p)
    vid, _ = bb.setup(p, scope, ["app/requirements.txt"], [bb.chk("L1", ["app/requirements.txt"])])
    ext = bb.extend(p, vid, attempts="2", minutes="120")
    st0 = bb.state(p, vid)
    granted = bb.mirror_grants(p, vid)
    time.sleep(0.5)
    f0, p0, d0 = len(bb.SNIFF.frames), len(bb.PROCS.order), len(bb.SNIFF.dns_answers)
    t0 = time.time()
    c, o, _, err = bb.provision(p, vid, list(bb.COMPONENTS), time_limit=1800)
    t1 = time.time()
    time.sleep(1.0)
    frames, procs = bb.SNIFF.frames[f0:], bb.PROCS.since(p0)
    answers = bb.SNIFF.dns_answers[d0:]
    st = bb.state(p, vid)
    ops = {op["component"]: op for op in (o or {}).get("data", {}).get("operations", [])}
    new_decl = [d for d in st["egress"]["declarations"] if d not in st0["egress"]["declarations"]]
    new_att = [a for a in st["attempts"] if a not in st0["attempts"]]
    entry = st["tool_provisioning"][-1] if st.get("tool_provisioning") else {}
    byname = {x["argv"][1] + ("-java" if "--download-java-db-only" in x["argv"] else ""): x
              for x in procs if x.get("argv")}
    pv, pj, pc = byname.get("image"), byname.get("image-java"), byname.get("fs")
    try:
        comp_json = json.loads((p / bb.CACHE / "components.json").read_text())
        gen = {n: p / bb.CACHE / "gen" / n / comp_json["components"][n]["generation"] for n in bb.COMPONENTS}
        meta_files = {n: json.loads((gen[n] / SUBS[n] / "metadata.json").read_text()) for n in bb.COMPONENTS}
    except (OSError, KeyError, ValueError) as exc:
        comp_json, gen, meta_files = {"components": {}, "error": repr(exc)}, {}, {}
    st_tools = bb.status(p)["trivy"]

    ip = [f for f in frames if f["etype"] in ("0x800", "0x86dd")]
    dns_q = sorted({f["dns"] for f in frames if "dns" in f})
    snis = [f["sni"] for f in ip if "sni" in f]
    resolved: dict[str, set[str]] = {}
    for a in answers:
        for name, kind, value in a["answers"]:
            resolved.setdefault(name, set()).add(value)
    names_for_ip: dict[str, set[str]] = {}
    for name, values in resolved.items():
        for v in values:
            names_for_ip.setdefault(v, set()).add(name)
    cname_chain = {n: sorted(v) for n, v in resolved.items()}
    dsts = sorted({(f.get("dst"), f.get("proto"), f.get("dport")) for f in ip}, key=str)
    resolver = {f["dst"] for f in ip if f.get("dport") == 53}
    tls_dsts = {f["dst"] for f in ip if f.get("proto") == 6 and f.get("dport") == 443}
    other = [d for d in dsts if not (d[2] == 53 and d[0] in resolver) and not (d[1] == 6 and d[2] == 443)]
    chain, todo = set(), ["mirror.gcr.io"]
    while todo:  # mirror.gcr.io and every name its CNAME records lead to
        n = todo.pop().rstrip(".")
        if n in chain:
            continue
        chain.add(n)
        todo += [v for _, kind, v in (x for a in answers for x in a["answers"] if x[0].rstrip(".") == n)
                 if kind == "CNAME"]
    mirror_addrs = {v for a in answers for name, kind, v in a["answers"]
                    if name.rstrip(".") in chain and kind in ("A", "AAAA")}
    tls_ip_names = {d: sorted(names_for_ip.get(d, set())) for d in tls_dsts}
    bytes_out = sum(1 for _ in ip)

    # scan with the live-provisioned components (offline flags; observed)
    f2, p2 = len(bb.SNIFF.frames), len(bb.PROCS.order)
    cs, os_, _, _ = bb.tool(p, vid, [bb.tchk("L1", ["vuln"], "filesystem", ["app/requirements.txt"])])
    time.sleep(1.0)
    scan_ip = [f for f in bb.SNIFF.frames[f2:] if f["etype"] in ("0x800", "0x86dd")]
    scan_procs = bb.PROCS.since(p2)
    runs = bb.state(p, vid).get("adapter_runs") or [{}]
    l1 = (runs[-1].get("checks") or {}).get("L1", {})
    _, concl, _, _ = bb.g(p, "conclude", vid)
    rp = p / bb.REPORTS / f"{vid}.md"
    md = rp.read_text() if rp.exists() else ""

    # export generations for the loopback registry (copy only; no new download)
    exported = {}
    if EXPORT.exists() and len(gen) == 3:
        for n in bb.COMPONENTS:
            dst = EXPORT / SUBS[n]
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(gen[n] / SUBS[n], dst)
        for rel in ("db/trivy.db", "db/metadata.json", "java-db/trivy-java.db", "java-db/metadata.json",
                    "policy/metadata.json"):
            exported[rel] = bb.sha_file(EXPORT / rel)
        exported["policy_files"] = sum(1 for x in (EXPORT / "policy").rglob("*") if x.is_file())

    bb.note("TC-L-01", {
        "provision_exit": c, "trivy_processes": len(procs), "seconds": round(t1 - t0, 1), "extend_exit": ext, "grants_exit_ok": granted,
        "operations": (o or {}).get("data", {}).get("operations"), "problems": (o or {}).get("problems"),
        "attempt": new_att, "declarations": new_decl, "argv": {k: v.get("argv") for k, v in byname.items()},
        "env_keys": {k: sorted(v.get("env", {})) for k, v in byname.items()},
        "cwd": {k: v.get("cwd") for k, v in byname.items()},
        "observed": {"ip_frames": bytes_out, "destinations": [list(map(str, d)) for d in dsts],
                     "dns_queries": dns_q, "dns_answers": cname_chain, "sni": sorted(set(snis)),
                     "tls_client_hellos": len(snis), "tls_destinations_by_dns_name": tls_ip_names,
                     "resolver": sorted(resolver), "mirror_cname_chain": sorted(chain),
                     "mirror_addresses": sorted(mirror_addrs),
                     "other_destinations": [list(map(str, d)) for d in other]},
        "metadata_files": meta_files, "status_components": st_tools.get("components"),
        "scan": {"exit": cs, "method_status": l1.get("method_status") or l1.get("status"),
                 "ip_frames": len(scan_ip), "trivy_processes": len(scan_procs),
                 "argv": [x.get("argv") for x in scan_procs]},
        "report_sections": [ln for ln in md.splitlines() if ln.startswith("## ")],
        "exported": exported, "stderr_tail": err[-800:] if err else ""})

    def op(n):
        return ops.get(n) or {}

    def one_repo(proc, flag, repo):
        a = (proc or {}).get("argv") or []
        return a.count(flag) == 1 and a[a.index(flag) + 1] == repo and not any(
            x in a for x in ("--db-repository", "--java-db-repository", "--checks-bundle-repository") if x != flag)

    return [
        ("B9 grants given by the user at a terminal (tool_update, metadata, exact mirror.gcr.io repository scopes)",
         granted),
        ("02b/02c live: every component provisioned from the real mirror.gcr.io, one operation each, completed, "
         "previous missing", c == 0 and set(ops) == set(bb.COMPONENTS)
         and all(x["outcome"] == "completed" and x["previous"] == "missing" for x in ops.values())),
        ("02b vulnerability DB argv: image --download-db-only, exactly one --db-repository "
         "mirror.gcr.io/aquasec/trivy-db:2, version check and telemetry off",
         pv is not None and pv["argv"][1:3] == ["image", "--download-db-only"]
         and one_repo(pv, "--db-repository", "mirror.gcr.io/aquasec/trivy-db:2")
         and "--skip-version-check" in pv["argv"] and "--disable-telemetry" in pv["argv"]),
        ("02b Java DB argv: exactly one --java-db-repository mirror.gcr.io/aquasec/trivy-java-db:1",
         pj is not None and one_repo(pj, "--java-db-repository", "mirror.gcr.io/aquasec/trivy-java-db:1")
         and "--skip-version-check" in pj["argv"] and "--disable-telemetry" in pj["argv"]),
        ("02b checks bundle argv: fs --scanners misconfig on an empty folder, exactly one "
         "--checks-bundle-repository mirror.gcr.io/aquasec/trivy-checks:2, update/lookup skips",
         pc is not None and one_repo(pc, "--checks-bundle-repository", "mirror.gcr.io/aquasec/trivy-checks:2")
         and all(f in pc["argv"] for f in ("--skip-db-update", "--skip-java-db-update", "--offline-scan",
                                            "--skip-version-check", "--disable-telemetry"))
         and pc["argv"][-1].endswith("/empty")),
        ("02b no project file passed; minimal environment; private operation folder as working folder; "
         "exactly three trivy processes",
         len(procs) == 3 and all(bb.no_project_path(x.get("argv", []), p) and set(x.get("env", {})) == bb.MINIMAL_ENV
                                 and f"/{bb.CACHE}/staging/op-" in x.get("cwd", "") for x in procs)),
        ("02b real-host observation: every TLS ClientHello carried SNI mirror.gcr.io (no ghcr.io, no "
         "pkg-containers.githubusercontent.com, no other server name)",
         len(snis) >= 1 and set(snis) == {"mirror.gcr.io"}),
        ("02b real-host observation: DNS queries only for mirror.gcr.io; every TLS connection went to an "
         "address the resolver returned for mirror.gcr.io (or its CNAME chain); no other IP destination "
         "than the resolver on 53 and those addresses on 443",
         dns_q != [] and {q.rstrip(".") for q in dns_q} == {"mirror.gcr.io"} and tls_dsts
         and tls_dsts <= mirror_addrs and other == []),
        ("02b one allowed declaration per operation, used:true, listing every known host (mirror.gcr.io) with "
         "its grant", len(new_decl) == 3 and all(d["decision"] == "allowed" and d["used"] is True
                                                and [h["host"] for h in d["known_hosts"]] == ["mirror.gcr.io"]
                                                and d["known_hosts"][0]["grant"] for d in new_decl)),
        ("02b provisioning registered as one tool_update attempt of the verification, finished",
         len(new_att) == 1 and new_att[0]["kind"] == "tool_update" and new_att[0]["status"] != "running"),
        ("02c result: repository, tag, outcome, size, time, content digest and metadata per component "
         "(DB: Version/UpdatedAt/NextUpdate/DownloadedAt; bundle: MajorVersion/Digest/DownloadedAt)",
         all(op(n).get("repository") and (op(n).get("content_digest") or "").startswith("sha256:")
             for n in bb.COMPONENTS)
         and set(op("vulnerability_db").get("metadata") or {}) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
         and set(op("java_db").get("metadata") or {}) >= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
         and set(op("checks_bundle").get("metadata") or {}) >= {"MajorVersion", "Digest", "DownloadedAt"}),
        ("02c recorded metadata equals the installed metadata.json files (live)",
         len(meta_files) == 3 and all(op(n).get("metadata") and all(meta_files[n].get(k) == v for k, v in
                                                                    op(n)["metadata"].items()) for n in bb.COMPONENTS)),
        ("02c result records the Maintainer action, the grants used and the configuration-level limit",
         entry.get("maintainer", {}).get("action") == "tools.provision" and all(op(n).get("grants") for n in bb.COMPONENTS)
         and "configuration-level" in entry.get("limit", "") and "not network enforcement" in entry.get("limit", "")),
        ("02c components stored per project in the private cache; staging removed",
         bb.staging_empty(p) and set(comp_json["components"]) == set(bb.COMPONENTS)),
        ("08a status: each component present, registry mirror.gcr.io",
         all((st_tools.get("components") or {}).get(n, {}).get("state") == "present"
             and st_tools["components"][n].get("registry") == "mirror.gcr.io" for n in bb.COMPONENTS)),
        ("02b report shows Tool Provisioning with repository, known hosts and the configuration-level limit",
         "Tool Provisioning" in md and "mirror.gcr.io/aquasec/trivy-db" in md and "Known hosts" in md
         and "configuration-level" in md),
        ("02d the live-provisioned components are used by an offline scan: completed, no IP frame sent",
         cs == 0 and len(scan_procs) >= 1 and scan_ip == []
         and all(all(f in x.get("argv", []) for f in bb.OFFLINE) for x in scan_procs)),
    ]


def selftest() -> int:
    """Offline (--network none) check of the observers: a loopback TLS ClientHello with SNI and a crafted DNS
    response must be decoded."""
    import ssl
    import threading

    bb.SNIFF = LiveSniffer()
    bb.SNIFF.start()
    time.sleep(0.5)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept()[0].recv(4096), daemon=True).start()
    ctx = ssl.create_default_context()
    raw = socket.create_connection(("127.0.0.1", port))
    raw.settimeout(1)
    try:
        ctx.wrap_socket(raw, server_hostname="mirror.gcr.io")
    except (OSError, ssl.SSLError):
        pass
    time.sleep(0.5)
    resp = (b"\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" + b"\x06mirror\x03gcr\x02io\x00\x00\x01\x00\x01"
            + b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03abc\xc0\x13"
            + b"\xc0\x2b\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x8e\xfa\x01\x52")
    dns = parse_dns(resp)
    snis = [f.get("sni") for f in bb.SNIFF.frames if f.get("sni")]
    ok = snis == ["mirror.gcr.io"] and ("mirror.gcr.io", "CNAME", "abc.gcr.io") in dns["answers"] \
        and ("abc.gcr.io", "A", "142.250.1.82") in dns["answers"]
    print(json.dumps({"selftest": "Pass" if ok else "Fail", "sniffer_ok": bb.SNIFF.ok, "snis": snis, "dns": dns}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest() if sys.argv[1:] == ["selftest"] else main())
