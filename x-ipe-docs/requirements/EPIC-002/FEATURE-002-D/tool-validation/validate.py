"""S-07 tool-level validation of Trivy (FEATURE-002-D, TASK-055/TASK-056). Runs only inside disposable containers.

  python3 validate.py download     # online: official release archives -> /tv (volume); verify digests
  python3 validate.py proxy-server # separate proxy container (internal + external network): logging CONNECT
                                   #   proxy on 0.0.0.0:3128, JSON lines to /plog/proxy.jsonl, deny list /plog/deny.txt
  python3 validate.py provision    # trivy container on an --internal network (no route out except the proxy):
                                   #   exact provisioning argv per component and per repository (mirror.gcr.io,
                                   #   ghcr.io), fallback checks; assembles the mirror.gcr.io results into /cache
  python3 validate.py elf        # offline: ELF program headers of both extracted binaries (static linkage)
  python3 validate.py run        # offline (--network none): /cache read-only (+ /cachew writable for variants),
                                 #         samples and image archives read-only; prints JSON lines

Never prints matched secret text: secrets are reported by rule, location, length and SHA-256 only.
"""
import hashlib, json, os, shutil, socket, subprocess, sys, tarfile, threading, time
import urllib.request
from pathlib import Path

VERSION = "0.76.1"
ARCH = "ARM64" if os.uname().machine in ("aarch64", "arm64") else "64bit"
REL = f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}"
ASSETS = {  # GitHub release metadata `digest` (checked 10-22-2026)
    "trivy_0.76.1_checksums.txt": "885debc41b570179e81af560e5f393a66be29b9ff8c52915674f3eb2304c535d",
    "trivy_0.76.1_Linux-ARM64.tar.gz": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    "trivy_0.76.1_Linux-64bit.tar.gz": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
}
TV, CACHE, SAMPLES, FIX = Path("/tv"), Path("/cache"), Path("/samples"), Path("/v/fixtures")
SECRET_FIX = Path("/work/fixtures/secret")  # generated at run time so no credential-like text is stored in the repo
BIN = TV / "ARM64" / "trivy" if ARCH == "ARM64" else TV / "64bit" / "trivy"
FAKE_SECRET = "AKIA" + "Z7Q3XK5N2PVB4L6M"  # self-authored fake (fixture); must never appear in stored output
FAKE_PAT = "ghp_" + "Qx7Lm2Vb9Tn4Rk8Wd3Hs6Jy1Pf5Gc0Za2Ue4"


def make_secret_fixture():
    SECRET_FIX.mkdir(parents=True, exist_ok=True)
    (SECRET_FIX / "settings.env").write_text(f"APP_NAME=demo\nAWS_ACCESS_KEY_ID={FAKE_SECRET}\nGITHUB_TOKEN={FAKE_PAT}\n")
    (SECRET_FIX / "clean.txt").write_text("nothing secret here\n")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def emit(rec): print(json.dumps(rec), flush=True)


def tree(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(Path(root).rglob("*")) if p.is_file() and not p.is_symlink()}


def download():
    TV.mkdir(parents=True, exist_ok=True)
    for name, want in ASSETS.items():
        dst = TV / name
        urllib.request.urlretrieve(f"{REL}/{name}", dst)
        got = sha(dst)
        rec = {"case": "download", "asset": name, "size": dst.stat().st_size, "sha256": got, "release_digest_match": got == want}
        if name.endswith(".tar.gz"):
            urllib.request.urlretrieve(f"{REL}/{name}.sigstore.json", str(dst) + ".sigstore.json")
            listed = {l.split()[1]: l.split()[0] for l in (TV / "trivy_0.76.1_checksums.txt").read_text().splitlines() if l.strip()}
            rec["checksums_txt_match"] = listed.get(name) == got
            out = TV / name.split("_")[-1].split(".")[0].replace("Linux-", "")
            out.mkdir(exist_ok=True)
            with tarfile.open(dst) as t:
                rec["archive_members"] = t.getnames()
                t.extract("trivy", out, filter="data")
            b = out / "trivy"
            rec["binary"] = {"path": str(b), "sha256": sha(b), "size": b.stat().st_size}
            rec["file_type"] = subprocess.run(["sh", "-c", f"command -v file >/dev/null && file -b {b} || head -c 20 {b} | od -c | head -2"], capture_output=True, text=True).stdout.strip()
        emit(rec)
    emit({"case": "cosign", "available": shutil.which("cosign") is not None, "note": "sigstore bundles downloaded; verification requires cosign"})


# --------------------------------------------------------------------------- logging CONNECT proxy
HOSTS = []
PROXY_LOG = os.environ.get("TV_PROXY_LOG")      # set in the trivy container when an external proxy logs to a file
DENY_FILE = None                                # set in the proxy-server: hosts listed there get 403
_LOG_LOCK = threading.Lock()


def _log(entry, logfile):
    HOSTS.append(entry)
    if logfile:
        with _LOG_LOCK, open(logfile, "a") as f:
            f.write(json.dumps(entry) + "\n")


def _pipe(a, b):
    try:
        while (d := a.recv(65536)):
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass


def _client(c, logfile=None):
    head = b""
    while b"\r\n\r\n" not in head:
        d = c.recv(4096)
        if not d:
            return
        head += d
    line = head.split(b"\r\n")[0].decode()
    method, target, _ = line.split(" ", 2)
    entry = {"t": round(time.time(), 1), "method": method, "target": target if method == "CONNECT" else target.split("?")[0]}
    if method != "CONNECT":
        _log(entry, logfile)
        c.sendall(b"HTTP/1.1 405 only CONNECT\r\n\r\n"); c.close(); return
    host, port = target.rsplit(":", 1)
    denied = DENY_FILE and Path(DENY_FILE).is_file() and host in Path(DENY_FILE).read_text().split()
    if denied:
        entry["denied_by_proxy"] = True
        _log(entry, logfile)
        c.sendall(b"HTTP/1.1 403 denied\r\n\r\n"); c.close(); return
    try:
        up = socket.create_connection((host, int(port)), timeout=60)
        up.settimeout(None)  # no idle timeout on established tunnels (long downloads, idle keep-alive connections)
    except OSError as exc:
        entry["upstream_error"] = type(exc).__name__
        _log(entry, logfile)
        c.sendall(b"HTTP/1.1 502 upstream unreachable\r\n\r\n"); c.close(); return
    _log(entry, logfile)
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    threading.Thread(target=_pipe, args=(c, up), daemon=True).start()
    _pipe(up, c)


def proxy(bind="127.0.0.1", logfile=None):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, 3128)); s.listen(50)
    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=_client, args=(c, logfile), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def proxy_server():
    global DENY_FILE
    DENY_FILE = "/plog/deny.txt"
    proxy("0.0.0.0", "/plog/proxy.jsonl")
    print("proxy listening on 0.0.0.0:3128", flush=True)
    while True:
        time.sleep(3600)


# --------------------------------------------------------------------------- runs
_PURL = os.environ.get("TV_PROXY_URL", "http://127.0.0.1:3128")
PROXY_ENV = {"HTTPS_PROXY": _PURL, "HTTP_PROXY": _PURL}


def _proxy_mark():
    return Path(PROXY_LOG).stat().st_size if PROXY_LOG and Path(PROXY_LOG).exists() else len(HOSTS)


def _proxy_since(mark):
    if PROXY_LOG:
        time.sleep(0.5)  # let the proxy container flush its last lines
        if not Path(PROXY_LOG).exists():
            return []
        with open(PROXY_LOG) as f:
            f.seek(mark)
            return [json.loads(l) for l in f.read().splitlines() if l.strip()]
    return HOSTS[mark:]


def _exec(argv, env, timeout):
    """Run one process; per-process CPU and peak RSS from wait4 (not cumulative over earlier cases)."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    chunks = {"out": [], "err": []}
    readers = [threading.Thread(target=lambda f, k: chunks[k].append(f.read()), args=(proc.stdout, "out")),
               threading.Thread(target=lambda f, k: chunks[k].append(f.read()), args=(proc.stderr, "err"))]
    for t in readers:
        t.start()
    timer = threading.Timer(timeout, proc.kill); timer.start()
    _, status, usage = os.wait4(proc.pid, 0)
    timer.cancel()
    for t in readers:
        t.join()
    proc.returncode = os.waitstatus_to_exitcode(status)
    dec = lambda k: b"".join(chunks[k]).decode("utf-8", "replace")
    return proc.returncode, dec("out"), dec("err"), usage


def run(name, args, env_extra=None, cache=True, timeout=1800, grep=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "TMPDIR": "/work/tmp", **PROXY_ENV, **(env_extra or {})}
    argv = [str(BIN), *args] + (["--cache-dir", str(CACHE)] if cache and "--cache-dir" not in args else [])
    start = time.time()
    n0 = _proxy_mark()
    code, out, err, usage = _exec(argv, env, timeout)
    rec = {"case": name, "args": args, "exit": code, "seconds": round(time.time() - start, 2),
           "cpu_seconds": round(usage.ru_utime + usage.ru_stime, 2), "max_rss_mb": round(usage.ru_maxrss / 1024, 1),
           "stderr_tail": _scrub(err)[-1500:], "fake_secret_in_raw_output": FAKE_SECRET in out + err,
           "fake_pat_in_raw_output": FAKE_PAT in out + err, "stdout_bytes": len(out)}
    if grep:
        rec["stderr_grep"] = {}
        for g in grep:
            lines = [l for l in err.splitlines() if g in l]
            if lines:
                rec["stderr_grep"][g] = {"count": len(lines), "first": [_scrub(l.split("\t", 2)[-1])[:240] for l in lines[:12]]}
    seen = _proxy_since(n0)
    if seen:
        rec["proxy_requests"] = seen
    if "--debug" in args and Path(args[-1]).is_dir():
        rec["secret_file_coverage"] = _secret_coverage(Path(args[-1]), err)
    try:
        doc = json.loads(out)
        rec.update(_shape(doc))
    except ValueError as exc:
        rec["stdout_head"] = _scrub(out)[:400]
        rec["parse_error"] = str(exc)
    emit(rec)
    return rec, out


def _secret_coverage(root, err):
    """Files the secret scanner reported as scanned (debug log) versus all regular files of the target."""
    scanned = {l.split('file_path="', 1)[1].split('"', 1)[0] for l in err.splitlines() if "Using streaming scanner" in l}
    files = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and not p.is_symlink()}
    missing = sorted(files - scanned)
    by_dir, by_ext = {}, {}
    for f in missing:
        d = f.split("/")[0] if "/" in f else "."
        by_dir[d] = by_dir.get(d, 0) + 1
        e = Path(f).suffix or Path(f).name
        by_ext[e] = by_ext.get(e, 0) + 1
    tests = sum(1 for f in missing if any(part in ("test", "tests") for part in Path(f).parts))
    return {"files": len(files), "secret_scanned": len(scanned & files), "not_scanned": len(missing),
            "not_scanned_by_top_dir": by_dir, "not_scanned_by_ext": dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:15]),
            "not_scanned_under_test_dirs": tests, "not_scanned_examples": missing[:12]}


def _scrub(text):
    return text.replace(FAKE_SECRET, "<FAKE-SECRET-PLAINTEXT>").replace(FAKE_PAT, "<FAKE-PAT-PLAINTEXT>")


def _shape(doc):
    res = {"top_keys": sorted(doc)}
    md = doc.get("Metadata") or {}
    res["metadata_keys"] = sorted(md)
    for k in ("OS", "ImageID", "RepoTags"):
        if md.get(k):
            res[f"metadata_{k}"] = md[k]
    targets = []
    for r in doc.get("Results") or []:
        t = {"Target": r.get("Target"), "Class": r.get("Class"), "Type": r.get("Type"), "keys": sorted(r)}
        vulns = r.get("Vulnerabilities") or []
        if vulns:
            t["vulns"] = len(vulns)
            t["vuln_keys"] = sorted(vulns[0])
            t["vuln_severities"] = _count(v.get("Severity") for v in vulns)
            t["vuln_example"] = {k: vulns[0].get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "SeveritySource", "PkgPath", "Status")}
            t["vuln_example"]["CweIDs"] = vulns[0].get("CweIDs")
            t["vuln_example"]["DataSource"] = vulns[0].get("DataSource")
        mis = r.get("Misconfigurations") or []
        if mis:
            t["misconfigs"] = len(mis)
            t["misconf_keys"] = sorted(mis[0])
            t["misconf_status"] = _count(m.get("Status") for m in mis)
            t["misconf_severities"] = _count(m.get("Severity") for m in mis if m.get("Status") == "FAIL")
            t["misconf_fail_ids"] = sorted({m.get("ID") for m in mis if m.get("Status") == "FAIL"})
            cm = mis[0].get("CauseMetadata") or {}
            t["misconf_cause_keys"] = sorted(cm)
        if r.get("MisconfSummary"):
            t["MisconfSummary"] = r["MisconfSummary"]
        sec = r.get("Secrets") or []
        if sec:
            t["secrets"] = [{"RuleID": s.get("RuleID"), "Category": s.get("Category"), "Severity": s.get("Severity"),
                             "StartLine": s.get("StartLine"), "EndLine": s.get("EndLine"), "keys": sorted(s),
                             "match_len": len(s.get("Match") or ""), "match_sha256": hashlib.sha256((s.get("Match") or "").encode()).hexdigest()[:16],
                             "match_has_asterisks": "*" in (s.get("Match") or ""),
                             "code_lines_have_asterisks": any("*" in (l.get("Content") or "") for l in ((s.get("Code") or {}).get("Lines") or [])),
                             "fake_plaintext_in_match": FAKE_SECRET in (s.get("Match") or ""),
                             "fake_plaintext_in_code": FAKE_SECRET in json.dumps(s.get("Code")) or FAKE_PAT in json.dumps(s.get("Code")),
                             "fake_pat_in_match": FAKE_PAT in (s.get("Match") or "")} for s in sec]
        pk = r.get("Packages") or []
        if pk:
            t["packages"] = len(pk)
        targets.append(t)
    res["results"] = targets
    return res


def _count(it):
    out = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return out


REPOS = {  # official repositories (tool --help defaults); one explicit repository per operation
    "mirror.gcr.io": {"vulnerability_db": "mirror.gcr.io/aquasec/trivy-db:2", "java_db": "mirror.gcr.io/aquasec/trivy-java-db:1",
                      "checks_bundle": "mirror.gcr.io/aquasec/trivy-checks:2"},
    "ghcr.io": {"vulnerability_db": "ghcr.io/aquasecurity/trivy-db:2", "java_db": "ghcr.io/aquasecurity/trivy-java-db:1",
                "checks_bundle": "ghcr.io/aquasecurity/trivy-checks:2"},
}
COMMON = ["--skip-version-check", "--disable-telemetry", "--no-progress"]


def provision_argv(component, repo, op, variant="fs"):
    cache = ["--cache-dir", str(op / "cache"), "--timeout", "1800s"]
    if component == "vulnerability_db":
        return ["image", "--download-db-only", "--db-repository", repo, *COMMON, *cache]
    if component == "java_db":
        return ["image", "--download-java-db-only", "--java-db-repository", repo, *COMMON, *cache]
    (op / "empty").mkdir(parents=True, exist_ok=True)
    if variant == "fs":  # no download-only option exists for the checks bundle in v0.76.1
        return ["fs", "--scanners", "misconfig", "--checks-bundle-repository", repo, "--skip-db-update", "--skip-java-db-update",
                "--offline-scan", *COMMON, "--format", "json", *cache, str(op / "empty")]
    # `config` rejects --no-progress in v0.76.1 (observed), so it is omitted for this variant
    return ["config", "--checks-bundle-repository", repo, "--skip-version-check", "--disable-telemetry", "--format", "json",
            *cache, str(op / "empty")]


def _deny(hosts):
    Path("/plog/deny.txt").write_text("\n".join(hosts) + "\n")


def _op(name):
    op = CACHE / "_ops" / name
    (op / "cache").mkdir(parents=True, exist_ok=True)
    return op


def provision():
    for d in ("/work/home", "/work/tmp"):
        Path(d).mkdir(parents=True, exist_ok=True)
    emit({"case": "provision-environment", "proxy_url": _PURL, "proxy_log": PROXY_LOG,
          "method": "trivy container attached only to a Docker --internal network; the only reachable peer is a "
                    "separate proxy container (also on the default bridge) logging every CONNECT; HTTPS_PROXY/HTTP_PROXY "
                    "point the tool at it, so any direct connection attempt would fail and show as an error"})
    try:
        socket.create_connection(("mirror.gcr.io", 443), timeout=10).close()
        direct = "connected (NOT isolated)"
    except OSError as exc:
        direct = f"failed: {type(exc).__name__}: {exc}"
    emit({"case": "direct-connection-without-proxy", "target": "mirror.gcr.io:443", "result": direct})
    _deny([])
    ops = {}
    for host, comps in REPOS.items():
        for comp, repo in comps.items():
            op = _op(f"{comp}-{host}")
            argv = provision_argv(comp, repo, op)
            run(f"provision-{comp}-{host}", argv, cache=False)
            _cache_state(f"provision-{comp}-{host}", op / "cache")
            ops[(comp, host)] = op
        op = _op(f"checks_bundle-config-{host}")
        run(f"provision-checks_bundle-{host}-via-config", provision_argv("checks_bundle", comps["checks_bundle"], op, "config"), cache=False)
        _cache_state(f"provision-checks_bundle-{host}-via-config", op / "cache")
    # fallback behaviour: deny mirror.gcr.io at the proxy
    _deny(["mirror.gcr.io"])
    for comp in ("vulnerability_db", "java_db", "checks_bundle"):
        op = _op(f"{comp}-single-denied")
        run(f"single-repository-mirror-denied-{comp}", provision_argv(comp, REPOS["mirror.gcr.io"][comp], op), cache=False, timeout=600)
        _cache_state(f"single-repository-mirror-denied-{comp}", op / "cache")
    op = _op("vulnerability_db-default-list-denied")
    run("default-repository-list-mirror-denied-vulnerability_db",
        ["image", "--download-db-only", *COMMON, "--cache-dir", str(op / "cache"), "--timeout", "1800s"], cache=False, timeout=900)
    _cache_state("default-repository-list-mirror-denied-vulnerability_db", op / "cache")
    _deny([])
    op = _op("checks_bundle-default-flags")
    run("checks-bundle-default-flags-misconfig-scan", ["fs", "--scanners", "misconfig", "--format", "json",
        "--cache-dir", str(op / "cache"), str(FIX / "misconfig")], cache=False)
    # assemble the scan cache from the mirror.gcr.io operations, then measure component re-hash time
    for comp, sub in (("vulnerability_db", "db"), ("java_db", "java-db"), ("checks_bundle", "policy")):
        os.rename(ops[(comp, "mirror.gcr.io")] / "cache" / sub, CACHE / sub)
    shutil.rmtree(CACHE / "_ops")
    _cache_state("assembled-from-mirror.gcr.io")
    rehash_timing()


def rehash_timing():
    """Time to SHA-256 each component as the toolkit would after a scan (Python hashlib, 1 MiB reads; two passes)."""
    comps = {"vulnerability_db": ["db/trivy.db", "db/metadata.json"], "java_db": ["java-db/trivy-java.db", "java-db/metadata.json"],
             "checks_bundle": sorted(str(p.relative_to(CACHE)) for p in (CACHE / "policy").rglob("*") if p.is_file())}
    for n in (1, 2):
        rec = {"case": f"rehash-timing-pass-{n}", "components": {}}
        for comp, files in comps.items():
            t = time.time(); size = 0
            for rel in files:
                sha(CACHE / rel); size += (CACHE / rel).stat().st_size
            rec["components"][comp] = {"files": len(files), "bytes": size, "seconds": round(time.time() - t, 2)}
        t = time.time()
        subprocess.run(["sha256sum", str(CACHE / "db/trivy.db"), str(CACHE / "java-db/trivy-java.db")], capture_output=True)
        rec["sha256sum_both_databases_seconds"] = round(time.time() - t, 2)
        emit(rec)


def _cache_state(label, root=None):
    root = root or CACHE
    rec = {"case": f"cache-state-{label}", "files": {}}
    for p in sorted(root.rglob("*")):
        if p.is_file() and "_variants" not in p.parts:
            rel = str(p.relative_to(root))
            key = "policy/content/* (checks bundle)" if rel.startswith("policy/content/") else rel
            n, size = rec["files"].get(key, (0, 0))
            rec["files"][key] = (n + 1, size + p.stat().st_size)
    for meta in ("db/metadata.json", "java-db/metadata.json", "policy/metadata.json"):
        m = root / meta
        if m.is_file():
            rec[meta] = json.loads(m.read_text())
    emit(rec)


def _cache_digest():
    return {rel: sha(CACHE / rel) for rel in ("db/trivy.db", "db/metadata.json", "java-db/trivy-java.db",
                                              "java-db/metadata.json", "policy/metadata.json") if (CACHE / rel).is_file()}


CACHE_W = Path("/cachew")  # the same volume mounted writable, only for hard-linked DB-state variants


def _variant(name, drop):
    """Hard-linked copy of the populated cache; modified files are unlinked before writing (originals untouched)."""
    dst = CACHE_W / "_variants" / name
    shutil.copytree(CACHE_W, dst, copy_function=os.link,
                    ignore=lambda d, n: ["_variants", "fanal", *drop] if Path(d) == CACHE_W else [])
    return dst


def make_more_fixtures():
    """Run-time fixtures holding fake secrets (never stored in the repository)."""
    cov = Path("/work/fixtures/secret-coverage")
    for sub in ("tests", "vendor", "node_modules", "docs", ".git", "examples", "src"):
        (cov / sub).mkdir(parents=True, exist_ok=True)
        (cov / sub / "conf.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_SECRET}\n")
    (cov / "docs" / "README.md").write_text(f"AWS_ACCESS_KEY_ID={FAKE_SECRET}\n")
    (cov / "src" / "blob.bin").write_bytes(b"\x00\x01\x02" * 100 + f"AWS_ACCESS_KEY_ID={FAKE_SECRET}".encode() + b"\x00" * 100)
    (cov / "src" / "big.txt").write_text(("x" * 1000 + "\n") * 12000 + f"AWS_ACCESS_KEY_ID={FAKE_SECRET}\n")
    req = Path("/work/fixtures/req-clean"); req.mkdir(parents=True, exist_ok=True)
    (req / "requirements.txt").write_text("six==1.17.0\n")
    return cov, req


def offline_runs():
    """--network none; a loopback logging proxy records every outbound attempt of tools that honour it.

    /cache is the populated cache mounted READ-ONLY; /cachew is the same volume (writable) for variants only.
    """
    proxy()
    make_secret_fixture()
    cov, req = make_more_fixtures()
    for d in ("/work/home", "/work/tmp"):
        Path(d).mkdir(parents=True, exist_ok=True)
    sample_hash = {s: tree(SAMPLES / s) for s in ("shanghai-marathon-registration", "WebGoat")}
    image_hash = tree(Path("/images"))
    fix_hash = tree(FIX)
    cache_before = _cache_digest()
    emit({"case": "inputs", "image_archives_sha256": image_hash, "cache_sha256": cache_before})
    v = subprocess.run([str(BIN), "--version", "--format", "json", "--cache-dir", str(CACHE)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "HOME": "/work/home"})
    emit({"case": "version", "exit": v.returncode, "stdout": v.stdout.strip()[:1500], "binary_sha256": sha(BIN)})
    _cache_state("before-offline")
    skip = ["--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan"]
    off = [*skip, "--skip-version-check", "--disable-telemetry", "--no-progress", "--format", "json"]
    img = [*off, "--cache-backend", "memory"]
    m, w = str(SAMPLES / "shanghai-marathon-registration"), str(SAMPLES / "WebGoat")
    dbg = ["Using streaming scanner", "Skipping path", "Skipping vulnerability scan", "Fetching the remote",
           "cannot be determined", "are loaded", "Falling back", "Default config file", "ignore file",
           "OS is not detected", "Detected OS", "ERROR", "WARN", "FATAL"]
    # ---- main scans (all offline flags)
    run("marathon-all-scanners", ["fs", *off, "--scanners", "vuln,misconfig,secret", m])
    run("marathon-all-scanners-debug", ["fs", *off, "--scanners", "vuln,misconfig,secret", "--debug", m], grep=dbg)
    run("webgoat-all-scanners", ["fs", *off, "--scanners", "vuln,misconfig,secret", w])
    run("webgoat-all-scanners-debug", ["fs", *off, "--scanners", "vuln,misconfig,secret", "--debug", w], grep=dbg)
    run("webgoat-pom-list-all-pkgs", ["fs", *off, "--scanners", "vuln", "--list-all-pkgs", w + "/pom.xml"])
    run("webgoat-dockerfile-include-non-failures", ["fs", *off, "--scanners", "misconfig", "--include-non-failures", w + "/Dockerfile"])
    run("webgoat-dockerfile-desktop-default", ["fs", *off, "--scanners", "misconfig", w + "/Dockerfile_desktop"])
    run("webgoat-dockerfile-desktop-file-patterns", ["fs", *off, "--scanners", "misconfig", "--file-patterns", "dockerfile:Dockerfile_desktop", w + "/Dockerfile_desktop"])
    run("fixture-secret", ["fs", *off, "--scanners", "secret", str(SECRET_FIX)])
    run("fixture-secret-coverage-debug", ["fs", *off, "--scanners", "secret", "--debug", str(cov)], grep=dbg)
    run("fixture-misconfig", ["fs", *off, "--scanners", "misconfig", str(FIX / "misconfig")])
    run("fixture-requirements-zero-vulns", ["fs", *off, "--scanners", "vuln", str(req)])
    run("image-redis-alpine", ["image", *img, "--scanners", "vuln,secret,misconfig", "--input", "/images/redis-6-alpine.tar"], grep=dbg)
    run("image-hello-world", ["image", *img, "--scanners", "vuln,secret", "--input", "/images/hello-world.tar"])
    run("image-hello-world-debug", ["image", *img, "--scanners", "vuln,secret", "--debug", "--input", "/images/hello-world.tar"], grep=dbg)
    run("image-jar-only", ["image", *img, "--scanners", "vuln", "--list-all-pkgs", "--input", "/images/jar-only.tar"])
    run("image-redis-alpine-fs-cache-readonly", ["image", *off, "--scanners", "vuln", "--input", "/images/redis-6-alpine.tar"])
    # ---- network behaviour without the full offline flag set (attempts recorded by the proxy, all fail)
    run("pom-without-offline-scan", ["fs", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
                                     "--disable-telemetry", "--format", "json", "--scanners", "vuln", w + "/pom.xml"], timeout=600)
    run("skip-flags-only-default-telemetry", ["fs", *skip, "--format", "json", "--scanners", "secret", str(SECRET_FIX)], timeout=600)
    run("no-flags-at-all", ["fs", "--format", "json", "--scanners", "vuln", m], timeout=600)
    # ---- errors, flags and exit codes
    run("missing-target", ["fs", *off, "--scanners", "vuln", "/nope/target"])
    run("invalid-flag", ["fs", *off, "--no-such-flag", m])
    run("unknown-scanner", ["fs", *off, "--scanners", "license2", m])
    run("license-scanner-accepted-by-tool", ["fs", *off, "--scanners", "license", m])
    run("config-files-disabled", ["fs", *off, "--config", "", "--ignorefile", "", "--secret-config", "", "--scanners", "secret", str(SECRET_FIX)])
    run("exit-code-on-findings", ["fs", *off, "--scanners", "secret", "--exit-code", "5", str(SECRET_FIX)])
    run("exit-code-no-findings", ["fs", *off, "--scanners", "secret", "--exit-code", "5", str(FIX / "misconfig")])
    run("severity-filter", ["image", *img, "--scanners", "vuln", "--severity", "CRITICAL,HIGH", "--input", "/images/redis-6-alpine.tar"])
    run("tool-timeout-1ms", ["fs", *off, "--scanners", "vuln,misconfig,secret", "--timeout", "1ms", w])
    run("not-an-image-archive", ["image", *img, "--scanners", "vuln", "--input", str(FIX / "misconfig" / "Dockerfile")])
    # ---- database / checks state
    empty = Path("/work/empty-cache"); empty.mkdir(parents=True, exist_ok=True)
    run("no-db-vuln", ["fs", *off, "--scanners", "vuln", "--cache-dir", str(empty), w + "/pom.xml"])
    run("no-db-secret-only", ["fs", *off, "--scanners", "secret", "--cache-dir", str(empty), str(SECRET_FIX)])
    run("no-checks-bundle-misconfig", ["fs", *off, "--scanners", "misconfig", "--cache-dir", str(empty), str(FIX / "misconfig")])
    corrupt = _variant("corrupt", ["java-db"])
    (corrupt / "db" / "trivy.db").unlink(); (corrupt / "db" / "trivy.db").write_bytes(b"not a bolt database")
    run("corrupted-db", ["fs", *off, "--scanners", "vuln", "--cache-dir", str(corrupt), w + "/pom.xml"])
    nojava = _variant("nojava", ["java-db"])
    run("no-java-db-image-with-jar", ["image", *img, "--scanners", "vuln", "--cache-dir", str(nojava), "--input", "/images/jar-only.tar"])
    run("no-java-db-fs-pom", ["fs", *off, "--scanners", "vuln", "--cache-dir", str(nojava), w + "/pom.xml"])
    run("fs-single-jar-file", ["fs", *off, "--scanners", "vuln", "--list-all-pkgs", w + "/.mvn/wrapper/maven-wrapper.jar"])
    old = _variant("old", ["java-db"])
    md = json.loads((old / "db" / "metadata.json").read_text())
    md.update(NextUpdate="2020-01-01T00:00:00Z", UpdatedAt="2019-12-31T00:00:00Z", DownloadedAt="2019-12-31T01:00:00Z")
    (old / "db" / "metadata.json").unlink(); (old / "db" / "metadata.json").write_text(json.dumps(md))
    run("old-db-with-skip-update", ["fs", *off, "--scanners", "vuln", "--cache-dir", str(old), w + "/pom.xml"])
    run("old-db-without-skip-update", ["fs", "--offline-scan", "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
                                        "--disable-telemetry", "--format", "json", "--scanners", "vuln", "--cache-dir", str(old), w + "/pom.xml"], timeout=600)
    shutil.rmtree(CACHE_W / "_variants")
    unchanged = {s: tree(SAMPLES / s) == h for s, h in sample_hash.items()}
    emit({"case": "side-effects", "samples_unchanged": unchanged, "fixtures_unchanged": tree(FIX) == fix_hash,
          "image_archives_unchanged": tree(Path("/images")) == image_hash, "cache_unchanged": _cache_digest() == cache_before,
          "home_entries": sorted(str(p.relative_to("/work/home")) for p in Path("/work/home").rglob("*"))[:40],
          "tmp_entries": sorted(os.listdir("/work/tmp")), "root_home_cache_exists": Path("/root/.cache/trivy").exists(),
          "empty_cache_after": sorted(str(p.relative_to(empty)) for p in empty.rglob("*"))})
    _cache_state("after-offline")
    for sub in (["fs", "--help"], ["image", "--help"]):
        h = subprocess.run([str(BIN), *sub], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": "/work/home"})
        emit({"case": f"help-{'-'.join(sub)}", "options": sorted({w.split("=")[0].rstrip(",") for w in h.stdout.split() if w.startswith("--")})})


def elf():
    import struct
    for arch in ("ARM64", "64bit"):
        b = (TV / arch / "trivy").read_bytes()[:1 << 16]
        phoff = struct.unpack_from("<Q", b, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", b, 0x36)
        types = {struct.unpack_from("<I", b, phoff + i * phentsize)[0] for i in range(phnum)}
        emit({"case": f"elf-{arch}", "e_machine": struct.unpack_from("<H", b, 0x12)[0],
              "has_PT_INTERP": 3 in types, "has_PT_DYNAMIC": 2 in types, "sha256": sha(TV / arch / "trivy")})


if __name__ == "__main__":
    {"download": download, "proxy-server": proxy_server, "provision": provision, "run": offline_runs, "elf": elf,
     "rehash": rehash_timing}[sys.argv[1]]()
