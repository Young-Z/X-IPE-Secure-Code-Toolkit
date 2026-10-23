"""Test double emulating observed Trivy v0.76.1 behaviour (FEATURE-002-D tool-level validation).

Tests copy this file into an executable with an absolute interpreter and embedded CONFIG and FIXTURES
paths (as `fake_opengrep.py`). Every behaviour below reproduces a recorded observation of
`x-ipe-docs/requirements/EPIC-002/FEATURE-002-D/tool-validation/results-linux-aarch64.jsonl` (cases in
brackets); the recorded option lists, component metadata and log lines live in `fixtures/trivy/`.

- Flags: only the option names of the recorded `fs --help` / `image --help` are accepted; any other
  flag → usage on stdout, FATAL, exit 1 [invalid-flag]. Scanner values other than vuln, misconfig,
  secret, license → FATAL [unknown-scanner]; `license` is accepted [license-scanner-accepted-by-tool].
- Log format: `<RFC3339>\t<LEVEL>\t<message>[\t<k>=<quoted v>…]` on stderr; DEBUG lines only with
  `--debug`; scanner anchors at INFO [webgoat-all-scanners].
- Offline: a scan without one of the six offline flags records a network attempt in the invocation
  log and still succeeds silently [pom-without-offline-scan, skip-flags-only-default-telemetry].
- Project configuration: without `--config ""`, `--ignorefile ""`, `--secret-config ""` the files
  `trivy.yaml`, `.trivyignore`, `trivy-secret.yaml` in the working directory are loaded (recorded in
  the invocation log) [config-files-disabled].
- Components through `--cache-dir`: `vuln` needs `db/metadata.json` (else ERROR + FATAL "first run",
  exit 1, no JSON [no-db-vuln]); a database starting with `CORRUPT` → FATAL "invalid database"
  [corrupted-db]; `misconfig` without `policy/content` → ERROR "Falling back to embedded checks", exit 0,
  same findings [no-checks-bundle-misconfig]; an image with a Java archive needs `java-db/metadata.json`
  (else FATAL for the whole scan [no-java-db-image-with-jar]).
- `fs` vuln: `pom.xml` (dependencies without `<version>` → DEBUG skip line + one WARN "Dependency
  version cannot be determined" [webgoat-all-scanners-debug]), `requirements.txt` (listed even with no
  vulnerability [fixture-requirements-zero-vulns]), `package-lock.json`; `.jar` files are not analysed
  [fs-single-jar-file].
- `fs` misconfig: `Dockerfile`, Kubernetes YAML (`apiVersion:` + `kind:`), `.tf` (+ module target `.`),
  and files named by `--file-patterns type:regex`; never compose files [fixture-misconfig]; failures
  only in the default output, `MisconfSummary` for every recognized file; `Scanned config file` debug.
- `fs` secret: `[secret] Using streaming scanner file_path=…` debug line per scanned file; silently
  skipped: folders `tests`, `test`, `examples`, `node_modules`, Markdown, binary files; `.git` →
  "Skipping path" [fixture-secret-coverage-debug]. AWS key ids and GitHub tokens are reported with the
  value replaced by asterisks of equal length in `Match` and `Code` (context lines in clear) [fixture-secret].
- `image --input`: reads the archive's `docker save` `manifest.json` and its config; the config key
  `fake_trivy` describes the image (OS, packages, Java archive). No OS → no Results and DEBUG
  "OS is not detected." [image-hello-world-debug].
- Provisioning argv (`--download-db-only`, `--download-java-db-only`, checks bundle via `fs` of an
  empty folder) writes exactly the recorded subtree [provision-*]; variants via config `provision`.
- Modes (config `mode`): normal, sleep (with a child), nap, tool-deadline, garbage, empty, huge,
  unanchored-log, write-component, debug-only-config, invalid-db, exit1, fallback.
- Code-review additions (opt-in, defaults unchanged): config `tz_offset` (e.g. `"+08:00"`) simulates a
  host whose local zone has that offset: like Go's `time.Now()`, log timestamps (RFC 3339), `CreatedAt`
  and the provisioned `DownloadedAt` (RFC 3339 with nanoseconds) use it unless `TZ` is `UTC`;
  `force_offset: true` uses it even then. Config `fatal_format: "debug"` prints a FATAL under `--debug`
  as Trivy's debug handler does (pkg/log/handler.go): `…\tFATAL\tFatal error` without fields, then the
  error as `  - %+v` continuation lines (wrapped messages separated by `  - `, each followed by
  indented stack frames). Mode `first-run` reports the vulnerability database as never downloaded
  even when linked [no-db-vuln]. The invocation log also records the `TZ` value (`tz`).
- Bug Fix TASK-059 additions (opt-in, defaults unchanged): config `warnings` = list of
  `{"msg": …, "fields": {…}}` emitted as WARN lines after the scanner anchors (the acceptance run observed
  "[pip] Unable to find python `site-packages` directory. License detection is skipped." with
  `err="unable to find path to Python executable"` and "Using severities from other vendors for some
  vulnerabilities. Read https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity-selection for
  details."); `--file-patterns ansible:<regex>` is analysed as type `ansible` (v0.76.1 `--help` lists it;
  the result shape is assumed like the other config types, not observed).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time

CONFIG = "__CONFIG__"
FIXTURES = "__FIXTURES__"
OFFLINE = (
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
    "--offline-scan",
    "--skip-version-check",
    "--disable-telemetry",
)
VALUE_FLAGS = {
    "--scanners",
    "--format",
    "--cache-dir",
    "--timeout",
    "--config",
    "--ignorefile",
    "--secret-config",
    "--cache-backend",
    "--input",
    "--file-patterns",
    "--db-repository",
    "--java-db-repository",
    "--checks-bundle-repository",
    "--severity",
    "--exit-code",
    "--skip-files",
    "--skip-dirs",
    "--output",
    "--vex",
    "--compliance",
    "--server",
    "--misconfig-scanners",
    "--template",
    "--pkg-types",
}
AWS = re.compile(r"AKIA[0-9A-Z]{16}")
GHP = re.compile(r"ghp_[0-9A-Za-z]{36}")
VULNS = {
    "com.thoughtworks.xstream:xstream": [
        {
            "VulnerabilityID": "CVE-2013-7285",
            "Severity": "CRITICAL",
            "SeveritySource": "ghsa",
            "FixedVersion": "1.4.7, 1.4.11",
            "Status": "fixed",
            "CweIDs": ["CWE-78"],
            "Title": "xstream: remote code execution due to insecure XML deserialization",
            "Description": "Xstream API versions up to 1.4.6 allow remote command execution.",
            "DataSource": {
                "ID": "ghsa",
                "Name": "GitHub Security Advisory Maven",
                "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
            },
        }
    ],
    "org.example:rejected": [
        {"VulnerabilityID": "CVE-2099-0001", "Severity": "UNKNOWN", "Status": "affected"},
        {"VulnerabilityID": "CVE-2099-0002", "Severity": "WEIRD", "Status": "affected", "Title": "odd"},
    ],
    "django": [
        {
            "VulnerabilityID": "CVE-2019-6975",
            "Severity": "HIGH",
            "FixedVersion": "2.1.6",
            "Status": "fixed",
            "CweIDs": ["CWE-770"],
            "Title": "python-django: memory exhaustion in django.utils.numberformat.format()",
        }
    ],
}


OFFSET = None  # (sign, hours, minutes) of the simulated local zone; None = UTC (default)


def now(nano=False):
    if OFFSET is None:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sign, hours, minutes = OFFSET
    t = time.time()
    local = time.gmtime(t + sign * (hours * 3600 + minutes * 60))
    frac = f".{int((t % 1) * 1e9):09d}" if nano else ""
    zone = f"{'+' if sign > 0 else '-'}{hours:02d}:{minutes:02d}"
    return time.strftime("%Y-%m-%dT%H:%M:%S", local) + frac + zone


def set_zone(c):
    global OFFSET
    raw = c.get("tz_offset")
    if not raw or (os.environ.get("TZ") == "UTC" and not c.get("force_offset")):
        return
    OFFSET = (-1 if raw[0] == "-" else 1, int(raw[1:3]), int(raw[4:6]))


def frames(msg):
    """`%+v` rendering of a wrapped error chain: `  - ` before each message, frames indented below."""
    parts = msg.split(": ")
    out = []
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        out.append(f"  - {part}" + ("" if last else ":"))
        if not last:
            out.append(f"    github.com/aquasecurity/trivy/pkg/fake.step{i}")
            out.append(f"        /home/runner/work/trivy/trivy/pkg/fake/step.go:{100 + i}")
    return "\n".join(out)


def cfg():
    return json.load(open(CONFIG)) if os.path.exists(CONFIG) else {}


class Log:
    def __init__(self, debug, fatal_format=None):
        self.debug_on = debug
        self.fatal_format = fatal_format

    def emit(self, level, msg, **fields):
        if level == "DEBUG" and not self.debug_on:
            return
        extra = "".join(f"\t{k}={json.dumps(v)}" for k, v in fields.items())
        sys.stderr.write(f"{now()}\t{level}\t{msg}{extra}\n")
        sys.stderr.flush()

    def fatal(self, msg):
        if self.debug_on and self.fatal_format == "debug":
            sys.stderr.write(f"{now()}\tFATAL\tFatal error\n{frames(msg)}\n")
            sys.stderr.flush()
            return 1
        sys.stderr.write(f"{now()}\tFATAL\tFatal error\t{msg}\n")
        sys.stderr.flush()
        return 1


def parse(argv):
    opts = json.load(open(os.path.join(FIXTURES, "help-options.json")))
    sub = argv[0] if argv else ""
    known = set(opts.get(sub, []))
    flags, values, positional = set(), {}, []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if name not in known:
                return None, f"unknown flag: {name}"
            if name in VALUE_FLAGS:
                val = a.split("=", 1)[1] if "=" in a else argv[i + 1]
                values.setdefault(name, []).append(val)
                i += 1 if "=" in a else 2
                continue
            flags.add(name)
        else:
            positional.append(a)
        i += 1
    return (sub, flags, values, positional), None


def listing(folder):
    out = {}
    if not folder or not os.path.isdir(folder):
        return out
    for dirpath, dirnames, filenames in os.walk(folder):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            kind = "link" if os.path.islink(p) else "dir" if os.path.isdir(p) else "file"
            out[os.path.relpath(p, folder)] = {"kind": kind, "nlink": st.st_nlink}
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return out


def record(entry):
    with open(os.path.join(os.path.dirname(CONFIG), "invocations.jsonl"), "a") as log:
        log.write(json.dumps(entry) + "\n")


# --------------------------------------------------------------------------- provisioning
def provision(kind, cache, c, log):
    variant = c.get("provision", {}).get(kind, "ok")
    meta_all = json.load(open(os.path.join(FIXTURES, "component-metadata.json")))
    meta = dict(
        meta_all["checks_bundle_ghcr" if kind == "checks_bundle" and c.get("registry") == "ghcr.io" else kind]
    )
    meta["DownloadedAt"] = now(nano=OFFSET is not None)
    meta.update(c.get("metadata", {}).get(kind, {}))
    sub = {"vulnerability_db": "db", "java_db": "java-db", "checks_bundle": "policy"}[kind]
    if kind == "checks_bundle":
        log.emit("INFO", "[misconfig] Misconfiguration scanning is enabled")
        log.emit("INFO", "[checks-client] Need to update the checks bundle")
        log.emit("INFO", "[checks-client] Downloading the checks bundle...")
    else:
        label = "vulndb" if kind == "vulnerability_db" else "javadb"
        log.emit("INFO", f"[{label}] Need to update DB")
    if variant == "fail":
        return log.fatal("init error: DB error: failed to download artifact: OCI repository error: denied")
    if variant == "bundle-refused":
        log.emit(
            "ERROR",
            "[misconfig] Falling back to embedded checks",
            err="failed to download checks bundle: download error: OCI repository error: denied",
        )
        print(json.dumps({"SchemaVersion": 2, "ArtifactName": "empty", "ArtifactType": "filesystem"}))
        return 0
    base = os.path.join(cache, sub)
    os.makedirs(base, exist_ok=True)
    if variant in ("slow", "partial-slow"):
        open(os.path.join(base, "partial.tmp"), "wb").write(b"x" * 1024)
        subprocess.Popen(["sleep", "120"])
        time.sleep(float(c.get("nap", 120)))
    if kind == "checks_bundle":
        content = os.path.join(base, "content", "policies", "docker")
        os.makedirs(content, exist_ok=True)
        for n in range(3):
            open(os.path.join(content, f"check{n}.rego"), "w").write(f"package fake.check{n}\n")
        if variant == "wrong-metadata":
            meta["MajorVersion"] = 1
    else:
        db = "trivy.db" if kind == "vulnerability_db" else "trivy-java.db"
        open(os.path.join(base, db), "wb").write(hashlib.sha256(kind.encode()).digest() * 512)
        if variant == "wrong-metadata":
            meta["Version"] = 99
    open(os.path.join(base, "metadata.json"), "w").write(json.dumps(meta))
    first = sorted(os.listdir(base))[0]
    if variant == "extra-file":
        open(os.path.join(cache, "extra.bin"), "w").write("unexpected")
    if variant == "symlink":
        os.symlink(os.path.join(base, first), os.path.join(base, "link"))
    if variant == "hardlink" and os.path.isfile(os.path.join(base, first)):
        os.link(os.path.join(base, first), os.path.join(base, "hard"))
    if variant == "hardlink" and kind == "checks_bundle":
        os.link(os.path.join(base, "metadata.json"), os.path.join(base, "content", "hard.json"))
    if kind == "checks_bundle":
        print(json.dumps({"SchemaVersion": 2, "ArtifactName": "empty", "ArtifactType": "filesystem"}))
    return 0


# --------------------------------------------------------------------------- scanning helpers
def binary(path):
    try:
        return b"\0" in open(path, "rb").read(8000)
    except OSError:
        return True


def secret_skipped(rel):
    parts = rel.split("/")
    return any(p in ("tests", "test", "examples", "node_modules") for p in parts[:-1]) or rel.endswith(".md")


def walk(root):
    if os.path.isfile(root):
        return [(os.path.basename(root), root)]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        if ".git" in dirnames:
            dirnames.remove(".git")
        for f in sorted(filenames):
            p = os.path.join(dirpath, f)
            out.append((os.path.relpath(p, root), p))
    return out


def pom(rel, path, log):
    text = open(path, encoding="utf-8", errors="replace").read()
    pkgs, vulns, warned = [], [], False
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        block = m.group(1)
        g = re.search(r"<groupId>(.*?)</groupId>", block)
        a = re.search(r"<artifactId>(.*?)</artifactId>", block)
        v = re.search(r"<version>(.*?)</version>", block)
        name = f"{g.group(1) if g else ''}:{a.group(1) if a else ''}"
        line = text[: m.start()].count("\n") + 1
        if v is None:
            log.emit(
                "DEBUG",
                "[pom] Skipping vulnerability scan as no version is detected for the package",
                name=name,
            )
            log.emit("DEBUG", "[pom] Fetching the remote pom.xml is skipped")
            if not warned:
                log.emit(
                    "WARN",
                    "[pom] Dependency version cannot be determined. Child dependencies will not be found.",
                    details="https://trivy.dev/docs/v0.76/guide/coverage/language/java"
                    "#empty-dependency-version",
                )
                warned = True
            continue
        pkgs.append(
            {
                "ID": f"{name}:{v.group(1)}",
                "Name": name,
                "Version": v.group(1),
                "Locations": [{"StartLine": line, "EndLine": line + 4}],
            }
        )
        for vul in VULNS.get(name, []):
            vulns.append(
                {
                    **vul,
                    "PkgName": name,
                    "PkgID": f"{name}:{v.group(1)}",
                    "InstalledVersion": v.group(1),
                    "Fingerprint": "sha256:" + "ab" * 32,
                }
            )
    return {
        "Target": rel,
        "Class": "lang-pkgs",
        "Type": "pom",
        "Packages": pkgs,
        **({"Vulnerabilities": vulns} if vulns else {}),
    }


def pip(rel, path):
    pkgs, vulns = [], []
    for n, line in enumerate(open(path, encoding="utf-8", errors="replace").read().splitlines(), 1):
        if "==" not in line:
            continue
        name, ver = line.strip().split("==", 1)
        pkgs.append(
            {
                "ID": f"{name}@{ver}",
                "Name": name,
                "Version": ver,
                "Locations": [{"StartLine": n, "EndLine": n}],
            }
        )
        for vul in VULNS.get(name, []):
            vulns.append({**vul, "PkgName": name, "InstalledVersion": ver})
    return {
        "Target": rel,
        "Class": "lang-pkgs",
        "Type": "pip",
        "Packages": pkgs,
        **({"Vulnerabilities": vulns} if vulns else {}),
    }


def npm(rel, path):
    doc = json.load(open(path))
    pkgs = [
        {
            "ID": f"{k.split('node_modules/')[-1]}@{v.get('version')}",
            "Name": k.split("node_modules/")[-1],
            "Version": v.get("version"),
        }
        for k, v in (doc.get("packages") or {}).items()
        if k
    ]
    return {"Target": rel, "Class": "lang-pkgs", "Type": "npm", "Packages": pkgs}


def misconf_type(rel, path, patterns):
    for ptype, rx in patterns:
        if re.search(rx, rel):
            return ptype
    name = os.path.basename(rel)
    if name == "Dockerfile":
        return "dockerfile"
    if name.endswith(".tf"):
        return "terraform"
    if name.endswith((".yaml", ".yml")) and "compose" not in name:
        text = open(path, encoding="utf-8", errors="replace").read()
        if re.search(r"^apiVersion:", text, re.M) and re.search(r"^kind:", text, re.M):
            return "kubernetes"
    return None


RULES = {
    "ansible": (3, []),
    "dockerfile": (
        27,
        [
            ("DS-0001", "MEDIUM", r"^FROM \S+:latest", "':latest' tag used"),
            ("DS-0002", "HIGH", None, "Image user should not be 'root'"),
            ("DS-0004", "MEDIUM", r"^EXPOSE 22\b", "Port 22 exposed"),
            ("DS-0005", "LOW", r"^ADD ", "ADD instead of COPY"),
            (
                "DS-0029",
                "HIGH",
                r"apt-get install(?!.*--no-install-recommends)",
                "'apt-get' missing '--no-install-recommends'",
            ),
        ],
    ),
    "kubernetes": (
        98,
        [
            ("KSV-0017", "HIGH", r"privileged: true", "Privileged container"),
            ("KSV-0105", "LOW", r"runAsUser: 0", "Containers must not set runAsUser to 0"),
        ],
    ),
    "terraform": (
        12,
        [
            (
                "AWS-0092",
                "HIGH",
                r'acl\s*=\s*"public-read"',
                "S3 Buckets not publicly accessible through ACL",
            ),
            (
                "AWS-0107",
                "CRITICAL",
                r"0\.0\.0\.0/0",
                "An ingress security group rule allows traffic from /0",
            ),
        ],
    ),
}


def misconf(rel, path, kind):
    total, rules = RULES[kind]
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    found = []
    for rid, sev, rx, title in rules:
        if rx is None:
            hit = None if any(x.startswith("USER ") for x in lines) else 1
        else:
            hit = next((n for n, x in enumerate(lines, 1) if re.search(rx, x)), None)
        if hit:
            found.append(
                {
                    "ID": rid,
                    "Type": f"{kind.capitalize()} Security Check",
                    "Title": title,
                    "Description": title,
                    "Message": f"{title} (line {hit})",
                    "Severity": sev,
                    "Status": "FAIL",
                    "Resolution": "Fix it",
                    "PrimaryURL": f"https://avd.example/{rid}",
                    "CauseMetadata": {
                        "Provider": kind.capitalize(),
                        "Service": "general",
                        "StartLine": hit,
                        "EndLine": hit,
                        "Code": {"Lines": [{"Number": hit, "Content": lines[hit - 1]}]},
                    },
                }
            )
    out = {
        "Target": rel,
        "Class": "config",
        "Type": kind,
        "MisconfSummary": {"Successes": total - len(found), "Failures": len(found)},
    }
    if found:
        out["Misconfigurations"] = found
    return out


def secrets(rel, path):
    text = open(path, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()
    found = []
    for n, line in enumerate(lines, 1):
        for rx, rid, cat, title in (
            (AWS, "aws-access-key-id", "AWS", "AWS Access Key ID"),
            (GHP, "github-pat", "GitHub", "GitHub Personal Access Token"),
        ):
            for m in rx.finditer(line):
                masked = line[: m.start()] + "*" * len(m.group(0)) + line[m.end() :]
                ctx = []
                for k in (n - 1, n, n + 1):
                    if 1 <= k <= len(lines):
                        content = masked if k == n else lines[k - 1]
                        ctx.append({"Number": k, "Content": content, "IsCause": k == n})
                found.append(
                    {
                        "RuleID": rid,
                        "Category": cat,
                        "Severity": "CRITICAL",
                        "Title": title,
                        "StartLine": n,
                        "EndLine": n,
                        "Offset": text.find(m.group(0)),
                        "Match": masked,
                        "Code": {"Lines": ctx},
                    }
                )
    return {"Target": rel, "Class": "secret", "Secrets": found} if found else None


def image(archive, need_java, log):
    with tarfile.open(archive) as tar:
        manifest = json.load(tar.extractfile("manifest.json"))
        config = json.load(tar.extractfile(manifest[0]["Config"]))
    desc = config.get("fake_trivy", {})
    meta = {
        "ImageID": "sha256:" + hashlib.sha256(json.dumps(config).encode()).hexdigest(),
        "DiffIDs": ["sha256:" + "11" * 32],
        "RepoTags": manifest[0].get("RepoTags") or [],
        "ImageConfig": {"os": "linux"},
        "Size": os.path.getsize(archive),
    }
    results = []
    if desc.get("jar"):
        if not need_java:
            log.emit("ERROR", "[javadb] The first run cannot skip downloading Java DB")
            return None, log.fatal(
                "run error: image scan error: scan error: scan failed: failed analysis: "
                "post analysis error: Unable to initialize the Java DB: Java DB update failed: "
                "'--skip-java-db-update' cannot be specified on the first run"
            )
        results.append(
            {
                "Target": "Java",
                "Class": "lang-pkgs",
                "Type": "jar",
                "Packages": [{"Name": "org.example:wrapper", "Version": "3.3.2"}],
            }
        )
    os_ = desc.get("os")
    if not os_:
        log.emit("DEBUG", "OS is not detected.")
        log.emit("DEBUG", "Detected OS: unknown")
    else:
        meta["OS"] = os_
        vulns = []
        for p in desc.get("packages", []):
            for v in p.get("vulns", []):
                vulns.append(
                    {
                        "VulnerabilityID": v["id"],
                        "PkgName": p["name"],
                        "InstalledVersion": p["version"],
                        "FixedVersion": v.get("fixed", ""),
                        "Severity": v["severity"],
                        "Layer": {"DiffID": "sha256:" + "11" * 32},
                        "Title": v.get("title", v["id"]),
                    }
                )
                if v["severity"] == "UNKNOWN":
                    log.emit(
                        "WARN", "Unable to get vulnerability details (CVE may be rejected)", vuln_id=v["id"]
                    )
        results.append(
            {
                "Target": f"{archive} ({os_['Family']} {os_['Name']})",
                "Class": "os-pkgs",
                "Type": os_["Family"],
                "Packages": [{"Name": p["name"], "Version": p["version"]} for p in desc.get("packages", [])],
                **({"Vulnerabilities": vulns} if vulns else {}),
            }
        )
    return {"Metadata": meta, "Results": results}, 0


# --------------------------------------------------------------------------- main
def main():
    c = cfg()
    set_zone(c)
    mode = c.get("mode", "normal")
    parsed, err = parse(sys.argv[1:])
    entry = {
        "argv": sys.argv,
        "env": sorted(os.environ),
        "cwd": os.getcwd(),
        "cwd_listing": sorted(os.listdir(os.getcwd())),
        "home": os.environ.get("HOME"),
        "tmpdir": os.environ.get("TMPDIR"),
        "pgid": os.getpgid(0),
        "tz": os.environ.get("TZ"),
    }
    if parsed is None:
        record({**entry, "kind": "refused", "error": err})
        print("Usage:\n  trivy [global flags] command [flags] target")
        sys.stderr.write(f"{now()}\tFATAL\tFatal error\t{err}\n")
        return 1
    sub, flags, values, positional = parsed
    log = Log("--debug" in flags, c.get("fatal_format"))
    cache = (values.get("--cache-dir") or [os.path.join(os.environ.get("HOME", "/"), ".cache", "trivy")])[-1]
    download = None
    if "--download-db-only" in flags:
        download = "vulnerability_db"
    elif "--download-java-db-only" in flags:
        download = "java_db"
    elif "--checks-bundle-repository" in values:
        download = "checks_bundle"
    entry.update(
        kind="provision" if download else "scan",
        component=download,
        cache_dir=cache,
        cache_listing=listing(cache),
        resolved={
            k: os.path.realpath(os.path.join(cache, k))
            for k in ("db", "java-db", "policy")
            if os.path.lexists(os.path.join(cache, k))
        },
        network_attempts=[f for f in OFFLINE if f not in flags] if not download else [],
        loaded_project_config=[
            n
            for n, f in (
                ("trivy.yaml", "--config"),
                (".trivyignore", "--ignorefile"),
                ("trivy-secret.yaml", "--secret-config"),
            )
            if values.get(f, [None])[-1] != "" and os.path.exists(n)
        ],
    )
    record(entry)
    if download:
        return provision(download, cache, c, log)
    scanners = (values.get("--scanners") or ["vuln,secret"])[-1].split(",")
    for s in scanners:
        if s not in ("vuln", "misconfig", "secret", "license"):
            return log.fatal(f"flag error: unknown scanner: {s}")
    if mode == "unanchored-log":
        sys.stderr.write(json.dumps({"level": "info", "msg": "scan started"}) + "\n")
        log = Log(False)
        log.emit = lambda *a, **k: None
    else:
        if "vuln" in scanners:
            log.emit("INFO", "[vuln] Vulnerability scanning is enabled")
        if "misconfig" in scanners:
            log.emit("INFO", "[misconfig] Misconfiguration scanning is enabled")
        if "secret" in scanners:
            log.emit("INFO", "[secret] Secret scanning is enabled")
    for w in c.get("warnings", []):
        log.emit("WARN", w["msg"], **w.get("fields", {}))
    if mode == "sleep":
        subprocess.Popen(["sleep", "120"])
        time.sleep(120)
    if mode == "nap":
        time.sleep(float(c.get("nap", 2)))
    if mode == "tool-deadline":
        log.emit(
            "WARN",
            "Provide a higher timeout value, see https://trivy.dev/docs/v0.76/guide/references/"
            "troubleshooting#timeout",
        )
        return log.fatal(
            "run error: fs scan error: scan error: scan failed: failed analysis: semaphore acquire: "
            "context deadline exceeded"
        )
    if mode == "exit1":
        return log.fatal("run error: unexpected failure")
    if mode == "write-component":
        for sub_ in ("db/trivy.db", "java-db/trivy-java.db", "policy/metadata.json"):
            p = os.path.join(cache, sub_)
            if os.path.exists(p):
                os.chmod(p, 0o644)
                with open(p, "ab") as handle:
                    handle.write(b"tampered")
                break
        if c.get("then") == "sleep":
            subprocess.Popen(["sleep", "120"])
            time.sleep(120)
        if c.get("then") == "exit1":
            return log.fatal("run error: unexpected failure after reading the database")
    if "vuln" in scanners:
        meta = os.path.join(cache, "db", "metadata.json")
        if mode == "first-run" or not os.path.isfile(meta):
            log.emit("ERROR", "[vulndb] The first run cannot skip downloading DB")
            return log.fatal(
                "run error: init error: DB error: database error: --skip-db-update cannot be "
                "specified on the first run"
            )
        if mode == "invalid-db" or open(os.path.join(cache, "db", "trivy.db"), "rb").read(7) == b"CORRUPT":
            return log.fatal(
                "run error: init error: DB error: error in vulnerability DB initialization: "
                "failed to open db: invalid database"
            )
    fallback = False
    if "misconfig" in scanners:
        log.emit(
            "INFO",
            "[checks-client] No downloadable checks were loaded as --skip-check-update is enabled, "
            "loading from existing cache...",
        )
        content = os.path.join(cache, "policy", "content")
        if mode == "fallback" or not (os.path.isdir(content) and os.listdir(content)):
            log.emit(
                "ERROR",
                "[misconfig] Falling back to embedded checks",
                err=f'failed to check cache: cache does not exist at "{content}"',
            )
            fallback = True
    doc = {"SchemaVersion": 2, "CreatedAt": now(), "ArtifactName": "", "ArtifactType": "filesystem"}
    results = []
    if sub == "image":
        archive = values["--input"][-1]
        doc.update(ArtifactName=archive, ArtifactType="container_image")
        need_java = os.path.isfile(os.path.join(cache, "java-db", "metadata.json"))
        img, code = image(archive, need_java, log)
        if img is None:
            return code
        doc["Metadata"] = img["Metadata"]
        results += img["Results"]
    else:
        root = positional[-1]
        doc["ArtifactName"] = root
        patterns = [tuple(p.split(":", 1)) for p in values.get("--file-patterns", [])]
        files = walk(root)
        lang = 0
        for rel, path in files:
            name = os.path.basename(rel)
            if "vuln" in scanners:
                if name == "pom.xml":
                    lang += 1
                    results.append(pom(rel, path, log))
                elif name == "requirements.txt":
                    lang += 1
                    results.append(pip(rel, path))
                elif name == "package-lock.json":
                    lang += 1
                    results.append(npm(rel, path))
            if "misconfig" in scanners:
                kind = misconf_type(rel, path, patterns)
                if kind:
                    log.emit("DEBUG", "Scanned config file", file_path=rel)
                    if mode != "debug-only-config":
                        results.append(misconf(rel, path, kind))
                    if kind == "terraform" and mode != "debug-only-config":
                        results.append(
                            {
                                "Target": ".",
                                "Class": "config",
                                "Type": "terraform",
                                "MisconfSummary": {"Successes": 69, "Failures": 0},
                            }
                        )
            if "secret" in scanners:
                if secret_skipped(rel) or binary(path):
                    continue
                log.emit("DEBUG", "[secret] Using streaming scanner", file_path=rel)
                if os.path.getsize(path) > 10 * 1024 * 1024:
                    log.emit(
                        "WARN",
                        "[secret] The size of the scanned file is too large. It is recommended to "
                        "use `--skip-files` for this file to avoid high memory consumption.",
                        file_path=rel,
                    )
                found = secrets(rel, path)
                if found:
                    results.append(found)
        if os.path.isdir(os.path.join(root, ".git")) and "secret" in scanners:
            log.emit("DEBUG", "Skipping path", path=".git")
        log.emit("INFO", "Number of language-specific files", num=lang)
        if "misconfig" in scanners:
            log.emit("INFO", "Detected config files", num=sum(1 for r in results if r["Class"] == "config"))
    if fallback:
        log.emit("DEBUG", "[rego] Embedded checks are loaded", count=563)
    elif "misconfig" in scanners:
        log.emit("DEBUG", "[rego] Checks from disk are loaded", count=580)
    if results:
        doc["Results"] = results
    if mode == "garbage":
        print("this is not json")
        return 0
    if mode == "empty":
        return 0
    if mode == "huge":
        sys.stdout.write(json.dumps(doc)[:-1] + ', "Pad": "' + "x" * (70 * 1024 * 1024) + '"}')
        return 0
    print(json.dumps(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
