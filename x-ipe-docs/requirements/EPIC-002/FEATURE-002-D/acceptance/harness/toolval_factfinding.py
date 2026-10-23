"""TASK-058 tool-level fact-finding (DAO-002: Trivy tool-level validation, offline, disposable containers, never the
implemented adapter). Prints JSON lines. Volumes: /tv (binaries, ro), /cache (fetched components, ro).

  python3 ff.py help       # FF-01 misconfiguration types of v0.76.1 (--help), compared with the toolkit text
  python3 ff.py tf         # FF-02 clean / module-only .tf results
  python3 ff.py rehash     # FF-03 re-hash timing (run once after a VM page-cache drop, then warm)
  python3 ff.py x86        # FF-04 (inside an emulated linux/amd64 container): version + small offline scan
"""
import hashlib, json, os, re, subprocess, sys, time
from pathlib import Path

CACHE = Path("/cache")
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "TMPDIR": "/work/tmp", "TZ": "UTC"}
OFFLINE = ["--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan",
           "--skip-version-check", "--disable-telemetry", "--no-progress"]


def emit(rec):
    print(json.dumps(rec), flush=True)


def binary():
    return os.environ.get("TRIVY_BIN", "/tv/ARM64/trivy")


def run(args, timeout=600):
    for d in ("/work/home", "/work/tmp"):
        Path(d).mkdir(parents=True, exist_ok=True)
    t = time.time()
    p = subprocess.run([binary(), *args], capture_output=True, text=True, env=ENV, timeout=timeout)
    return p.returncode, p.stdout, p.stderr, round(time.time() - t, 2)


def help_types():
    for sub in ("fs", "config", "image"):
        code, out, err, _ = run([sub, "--help"])
        m = re.search(r"--misconfig-scanners strings\s+(.*?)\(default \[([^\]]*)\]\)", out, re.S)
        emit({"case": f"help-{sub}", "exit": code, "misconfig_scanners_default": m.group(2).split(",") if m else None,
              "description": " ".join(m.group(1).split()) if m else None})
    code, out, err, _ = run(["fs", "--help"])
    m = re.search(r"--file-patterns strings\s+(.*?)\n\s+--", out, re.S)
    emit({"case": "help-fs-file-patterns", "text": " ".join(m.group(1).split()) if m else None})
    src = Path("/toolkit/x-ipe-secure-code-toolkit-framework/scripts/src/x_ipe_secure_code/adapters/trivy.py")
    if src.exists():
        text = src.read_text()
        m = re.search(r"CONFIG_TYPES\s*=\s*(\([^)]*\)|frozenset\([^)]*\)|\{[^}]*\}|\[[^\]]*\])", text, re.S)
        emit({"case": "toolkit-CONFIG_TYPES-source-text", "text": " ".join(m.group(1).split()) if m else None})


TF = {
    "variable-only.tf": 'variable "region" {\n  type    = string\n  default = "eu-west-1"\n}\n',
    "locals-output.tf": 'locals {\n  name = "demo"\n}\n\noutput "name" {\n  value = local.name\n}\n',
    "secure-bucket.tf": (
        'resource "aws_s3_bucket" "b" {\n  bucket = "fat-demo-bucket"\n}\n\n'
        'resource "aws_s3_bucket_public_access_block" "b" {\n  bucket                  = aws_s3_bucket.b.id\n'
        '  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n'
        '  restrict_public_buckets = true\n}\n\n'
        'resource "aws_s3_bucket_versioning" "b" {\n  bucket = aws_s3_bucket.b.id\n  versioning_configuration {\n'
        '    status = "Enabled"\n  }\n}\n\n'
        'resource "aws_kms_key" "k" {\n  enable_key_rotation = true\n}\n\n'
        'resource "aws_s3_bucket_server_side_encryption_configuration" "b" {\n  bucket = aws_s3_bucket.b.id\n'
        '  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm     = "aws:kms"\n'
        '      kms_master_key_id = aws_kms_key.k.arn\n    }\n  }\n}\n\n'
        'resource "aws_s3_bucket_logging" "b" {\n  bucket        = aws_s3_bucket.b.id\n'
        '  target_bucket = aws_s3_bucket.b.id\n  target_prefix = "log/"\n}\n'),
    "failing-bucket.tf": 'resource "aws_s3_bucket" "demo" {\n  bucket = "demo-bucket"\n  acl    = "public-read"\n}\n',
}


def tf():
    base = Path("/work/tf")
    for name, body in TF.items():
        d = base / name.removesuffix(".tf")
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(body)
        code, out, err, secs = run(["fs", "--scanners", "misconfig", *OFFLINE, "--format", "json", "--debug",
                                    "--config", "", "--ignorefile", "", "--secret-config", "",
                                    "--cache-dir", str(CACHE), str(d)])
        doc = json.loads(out) if out.strip().startswith("{") else {}
        results = [{"Target": r.get("Target"), "Class": r.get("Class"), "Type": r.get("Type"),
                    "MisconfSummary": r.get("MisconfSummary"),
                    "failures": [m.get("ID") for m in r.get("Misconfigurations") or [] if m.get("Status") == "FAIL"]}
                   for r in doc.get("Results") or []]
        scanned = [l.split("\t")[-1] for l in err.splitlines() if "Scanned config file" in l]
        emit({"case": f"tf-{name}", "exit": code, "seconds": secs, "results": results,
              "debug_scanned_config_file_lines": scanned,
              "fallback": "Falling back to embedded checks" in err})


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def rehash():
    comps = {"vulnerability_db": ["db/trivy.db", "db/metadata.json"],
             "java_db": ["java-db/trivy-java.db", "java-db/metadata.json"],
             "checks_bundle": sorted(str(p.relative_to(CACHE)) for p in (CACHE / "policy").rglob("*") if p.is_file())}
    label = os.environ.get("FF_LABEL", "pass")
    rec = {"case": f"rehash-{label}", "components": {}}
    for comp, files in comps.items():
        t = time.time()
        size = 0
        for rel in files:
            sha(CACHE / rel)
            size += (CACHE / rel).stat().st_size
        secs = time.time() - t
        rec["components"][comp] = {"files": len(files), "bytes": size, "seconds": round(secs, 2),
                                   "MB_per_s": round(size / 1e6 / secs, 1) if secs else None}
    emit(rec)


def x86():
    code, out, err, secs = run(["--version", "--format", "json"])
    emit({"case": "x86-version", "machine": os.uname().machine, "exit": code, "seconds": secs,
          "version": (json.loads(out) if out.strip().startswith("{") else {}).get("Version"),
          "stderr_tail": err[-300:]})
    d = Path("/work/fx")
    d.mkdir(parents=True, exist_ok=True)
    (d / "requirements.txt").write_text("requests==2.19.0\n")
    (d / "Dockerfile").write_text("FROM alpine:3.10\nRUN apk add curl\n")
    for scanners in ("vuln", "misconfig"):
        code, out, err, secs = run(["fs", "--scanners", scanners, *OFFLINE, "--format", "json", "--cache-dir",
                                    str(CACHE), str(d)])
        doc = json.loads(out) if out.strip().startswith("{") else {}
        emit({"case": f"x86-fs-{scanners}", "exit": code, "seconds": secs,
              "results": [{"Target": r.get("Target"), "Class": r.get("Class"),
                           "vulnerabilities": len(r.get("Vulnerabilities") or []),
                           "misconf": r.get("MisconfSummary")} for r in doc.get("Results") or []],
              "stderr_tail": err[-300:] if code else ""})


if __name__ == "__main__":
    {"help": help_types, "tf": tf, "rehash": rehash, "x86": x86}[sys.argv[1]]()
