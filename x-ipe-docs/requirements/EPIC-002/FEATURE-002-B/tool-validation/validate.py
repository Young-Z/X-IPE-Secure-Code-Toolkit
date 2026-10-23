"""S-07 tool-level validation of Opengrep (FEATURE-002-B, TASK-027). Runs inside a disposable container.

  python3 validate.py download   # online: fetch the official release binary into /og (volume)
  python3 validate.py run        # offline (--network none): scans on the MVP samples, prints JSON lines
"""
import hashlib, json, os, resource, subprocess, sys, time, urllib.request
from pathlib import Path

VERSION = "v1.31.0"
ARCH = "aarch64" if os.uname().machine in ("aarch64", "arm64") else "x86"
ASSET = f"opengrep_manylinux_{ARCH}"
BIN = Path("/og/opengrep")
SAMPLES = Path("/samples")
HERE = Path(__file__).resolve().parent


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def tree(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(Path(root).rglob("*")) if p.is_file() and not p.is_symlink()}


def download():
    url = f"https://github.com/opengrep/opengrep/releases/download/{VERSION}/{ASSET}"
    BIN.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, BIN)
    for ext in (".sig", ".cert"):
        urllib.request.urlretrieve(url + ext, str(BIN) + ext)
    BIN.chmod(0o755)
    print(json.dumps({"asset": ASSET, "url": url, "sha256": sha(BIN), "size": BIN.stat().st_size}))


def run(name, args, cwd=None):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.time()
    proc = subprocess.run([str(BIN), *args], capture_output=True, text=True, cwd=cwd, timeout=1800)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    rec = {"case": name, "args": args, "exit": proc.returncode, "seconds": round(time.time() - start, 2),
           "cpu_seconds": round((after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), 2),
           "max_rss_mb": round(after.ru_maxrss / 1024, 1), "stderr_tail": proc.stderr[-600:]}
    try:
        out = json.loads(proc.stdout)
        rec["json_keys"] = sorted(out)
        rec["results"] = [{"check_id": r["check_id"], "path": r["path"], "line": r["start"]["line"],
                           "severity": r["extra"].get("severity"), "cwe": r["extra"].get("metadata", {}).get("cwe")}
                          for r in out.get("results", [])]
        rec["errors"] = [{k: e.get(k) for k in ("type", "level", "message", "path")} for e in out.get("errors", [])]
        rec["paths_scanned"] = len(out.get("paths", {}).get("scanned", []))
        rec["version_in_output"] = out.get("version")
        rec["sample_result_keys"] = sorted(out["results"][0]) if out.get("results") else []
        rec["sample_extra_keys"] = sorted(out["results"][0]["extra"]) if out.get("results") else []
    except (ValueError, KeyError) as exc:
        rec["stdout_head"] = proc.stdout[:400]
        rec["parse_error"] = str(exc)
    print(json.dumps(rec), flush=True)
    return rec


def main():
    if sys.argv[1] == "download":
        return download()
    home_before = set(os.listdir(Path.home()))
    sample_hash = {s: tree(SAMPLES / s) for s in ("shanghai-marathon-registration", "WebGoat")}
    v = subprocess.run([str(BIN), "--version"], capture_output=True, text=True)
    print(json.dumps({"case": "version", "exit": v.returncode, "stdout": v.stdout.strip(), "binary_sha256": sha(BIN)}))
    common = ["scan", "--json", "--disable-version-check"]
    run("marathon-python-rules", [*common, "--config", str(HERE / "rules"), str(SAMPLES / "shanghai-marathon-registration")])
    run("webgoat-java-rules", [*common, "--config", str(HERE / "rules"), str(SAMPLES / "WebGoat/src")])
    run("missing-rules-path", [*common, "--config", "/nope/rules.yaml", str(SAMPLES / "shanghai-marathon-registration")])
    run("invalid-rule-file", [*common, "--config", str(HERE / "rules-invalid.yaml"), str(SAMPLES / "shanghai-marathon-registration")])
    run("missing-target", [*common, "--config", str(HERE / "rules"), "/nope/target"])
    run("no-config-given", ["scan", "--json", "--disable-version-check", str(SAMPLES / "shanghai-marathon-registration")])
    run("registry-config-offline", [*common, "--config", "p/default", str(SAMPLES / "shanghai-marathon-registration")])
    run("timeout-flag", [*common, "--timeout", "1", "--config", str(HERE / "rules"), str(SAMPLES / "WebGoat/src")])
    unchanged = {s: tree(SAMPLES / s) == h for s, h in sample_hash.items()}
    print(json.dumps({"case": "side-effects", "samples_unchanged": unchanged,
                      "new_home_entries": sorted(set(os.listdir(Path.home())) - home_before)}))
    h = subprocess.run([str(BIN), "scan", "--help"], capture_output=True, text=True)
    print(json.dumps({"case": "scan-help-options", "options": sorted({w.split("=")[0] for w in h.stdout.split() if w.startswith("--")})}))


if __name__ == "__main__":
    main()
