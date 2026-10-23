"""TASK-058 tool-level download (DAO-002: Trivy tool-level validation under the human's existing
authorization; disposable container only). NOT the implemented adapter.

  python3 fetch.py binaries    # /tv volume: official v0.76.1 Linux archives + checksums, digests verified, binaries extracted
  python3 fetch.py components  # /cache volume: vulnerability DB, Java DB, checks bundle from mirror.gcr.io with the
                               # validated provisioning argv of tool-validation/README.md (one repository each)
Prints JSON lines only.
"""
import hashlib, json, os, shutil, subprocess, sys, tarfile, time, urllib.request
from pathlib import Path

VERSION = "0.76.1"
REL = f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}"
API = f"https://api.github.com/repos/aquasecurity/trivy/releases/tags/v{VERSION}"
OFFICIAL = {  # tool-validation/README.md "Official Release Digests" (release metadata + checksums.txt)
    "trivy_0.76.1_checksums.txt": "885debc41b570179e81af560e5f393a66be29b9ff8c52915674f3eb2304c535d",
    "trivy_0.76.1_Linux-ARM64.tar.gz": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    "trivy_0.76.1_Linux-64bit.tar.gz": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
}
BINARIES = {"ARM64": "b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85",
            "64bit": "d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83"}
TV, CACHE = Path("/tv"), Path("/cache")
COMMON = ["--skip-version-check", "--disable-telemetry", "--no-progress"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def emit(rec):
    print(json.dumps(rec), flush=True)


def binaries():
    TV.mkdir(parents=True, exist_ok=True)
    meta = json.loads(urllib.request.urlopen(urllib.request.Request(API, headers={"User-Agent": "fat-002d"})).read())
    release = {a["name"]: (a.get("digest") or "").removeprefix("sha256:") for a in meta.get("assets", [])}
    emit({"case": "release-metadata", "tag": meta.get("tag_name"), "published_at": meta.get("published_at"),
          "assets_with_digest": sorted(n for n in release if n in OFFICIAL)})
    for name, want in OFFICIAL.items():
        dst = TV / name
        urllib.request.urlretrieve(f"{REL}/{name}", dst)
        got = sha(dst)
        rec = {"case": "download", "asset": name, "size": dst.stat().st_size, "sha256": got,
               "official_digest_match": got == want, "release_metadata_match": release.get(name) == got}
        if name.endswith(".tar.gz"):
            listed = {l.split()[1]: l.split()[0] for l in (TV / "trivy_0.76.1_checksums.txt").read_text().splitlines() if l.strip()}
            rec["checksums_txt_match"] = listed.get(name) == got
            arch = name.split("_")[-1].split(".")[0].replace("Linux-", "")
            out = TV / arch
            out.mkdir(exist_ok=True)
            with tarfile.open(dst) as t:
                t.extract("trivy", out, filter="data")
            b = out / "trivy"
            b.chmod(0o755)
            rec["binary"] = {"path": str(b), "sha256": sha(b), "size": b.stat().st_size,
                             "official_binary_match": sha(b) == BINARIES[arch]}
        emit(rec)


def provision_argv(component, repo, op):
    cache = ["--cache-dir", str(op / "cache"), "--timeout", "1800s"]
    if component == "vulnerability_db":
        return ["image", "--download-db-only", "--db-repository", repo, *COMMON, *cache]
    if component == "java_db":
        return ["image", "--download-java-db-only", "--java-db-repository", repo, *COMMON, *cache]
    (op / "empty").mkdir(parents=True, exist_ok=True)
    return ["fs", "--scanners", "misconfig", "--checks-bundle-repository", repo, "--skip-db-update",
            "--skip-java-db-update", "--offline-scan", *COMMON, "--format", "json", *cache, str(op / "empty")]


def components():
    binary = TV / ("ARM64" if os.uname().machine in ("aarch64", "arm64") else "64bit") / "trivy"
    assert sha(binary) in BINARIES.values()
    for d in ("/work/home", "/work/tmp"):
        Path(d).mkdir(parents=True, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "TMPDIR": "/work/tmp", "TZ": "UTC"}
    repos = {"vulnerability_db": ("mirror.gcr.io/aquasec/trivy-db:2", "db"),
             "java_db": ("mirror.gcr.io/aquasec/trivy-java-db:1", "java-db"),
             "checks_bundle": ("mirror.gcr.io/aquasec/trivy-checks:2", "policy")}
    for comp, (repo, sub) in repos.items():
        op = CACHE / "_ops" / comp
        (op / "cache").mkdir(parents=True, exist_ok=True)
        argv = [str(binary), *provision_argv(comp, repo, op)]
        t = time.time()
        p = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=3600)
        files = sorted(str(x.relative_to(op / "cache")) for x in (op / "cache").rglob("*") if x.is_file())
        emit({"case": f"tool-level-download-{comp}", "argv_after_trivy": argv[1:], "exit": p.returncode,
              "seconds": round(time.time() - t, 1), "files": len(files),
              "fallback_line": "Falling back to embedded checks" in p.stderr,
              "stderr_tail": p.stderr[-600:]})
        if (CACHE / sub).exists():
            shutil.rmtree(CACHE / sub)
        os.rename(op / "cache" / sub, CACHE / sub)
    shutil.rmtree(CACHE / "_ops")
    for meta in ("db/metadata.json", "java-db/metadata.json", "policy/metadata.json"):
        emit({"case": "metadata", "file": meta, "content": json.loads((CACHE / meta).read_text())})
    sizes = {}
    for sub in ("db", "java-db", "policy"):
        fs = [x for x in (CACHE / sub).rglob("*") if x.is_file()]
        sizes[sub] = {"files": len(fs), "bytes": sum(x.stat().st_size for x in fs)}
    emit({"case": "assembled", "sizes": sizes,
          "digests": {r: sha(CACHE / r) for r in ("db/trivy.db", "db/metadata.json", "java-db/trivy-java.db",
                                                   "java-db/metadata.json", "policy/metadata.json")}})


if __name__ == "__main__":
    {"binaries": binaries, "components": components}[sys.argv[1]]()
