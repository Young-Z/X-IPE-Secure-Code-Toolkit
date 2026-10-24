"""B17 download (human item B17 = A): the official Trivy v0.76.1 linux/arm64 release archive from GitHub, inside a
disposable container, into the disposable volume mounted at /tv. Only this one asset is fetched (no API call, no
checksums file, no x86-64 asset). The archive digest is compared with the pinned value BEFORE extraction and the
extracted binary digest BEFORE anything may execute it; any mismatch deletes the files and exits 3.
Prints JSON lines only.
"""
import hashlib
import json
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

URL = "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-ARM64.tar.gz"
ARCHIVE_SHA = "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"  # tool-validation + digests.TRIVY
BINARY_SHA = "b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85"
TV = Path("/tv")


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def emit(rec: dict) -> None:
    print(json.dumps(rec), flush=True)


def main() -> int:
    TV.mkdir(parents=True, exist_ok=True)
    dst = TV / "trivy_0.76.1_Linux-ARM64.tar.gz"
    t = time.time()
    req = urllib.request.Request(URL, headers={"User-Agent": "fat-002d-b17"})
    with urllib.request.urlopen(req) as r, open(dst, "wb") as f:
        final_url = r.geturl()
        while chunk := r.read(1 << 20):
            f.write(chunk)
    got = sha(dst)
    rec = {"case": "download", "url": URL, "final_host": final_url.split("/")[2], "size": dst.stat().st_size,
           "sha256": got, "pinned_archive_sha256": ARCHIVE_SHA, "archive_match": got == ARCHIVE_SHA,
           "seconds": round(time.time() - t, 1)}
    emit(rec)
    if got != ARCHIVE_SHA:
        dst.unlink()
        emit({"case": "abort", "reason": "archive digest mismatch; nothing extracted or executed"})
        return 3
    out = TV / "ARM64"
    out.mkdir(exist_ok=True)
    with tarfile.open(dst) as tf:
        tf.extract("trivy", out, filter="data")
    b = out / "trivy"
    bsha = sha(b)
    emit({"case": "extract", "path": str(b), "size": b.stat().st_size, "sha256": bsha,
          "pinned_binary_sha256": BINARY_SHA, "binary_match": bsha == BINARY_SHA})
    if bsha != BINARY_SHA:
        b.unlink()
        emit({"case": "abort", "reason": "binary digest mismatch; binary deleted, never executed"})
        return 3
    b.chmod(0o755)
    return 0


if __name__ == "__main__":
    sys.exit(main())
