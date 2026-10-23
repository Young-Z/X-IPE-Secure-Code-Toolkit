"""Loopback OCI registry for FEATURE-002-D acceptance (TASK-058). Harness only; never part of the toolkit.

DAO-002: the adapter's provisioning code path may be exercised only against fakes or a loopback registry that
needs no new download. This server impersonates mirror.gcr.io, ghcr.io and pkg-containers.githubusercontent.com
on a Docker --internal network (names mapped to it with --add-host in the client container, TLS with a
disposable test CA trusted only inside that disposable client container). It serves OCI artifacts rebuilt
from the components that were already fetched by the tool-level validation method (no new download).

  python3 registry.py build   # /cache (ro, fetched components) -> /oci (artifacts: blobs + manifests)
  python3 registry.py serve   # HTTPS :443; request log /reglog/requests.jsonl; control file /reglog/mode.json
                              #   {"refuse": [host...], "slow_bps": int, "variant": {"vulnerability_db": "old"}}
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import socket
import ssl
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CACHE, OCI, LOG, CERTS = Path("/cache"), Path("/oci"), Path("/reglog"), Path("/certs")
TYPES = {
    "vulnerability_db": ("application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", "db", "db.tar.gz"),
    "java_db": ("application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip", "java-db", "javadb.tar.gz"),
    "checks_bundle": ("application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", "policy/content", "bundle.tar.gz"),
}
REPOS = {
    ("mirror.gcr.io", "aquasec/trivy-db", "2"): "vulnerability_db",
    ("mirror.gcr.io", "aquasec/trivy-java-db", "1"): "java_db",
    ("mirror.gcr.io", "aquasec/trivy-checks", "2"): "checks_bundle",
    ("ghcr.io", "aquasecurity/trivy-db", "2"): "vulnerability_db",
    ("ghcr.io", "aquasecurity/trivy-java-db", "1"): "java_db",
    ("ghcr.io", "aquasecurity/trivy-checks", "2"): "checks_bundle",
}
BLOB_HOST = "pkg-containers.githubusercontent.com"
LOCK = threading.Lock()


def _blob(data_path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    with open(data_path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    digest = "sha256:" + h.hexdigest()
    final = OCI / "blobs" / digest.split(":")[1]
    os.replace(data_path, final)
    return digest, final.stat().st_size


def _layer(files: list[tuple[str, Path | bytes]]) -> Path:
    tmp = OCI / "tmp-layer"
    with open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as t:
            for name, src in files:
                if isinstance(src, bytes):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(src), 0o644, 0
                    t.addfile(info, io.BytesIO(src))
                else:
                    info = t.gettarinfo(str(src), arcname=name)
                    info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
                    with open(src, "rb") as f:
                        t.addfile(info, f)
    return tmp


def build() -> None:
    (OCI / "blobs").mkdir(parents=True, exist_ok=True)
    cfg = OCI / "tmp-config"
    cfg.write_bytes(b"{}")
    cdigest, csize = _blob(cfg)
    index = {}
    for comp, (mtype, sub, title) in TYPES.items():
        base = CACHE / sub
        files = sorted(p for p in base.rglob("*") if p.is_file())
        variants = {"current": [(str(p.relative_to(base)), p) for p in files]}
        if comp == "vulnerability_db":  # outdated by its own metadata (AC-002D-04c); same database file
            meta = json.loads((base / "metadata.json").read_text())
            meta.update(UpdatedAt="2019-05-01T00:00:00Z", NextUpdate="2019-05-02T00:00:00Z")
            variants["old"] = [(n, (json.dumps(meta).encode() if n == "metadata.json" else p)) for n, p in variants["current"]]
        for variant, members in variants.items():
            t = time.time()
            ldigest, lsize = _blob(_layer(members))
            manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {"mediaType": "application/vnd.aquasec.trivy.config.v1+json", "digest": cdigest,
                                   "size": csize},
                        "layers": [{"mediaType": mtype, "digest": ldigest, "size": lsize,
                                    "annotations": {"org.opencontainers.image.title": title}}],
                        "annotations": {"org.opencontainers.image.description": f"FAT-002D loopback rebuild ({variant})",
                                        **({"org.opencontainers.image.version": "2.0.0"} if comp == "checks_bundle" else {})}}
            body = json.dumps(manifest, separators=(",", ":")).encode()
            mdigest = "sha256:" + hashlib.sha256(body).hexdigest()
            (OCI / "manifests").mkdir(exist_ok=True)
            (OCI / "manifests" / f"{comp}-{variant}.json").write_bytes(body)
            index[f"{comp}-{variant}"] = {"manifest_digest": mdigest, "layer_digest": ldigest, "layer_size": lsize,
                                          "members": len(members), "seconds": round(time.time() - t, 1)}
            print(json.dumps({"case": "oci-build", "artifact": f"{comp}-{variant}", **index[f"{comp}-{variant}"]}), flush=True)
    (OCI / "index.json").write_text(json.dumps(index, indent=1))


def _mode() -> dict:
    try:
        return json.loads((LOG / "mode.json").read_text())
    except (OSError, ValueError):
        return {}


def _log(entry: dict) -> None:
    entry["t"] = round(time.time(), 3)
    with LOCK, open(LOG / "requests.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fat2d-loopback"

    def log_message(self, *args):  # noqa: D401 - silence default stderr logging
        pass

    def _send(self, status: int, body: bytes = b"", headers: dict | None = None, path: Path | None = None) -> None:
        size = path.stat().st_size if path else len(body)
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(size))
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        self.end_headers()
        sent = 0
        if self.command != "HEAD":
            if path:
                bps = int(_mode().get("slow_bps") or 0)
                with open(path, "rb") as f:
                    while chunk := f.read(65536 if bps else 1 << 20):
                        self.wfile.write(chunk)
                        sent += len(chunk)
                        if bps:
                            time.sleep(len(chunk) / bps)
            else:
                self.wfile.write(body)
                sent = len(body)
        _log({"sni": getattr(self.connection, "fat_sni", None), "host": self.headers.get("Host"),
              "method": self.command, "path": self.path, "status": status, "bytes": sent,
              "client": self.client_address[0]})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        path = self.path.split("?")[0]
        if path in ("/v2/", "/v2"):
            return self._send(200, b"{}", {"Content-Type": "application/json"})
        if host == BLOB_HOST and path.startswith("/ghcr1/blobs/sha256:"):
            blob = OCI / "blobs" / path.rsplit(":", 1)[1]
            return self._send(200, path=blob, headers={"Content-Type": "application/octet-stream"}) if blob.is_file() \
                else self._send(404)
        if path.startswith("/v2/") and "/manifests/" in path:
            name, ref = path[4:].split("/manifests/", 1)
            comp = REPOS.get((host, name, ref))
            if comp is None:
                return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}', {"Content-Type": "application/json"})
            variant = (_mode().get("variant") or {}).get(comp, "current")
            body = (OCI / "manifests" / f"{comp}-{variant}.json").read_bytes()
            return self._send(200, body, {"Content-Type": "application/vnd.oci.image.manifest.v1+json",
                                          "Docker-Content-Digest": "sha256:" + hashlib.sha256(body).hexdigest()})
        if path.startswith("/v2/") and "/blobs/sha256:" in path:
            name, digest = path[4:].split("/blobs/", 1)
            if not any(h == host and n == name for h, n, _ in REPOS):
                return self._send(404)
            blob = OCI / "blobs" / digest.split(":", 1)[1]
            if not blob.is_file():
                return self._send(404)
            if host == "ghcr.io":  # like the real registry: blobs are served by its blob host
                return self._send(307, headers={"Location": f"https://{BLOB_HOST}/ghcr1/blobs/{digest}"})
            return self._send(200, path=blob, headers={"Content-Type": "application/octet-stream"})
        return self._send(404)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def finish_request(self, request, client_address):
        holder = {}

        def sni(sock, name, _ctx):
            holder["sni"] = name
            refused = name in (_mode().get("refuse") or [])
            _log({"event": "tls_hello", "sni": name, "client": client_address[0], "refused": refused})
            if refused:
                return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
            return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERTS / "leaf.pem", CERTS / "leaf.key")
        ctx.sni_callback = sni
        try:
            tls = ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            _log({"event": "tls_failed", "sni": holder.get("sni"), "client": client_address[0], "error": type(exc).__name__})
            return
        tls.fat_sni = holder.get("sni")
        try:
            super().finish_request(tls, client_address)
        except (ConnectionError, ssl.SSLError, OSError):
            pass


def serve() -> None:
    LOG.mkdir(parents=True, exist_ok=True)
    srv = Server(("0.0.0.0", 443), Handler)
    print("loopback registry listening on :443", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    {"build": build, "serve": serve}[sys.argv[1]]()
