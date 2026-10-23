"""Synthetic tar archives for FEATURE-002-D tests (no `tarfile` writer: malformed members must be possible).

`docker_save()` builds a `docker save` archive (classic or Docker >= 25 layout with OCI members) whose
config carries a `fake_trivy` description read by `fake_trivy.py`. `member()`, `pax()` and `gnu_long()`
build raw 512-byte ustar headers so tests can create every refused structure of AC-002D-03h.
"""

from __future__ import annotations

import hashlib
import json

BLOCK = 512


def _octal(value: int, width: int) -> bytes:
    return (f"%0{width - 1}o" % value).encode() + b"\0"


def header(
    name: str | bytes,
    size: int = 0,
    typeflag: bytes = b"0",
    linkname: str = "",
    mode: int = 0o644,
    *,
    bad_checksum: bool = False,
    base256_size: bool = False,
    magic: bytes = b"ustar\x0000",
) -> bytes:
    raw_name = name if isinstance(name, bytes) else name.encode("utf-8")
    h = bytearray(BLOCK)
    h[0:100] = raw_name[:100].ljust(100, b"\0")
    h[100:108] = _octal(mode, 8)
    h[108:116] = _octal(0, 8)
    h[116:124] = _octal(0, 8)
    if base256_size:
        h[124:136] = b"\x80" + size.to_bytes(11, "big")
    else:
        h[124:136] = _octal(size, 12)
    h[136:148] = _octal(1700000000, 12)
    h[148:156] = b" " * 8
    h[156:157] = typeflag
    h[157:257] = linkname.encode()[:100].ljust(100, b"\0")
    h[257:265] = magic
    checksum = sum(h) + (1 if bad_checksum else 0)
    h[148:156] = f"{checksum:06o}".encode() + b"\0 "
    return bytes(h)


def _pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % BLOCK)


def member(name: str | bytes, data: bytes = b"", typeflag: bytes = b"0", linkname: str = "", **kw) -> bytes:
    size = len(data) if typeflag in (b"0", b"\0", b"x", b"g", b"L", b"K", b"7", b"S") else 0
    return header(name, kw.pop("size", size), typeflag, linkname, **kw) + _pad(data)


def directory(name: str) -> bytes:
    return member(name if name.endswith("/") else name + "/", typeflag=b"5", mode=0o755)


def pax(records: dict[str, str], *, global_: bool = False, raw: bytes | None = None) -> bytes:
    body = raw if raw is not None else b"".join(_pax_record(k, v) for k, v in records.items())
    return member("pax_global_header" if global_ else "PaxHeaders/x", body, b"g" if global_ else b"x")


def _pax_record(key: str, value: str) -> bytes:
    payload = f" {key}={value}\n".encode()
    length = len(payload) + 1
    while len(str(length).encode()) + len(payload) != length:
        length = len(str(length).encode()) + len(payload)
    return str(length).encode() + payload


def gnu_long(name: str, *, link: bool = False) -> bytes:
    return member("././@LongLink", name.encode() + b"\0", b"K" if link else b"L")


def end() -> bytes:
    return b"\0" * (2 * BLOCK)


def archive(*parts: bytes, trailer: bool = True) -> bytes:
    return b"".join(parts) + (end() if trailer else b"")


def layer_tar(files: dict[str, bytes]) -> bytes:
    return archive(*(member(n, d) for n, d in files.items()))


def docker_save(
    *,
    os_info: dict | None = None,
    packages: list | None = None,
    jar: bool = False,
    docker25: bool = False,
    repo_tag: str = "demo:latest",
    extra: tuple[bytes, ...] = (),
    manifest_override: object = None,
) -> bytes:
    """A small `docker save` archive; `docker25` adds `oci-layout`, `index.json` and `blobs/`."""
    layer = layer_tar({"app/wrapper.jar" if jar else "etc/os-release": b"fake layer\n"})
    config = {
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]},
        "fake_trivy": {"os": os_info, "packages": packages or [], "jar": jar},
    }
    config_bytes = json.dumps(config).encode()
    chex, lhex = hashlib.sha256(config_bytes).hexdigest(), hashlib.sha256(layer).hexdigest()
    parts = []
    if docker25:
        cname, lname = f"blobs/sha256/{chex}", f"blobs/sha256/{lhex}"
        index = {"schemaVersion": 2, "manifests": [{"digest": "sha256:" + chex}]}
        parts += [
            directory("blobs"),
            directory("blobs/sha256"),
            member(cname, config_bytes),
            member(lname, layer),
            member("index.json", json.dumps(index).encode()),
            member("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'),
        ]
    else:
        cname, lname = f"{chex}.json", f"{lhex}/layer.tar"
        parts += [member(cname, config_bytes), directory(lhex), member(lname, layer)]
        parts.append(member("repositories", json.dumps({"demo": {"latest": lhex}}).encode()))
    manifest = (
        manifest_override
        if manifest_override is not None
        else [{"Config": cname, "RepoTags": [repo_tag], "Layers": [lname]}]
    )
    parts.append(member("manifest.json", json.dumps(manifest).encode()))
    return archive(*parts, *extra)


def oci_only() -> bytes:
    """A pure OCI layout archive (no `docker save` manifest.json)."""
    blob = b'{"schemaVersion": 2}'
    return archive(
        directory("blobs"),
        directory("blobs/sha256"),
        member("blobs/sha256/" + hashlib.sha256(blob).hexdigest(), blob),
        member("index.json", b'{"schemaVersion": 2, "manifests": []}'),
        member("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'),
    )
