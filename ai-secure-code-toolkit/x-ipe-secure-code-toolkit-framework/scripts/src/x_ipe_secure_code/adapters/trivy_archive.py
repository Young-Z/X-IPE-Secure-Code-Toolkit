"""Bounded `docker save` archive validation (FEATURE-002-D, AC-002D-03c/03g/03h).

Reads only through the given (no-follow) descriptor with `os.pread`; never extracts anything. Extension
headers (`x` pax per-file, `L` GNU long name) are applied to the next member exactly as a POSIX consumer
applies them; global pax headers, links, devices, FIFOs, sparse and other special members are refused.
"""

from __future__ import annotations

import bisect
import json
import os
from dataclasses import dataclass

MAX_ARCHIVE = 8 * 1024**3
MAX_MEMBERS = 100_000
MAX_PAX = 64 * 1024
MAX_LONG_NAME = 4 * 1024
MAX_MANIFEST = 1024 * 1024
BLOCK = 512
PAX_KEYS = {"path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname", "comment"}
COMPRESSED = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")
OCI_MEMBERS = ("oci-layout", "index.json")
STEP = "Pass an explicitly declared `docker save` .tar file target of at most 8 GiB"


@dataclass(frozen=True)
class ArchiveInfo:
    members: int
    manifest_entries: int
    layers: int
    config: str

    def to_dict(self) -> dict:
        return {
            "members": self.members,
            "manifest_entries": self.manifest_entries,
            "layers": self.layers,
            "config": self.config,
        }


@dataclass(frozen=True)
class ArchiveError:
    code: str
    reason: str


class _Bad(Exception):
    pass


def _read(fd: int, size: int, offset: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = os.pread(fd, size - len(data), offset + len(data))
        if not chunk:
            break
        data += chunk
    return data


def _octal(field: bytes, what: str) -> int:
    if field[:1] and field[0] & 0x80:
        raise _Bad(f"base-256 {what} field not supported")
    text = field.replace(b"\0", b" ").strip()
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        raise _Bad(f"invalid {what} field") from None


def _checksum(block: bytes, offset: int) -> None:
    stored = _octal(block[148:156], "checksum")
    computed = sum(block[:148]) + 32 * 8 + sum(block[156:])
    if stored != computed:
        raise _Bad(f"header checksum mismatch at offset {offset}")


def clean_name(raw: str, *, directory: bool = False) -> str:
    """POSIX-clean relative member name (one trailing `/` allowed for folders); raises _Bad otherwise."""
    if raw == "":
        raise _Bad("empty member name")
    if "\0" in raw or "\\" in raw:
        raise _Bad(f"member name {raw} has a NUL or backslash")
    if raw.startswith("/"):
        raise _Bad(f"absolute member name {raw}")
    name = raw[:-1] if directory and raw.endswith("/") else raw
    if any(seg in ("", ".", "..") for seg in name.split("/")):
        raise _Bad(f"member name {raw} has an empty, '.' or '..' segment")
    return name


def _pax(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0 or not data[pos:space].isdigit():
            raise _Bad("malformed pax record")
        length = int(data[pos:space])
        record = data[pos : pos + length]
        if (
            length <= space - pos + 1
            or len(record) != length
            or not record.endswith(b"\n")
            or b"=" not in record
        ):
            raise _Bad("malformed pax record")
        key, _, value = record[space - pos + 1 : -1].partition(b"=")
        try:
            key_s, value_s = key.decode("utf-8"), value.decode("utf-8")
        except UnicodeError:
            raise _Bad("malformed pax record (not UTF-8)") from None
        if key_s not in PAX_KEYS:
            raise _Bad(f"pax key {key_s} not supported")
        out[key_s] = value_s
        pos += length
    return out


def _members(fd: int, size: int) -> dict[str, tuple[str, int, int]]:
    """name -> (type 'file'|'dir', data offset, data size) for every member, validating the stream."""
    members: dict[str, tuple[str, int, int]] = {}
    offset, pending = 0, None
    while True:
        if offset + BLOCK > size:
            raise _Bad("truncated archive: end-of-archive blocks missing")
        block = _read(fd, BLOCK, offset)
        if block == b"\0" * BLOCK:
            if _read(fd, BLOCK, offset + BLOCK) != b"\0" * BLOCK:
                raise _Bad("truncated archive: single zero block")
            if pending is not None:
                raise _Bad("pax or long-name header not followed by a member")
            pos = offset + 2 * BLOCK
            while pos < size:
                chunk = _read(fd, min(CHUNK_TAIL, size - pos), pos)
                if chunk.strip(b"\0"):
                    raise _Bad("data after the end of the archive")
                pos += len(chunk)
            return members
        _checksum(block, offset)
        member_size = _octal(block[124:136], "size")
        typeflag = block[156:157]
        data_offset = offset + BLOCK
        if typeflag in (b"x", b"L"):
            if pending is not None:
                raise _Bad("two extension headers for one member")
            limit = MAX_PAX if typeflag == b"x" else MAX_LONG_NAME
            if member_size > limit:
                raise _Bad(
                    "pax header larger than 64 KiB" if typeflag == b"x" else "long name larger than 4 KiB"
                )
            if data_offset + member_size > size:
                raise _Bad("truncated extension header")
            data = _read(fd, member_size, data_offset)
            pending = (
                _pax(data)
                if typeflag == b"x"
                else {"path": data.split(b"\0", 1)[0].decode("utf-8", "strict")}
            )
            offset = data_offset + _padded(member_size)
            continue
        if typeflag == b"g":
            raise _Bad("global pax header not supported")
        raw_name = block[0:100].split(b"\0", 1)[0]
        prefix = block[345:500].split(b"\0", 1)[0] if block[257:262] == b"ustar" else b""
        if typeflag in (b"1", b"2"):
            raise _Bad(f"link member not allowed: {raw_name.decode('utf-8', 'replace')}")
        if typeflag in (b"3", b"4", b"6", b"7"):
            raise _Bad(
                f"special member not allowed (device, FIFO or contiguous file): "
                f"{raw_name.decode('utf-8', 'replace')}"
            )
        if typeflag == b"S":
            raise _Bad("sparse member not supported")
        if typeflag == b"K":
            raise _Bad("long link name header not supported")
        if typeflag not in (b"0", b"\0", b"5"):
            raise _Bad(f"unsupported member type {typeflag!r}")
        try:
            name = (prefix + b"/" + raw_name if prefix else raw_name).decode("utf-8", "strict")
        except UnicodeError:
            raise _Bad("member name is not valid UTF-8") from None
        if pending is not None:
            if "path" in pending:
                name = pending["path"]
            if "size" in pending:
                if not pending["size"].isdigit():
                    raise _Bad("invalid pax size")
                member_size = int(pending["size"])
        pending = None
        is_dir = typeflag == b"5"
        clean = clean_name(name, directory=is_dir)
        if clean in members:
            raise _Bad(f"duplicate member name {clean}")
        if data_offset + _padded(member_size) > size:
            raise _Bad(f"truncated member {clean}")
        members[clean] = ("dir" if is_dir else "file", data_offset, member_size)
        if len(members) > MAX_MEMBERS:
            raise _Bad(f"more than {MAX_MEMBERS} members")
        offset = data_offset + _padded(member_size)


CHUNK_TAIL = 1024 * 1024


def _padded(n: int) -> int:
    return (n + BLOCK - 1) // BLOCK * BLOCK


def _manifest(fd: int, members: dict[str, tuple[str, int, int]]) -> tuple[int, int, str]:
    entry = members.get("manifest.json")
    if entry is None or entry[0] != "file":
        if any(m in members for m in OCI_MEMBERS):
            raise _Bad("pure OCI layout archives are not supported; use `docker save`")
        raise _Bad("not a docker save archive: top-level manifest.json missing")
    if entry[2] > MAX_MANIFEST:
        raise _Bad("manifest.json larger than 1 MiB")
    try:
        doc = json.loads(_read(fd, entry[2], entry[1]).decode("utf-8"))
    except (UnicodeError, ValueError):
        raise _Bad("manifest.json is not valid JSON") from None
    if not isinstance(doc, list) or not 1 <= len(doc) <= 64:
        raise _Bad("manifest.json must be a list of 1 to 64 entries")
    layers = 0
    for i, item in enumerate(doc):
        if not isinstance(item, dict) or not isinstance(item.get("Config"), str):
            raise _Bad(f"manifest.json entry {i} needs a Config name")
        refs = item.get("Layers")
        if not isinstance(refs, list) or not refs or not all(isinstance(r, str) for r in refs):
            raise _Bad(f"manifest.json entry {i} needs a non-empty list of Layers names")
        for field, ref in [("Config", item["Config"]), *(("Layers", r) for r in refs)]:
            name = clean_name(ref)
            if members.get(name, ("missing",))[0] != "file":
                raise _Bad(f"manifest.json {field} reference {ref} does not name an existing regular member")
        layers += len(refs)
    return len(doc), layers, doc[0]["Config"]


def validate_archive(fd: int, size: int) -> ArchiveInfo | ArchiveError:
    """Validate a `docker save` archive read through `fd` (whose size is `size`)."""
    if size > MAX_ARCHIVE:
        return ArchiveError(
            "IMAGE_ARCHIVE_TOO_LARGE", f"{size} bytes is larger than the 8 GiB maximum ({MAX_ARCHIVE} bytes)"
        )
    try:
        head = _read(fd, 8, 0)
        if any(head.startswith(m) for m in COMPRESSED):
            raise _Bad("compressed archives are not supported; uncompressed tar only")
        members = _members(fd, size)
        entries, layers, config = _manifest(fd, members)
        names = sorted(members)
        for name, (kind, _, _) in members.items():
            i = bisect.bisect_left(names, name + "/")
            if kind == "file" and i < len(names) and names[i].startswith(name + "/"):
                raise _Bad(f"regular member {name} is also used as a folder")
    except _Bad as exc:
        return ArchiveError("IMAGE_ARCHIVE_INVALID", str(exc))
    except (OSError, UnicodeError) as exc:
        return ArchiveError("IMAGE_ARCHIVE_INVALID", f"archive not readable: {exc}")
    return ArchiveInfo(len(members), entries, layers, config)
