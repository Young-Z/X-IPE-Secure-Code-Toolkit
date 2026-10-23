"""Unit tests for the bounded `docker save` archive validation (FEATURE-002-D AC-002D-03c, 03g, 03h).

`trivy_archive.validate_archive(fd, size)` reads through a no-follow descriptor and returns an
`ArchiveInfo` (members, manifest_entries, layers, config) or an `ArchiveError` (`code`, `reason`).
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("trivytar", Path(__file__).parent / "trivytar.py")
tt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tt)
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX descriptors")
GIB8 = 8 * 1024**3


def validate(tmp_path: Path, data: bytes, size: int | None = None):
    from x_ipe_secure_code.adapters import safe_io, trivy_archive

    path = tmp_path / "image.tar"
    path.write_bytes(data)
    fd = safe_io.open_nofollow(tmp_path, "image.tar")
    try:
        return trivy_archive.validate_archive(fd, len(data) if size is None else size)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def refused(tmp_path, data, *words, size=None):
    from x_ipe_secure_code.adapters import trivy_archive

    out = validate(tmp_path, data, size)
    assert isinstance(out, trivy_archive.ArchiveError), out
    assert out.code == "IMAGE_ARCHIVE_INVALID"
    for word in words:
        assert word.lower() in out.reason.lower(), (word, out.reason)
    return out


def accepted(tmp_path, data):
    from x_ipe_secure_code.adapters import trivy_archive

    out = validate(tmp_path, data)
    assert isinstance(out, trivy_archive.ArchiveInfo), out
    return out


# ---------------------------------------------------------------- accepted layouts
def test_classic_docker_save_accepted(tmp_path):
    info = accepted(tmp_path, tt.docker_save(os_info={"Family": "alpine", "Name": "3.21.6"}))
    assert info.manifest_entries == 1 and info.layers == 1 and info.members >= 4 and info.config


def test_docker25_layout_accepted(tmp_path):
    info = accepted(tmp_path, tt.docker_save(docker25=True))
    assert info.manifest_entries == 1 and info.layers == 1


def test_trailing_zero_blocks_allowed(tmp_path):
    accepted(tmp_path, tt.docker_save() + b"\0" * 8192)


# ---------------------------------------------------------------- AC-002D-03g size bound
def test_size_limit(tmp_path):
    from x_ipe_secure_code.adapters import trivy_archive

    out = validate(tmp_path, tt.docker_save(), size=GIB8 + 1)
    assert isinstance(out, trivy_archive.ArchiveError) and out.code == "IMAGE_ARCHIVE_TOO_LARGE"
    assert str(GIB8 + 1) in out.reason.replace(",", "") and "8 GiB" in out.reason


# ---------------------------------------------------------------- AC-002D-03h structure
def test_pure_oci_refused(tmp_path):
    refused(tmp_path, tt.oci_only(), "pure OCI layout", "docker save")


@pytest.mark.parametrize(
    ("typeflag", "linkname", "word"),
    [
        (b"1", "a", "link"),
        (b"2", "/etc/passwd", "link"),
        (b"3", "", "special"),
        (b"4", "", "special"),
        (b"6", "", "special"),
        (b"7", "", "special"),
        (b"K", "", ""),
        (b"V", "", ""),
        (b"M", "", ""),
        (b"N", "", ""),
        (b"Z", "", ""),
    ],
)
def test_link_and_special_members_refused(tmp_path, typeflag, linkname, word):
    bad = (
        tt.member("evil", b"", typeflag, linkname) if typeflag != b"K" else tt.gnu_long("x" * 120, link=True)
    )
    out = refused(tmp_path, tt.docker_save(extra=(bad,)))
    if word:
        assert word in out.reason.lower()


@pytest.mark.parametrize(
    ("name", "word"),
    [
        ("/abs/file", "/abs/file"),
        ("../evil", "../evil"),
        ("a/../b", "a/../b"),
        ("a//b", "a//b"),
        ("./a", "./a"),
        ("a\\b", "a\\b"),
        ("", ""),
        (b"bad\xff", ""),
    ],
)
def test_unclean_and_duplicate_names_refused(tmp_path, name, word):
    out = refused(tmp_path, tt.docker_save(extra=(tt.member(name, b"x"),)))
    if word:
        assert word in out.reason


def test_duplicate_and_file_as_folder_names_refused(tmp_path):
    refused(tmp_path, tt.docker_save(extra=(tt.member("manifest.json", b"[]"),)), "duplicate")
    refused(tmp_path, tt.docker_save(extra=(tt.member("dir", b"x"), tt.directory("dir"))), "dir")
    refused(tmp_path, tt.docker_save(extra=(tt.member("f", b"x"), tt.member("f/inner", b"y"))), "f")


def test_dangling_or_ambiguous_references_refused(tmp_path):
    good = json.loads(_manifest_of(tt.docker_save()))
    cases = [
        ([{"Config": "missing.json", "Layers": good[0]["Layers"]}], "missing.json"),
        ([{"Config": good[0]["Config"], "Layers": ["nope/layer.tar"]}], "nope/layer.tar"),
        ([{"Config": good[0]["Config"], "Layers": []}], "Layers"),
        ([{"Layers": good[0]["Layers"]}], "Config"),
        ([{"Config": "../x.json", "Layers": good[0]["Layers"]}], "../x.json"),
        ({"Config": good[0]["Config"]}, "manifest"),
        ([], "manifest"),
        ([{"Config": good[0]["Config"], "Layers": [good[0]["Layers"][0].rsplit("/", 1)[0]]}], "regular"),
    ]
    for manifest, word in cases:
        refused(tmp_path, tt.docker_save(manifest_override=manifest), word)
    refused(tmp_path, tt.archive(tt.member("manifest.json", b"not json")), "manifest")
    refused(tmp_path, tt.archive(tt.member("manifest.json", b"[" + b" " * (1024 * 1024) + b"]")), "manifest")


def _manifest_of(data: bytes) -> bytes:
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return tar.extractfile("manifest.json").read()


def test_sparse_truncated_compressed_refused(tmp_path):
    refused(tmp_path, tt.docker_save(extra=(tt.member("sparse", b"x" * 10, b"S"),)), "sparse")
    data = tt.docker_save()
    refused(tmp_path, data[: len(data) - 1024 - 700], "truncat")
    refused(tmp_path, gzip.compress(data), "compressed")
    for magic in (b"BZh91AY&SY", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd"):
        refused(tmp_path, magic + data[len(magic) :], "compressed")
    refused(tmp_path, tt.archive(tt.header("x", 10, bad_checksum=True) + tt._pad(b"x" * 10)), "checksum")
    refused(tmp_path, tt.archive(tt.header("x", 10, base256_size=True) + tt._pad(b"x" * 10)), "size")
    fake_huge = tt.header("x", 10**9) + b"x" * 512
    refused(tmp_path, tt.archive(fake_huge), "truncat")


def test_member_count_bounded(tmp_path):
    many = tuple(tt.directory(f"d{i}") for i in range(100_001))
    refused(tmp_path, tt.docker_save(extra=many), "member")


def test_oversized_pax_and_longname_refused(tmp_path):
    refused(
        tmp_path, tt.docker_save(extra=(tt.pax({"comment": "c" * (65 * 1024)}), tt.member("a", b"x"))), "pax"
    )
    refused(tmp_path, tt.docker_save(extra=(tt.gnu_long("n" * (5 * 1024)), tt.member("a", b"x"))), "name")


def test_global_pax_header_refused(tmp_path):
    """A global `path`/`size` changes how later members are read by a consumer: refused, never applied."""
    data = tt.docker_save()
    rename = tt.pax({"path": "manifest.json"}, global_=True)
    refused(tmp_path, rename + data, "global pax header not supported")
    resize = tt.pax({"size": "0"}, global_=True)
    refused(tmp_path, resize + data, "global pax header not supported")
    refused(tmp_path, tt.docker_save(extra=(tt.pax({"comment": "x"}, global_=True),)), "global pax header")


def test_pax_path_size_applied_to_next_member_only(tmp_path):
    from x_ipe_secure_code.adapters import trivy_archive

    data = tt.docker_save()
    # a pax `path` renames the next member to a second manifest.json: duplicate, as a consumer would see it
    refused(
        tmp_path,
        tt.archive(tt.pax({"path": "manifest.json"}), tt.member("innocent", b"[]"))[:-1024] + data,
        "duplicate",
    )
    # a pax `path` with `..` applies to the next member and is refused like a ustar name
    refused(
        tmp_path, tt.docker_save(extra=(tt.pax({"path": "../escape"}), tt.member("ok", b"x"))), "../escape"
    )
    # applied only to the immediately following member: the one after keeps its own name
    ok = tt.docker_save(
        extra=(tt.pax({"path": "renamed-once"}), tt.member("first", b"x"), tt.member("second", b"y"))
    )
    assert isinstance(validate(tmp_path, ok), trivy_archive.ArchiveInfo)
    # an `x` header not followed by a member, or two extension headers for one member
    refused(tmp_path, tt.docker_save(extra=(tt.pax({"comment": "x"}),)))
    refused(
        tmp_path,
        tt.docker_save(extra=(tt.pax({"comment": "x"}), tt.pax({"comment": "y"}), tt.member("z", b""))),
    )
    # a pax `size` changes the next member's boundary exactly as a consumer reads it
    body = b"A" * 600
    shifted = tt.archive(tt.pax({"size": "600"}), tt.header("blob", 0) + tt._pad(body))[:-1024]
    assert isinstance(validate(tmp_path, shifted + tt.docker_save()), trivy_archive.ArchiveInfo)
    # ustar size 1024 would skip a hidden symlink header; the pax size 0 makes a consumer read it: refused
    hidden = tt.header("hidden", 0, b"2", "/etc/passwd") + b"\0" * 512
    smuggled = tt.archive(tt.pax({"size": "0"}), tt.header("blob", 1024) + hidden)[:-1024]
    refused(tmp_path, smuggled + tt.docker_save(), "link")


@pytest.mark.parametrize(
    "key",
    [
        "linkpath",
        "hdrcharset",
        "GNU.sparse.size",
        "SCHILY.xattr.user.x",
        "LIBARCHIVE.creationtime",
        "unknown",
    ],
)
def test_unknown_pax_keys_refused(tmp_path, key):
    refused(tmp_path, tt.docker_save(extra=(tt.pax({key: "1"}), tt.member("a", b"x"))), key.split(".")[0])


def test_malformed_pax_records_refused(tmp_path):
    refused(tmp_path, tt.docker_save(extra=(tt.pax({}, raw=b"99 path=a\n"), tt.member("a", b"x"))), "pax")
    refused(tmp_path, tt.docker_save(extra=(tt.pax({}, raw=b"garbage"), tt.member("a", b"x"))), "pax")


@posix_only
def test_reads_only_through_the_given_descriptor(tmp_path):
    """The validator never re-opens the path: a swap after opening does not change what is validated."""
    from x_ipe_secure_code.adapters import safe_io, trivy_archive

    path = tmp_path / "image.tar"
    path.write_bytes(tt.docker_save())
    fd = safe_io.open_nofollow(tmp_path, "image.tar")
    os.rename(path, tmp_path / "moved.tar")
    os.symlink("/etc/passwd", path)
    try:
        out = trivy_archive.validate_archive(fd, (tmp_path / "moved.tar").stat().st_size)
    finally:
        os.close(fd)
    assert isinstance(out, trivy_archive.ArchiveInfo)


def test_staged_copy_revalidated(tmp_path):
    """The same function validates the staged snapshot; a corrupted snapshot is refused."""
    data = tt.docker_save()
    accepted(tmp_path, data)
    corrupted = bytearray(data)
    corrupted[0] ^= 0xFF
    refused(tmp_path, bytes(corrupted))
