"""FEATURE-002-G: read boundary, path safety and the exclusive comparison writer.

AC-002G-01a, 01d, 01e, 06a, 07a…07g, 07j, 07k.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap

import pytest
import write_audit
from comparehelp import (
    COMPARISONS,
    E_ID,
    GUARD,
    L_ID,
    REPORTS,
    X_ID,
    AccessRecorder,
    compare,
    compare_io,
    compare_match,
    compare_render,
    compare_validate,
    finding,
    load_comparison,
    make_project,
    manifest,
    put_pair,
    result,
    run_compare,
)
from conftest import SRC

posix_only = pytest.mark.skipif(os.name == "nt", reason="no-follow handle guarantees are POSIX only")


def preload():
    for module in (compare, compare_io, compare_match, compare_render, compare_validate):
        assert module.module is not None


def project(tmp_path, name="proj", **kw):
    root = make_project(tmp_path, name)
    put_pair(
        root,
        result(E_ID, findings=[finding("F1", line=3), finding("F2", line=9)]),
        result(L_ID, findings=[finding("G1", line=3), finding("G3", path="src/c.py", line=1)]),
        **kw,
    )
    return root


def refused(env, code):
    assert env["ok"] is False and env["problems"][0]["code"] == code, env
    return env


def gc_entries(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.name.startswith(("gc-", ".gc-")))


# ------------------------------------------------------------------------------ AC-002G-01a / 01d / 01e / 06a
@posix_only
def test_01a_reads_only_named_results_and_reports(tmp_path):
    root = project(tmp_path)
    (root / REPORTS / f"{X_ID}.json").write_text("{}")
    (root / "src").mkdir()
    (root / "src" / "a.py").write_text("print(1)\n")
    preload()
    with AccessRecorder() as rec:
        env, _ = run_compare(root)
    assert env["ok"], env
    real = os.path.realpath(root)
    twins = {os.path.join(real, REPORTS, f"{v}.{s}") for v in (E_ID, L_ID) for s in ("json", "md")}
    comp = os.path.join(real, COMPARISONS)
    reads = set(rec.content_opens(root))
    assert twins <= reads and {p for p in reads - twins if not p.startswith(comp + os.sep)} == set()
    assert {p for p in rec.write_opens(root) if not p.startswith(comp + os.sep)} == set()
    chain = {real}
    for rel in (REPORTS, GUARD, COMPARISONS):
        parts = rel.split("/")
        chain |= {os.path.join(real, *parts[: i + 1]) for i in range(len(parts))}
    assert set(rec.dir_opens(root)) <= chain
    allowed_stats = twins | {comp} | {os.path.join(real, GUARD, v) for v in (E_ID, L_ID)}
    for path in rec.stats:
        if path.startswith(real + os.sep):
            assert path in allowed_stats or path.startswith(comp + os.sep), path
    assert not [e for e in rec.events if e[0] in ("os.listdir", "os.scandir") and real in e[1]]
    assert not [e for e in rec.events if e[0] in ("subprocess.Popen", "os.exec", "os.posix_spawn", "os.fork")]


def _cmp_data(root, env):
    data, _ = load_comparison(root, env)
    for key in ("comparison_id", "created_at"):
        data.pop(key)
    return data


@posix_only
def test_01d_ignores_targets_other_reports_run_files(tmp_path):
    def setup(name):
        root = project(tmp_path, name)
        (root / "src").mkdir()
        for f in ("a.py", "b.py"):
            (root / "src" / f).write_text("x = 1\n")
        for vid in (E_ID, L_ID):
            (root / GUARD / vid / "state.json").write_text('{"state": 1}')
        return root

    base = setup("intact")
    baseline = _cmp_data(base, run_compare(base)[0])
    root = setup("changed")
    (root / "src" / "a.py").write_text("x = 2\n")
    (root / "src" / "b.py").unlink()
    (root / REPORTS / f"{X_ID}.json").write_bytes(b"\x00corrupt")
    (root / REPORTS / f"{X_ID}.md").write_bytes(b"corrupt")
    locked = [root / GUARD / vid / "state.json" for vid in (E_ID, L_ID)]
    for path in locked:
        path.chmod(0)
    try:
        before = manifest(root)
        with AccessRecorder() as rec:
            env, _ = run_compare(root)
        assert _cmp_data(root, env) == baseline
        assert manifest(root, exclude=COMPARISONS) == [x for x in before if not x[0].startswith(COMPARISONS)]
        assert not [e for e in rec.events if e[0] in ("subprocess.Popen", "os.exec", "os.posix_spawn")]
    finally:
        for path in locked:
            path.chmod(0o644)


def test_01e_no_network(tmp_path, monkeypatch):
    root = project(tmp_path)
    expected = _cmp_data(root, run_compare(root)[0])

    def blocked(*_a, **_k):
        raise OSError("network blocked by the test")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    preload()
    with AccessRecorder() as rec:
        env, _ = run_compare(root)
    assert _cmp_data(root, env) == expected
    assert not [e for e in rec.events if e[0].startswith("socket.")]


def test_06a_outputs_pair_in_comparisons_only(tmp_path):
    root = project(tmp_path)
    before = manifest(root)
    env, _ = run_compare(root)
    cid = env["data"]["comparison_id"]
    assert sorted(p.name for p in (root / COMPARISONS).iterdir()) == [f"{cid}.json", f"{cid}.md"]
    raw = (root / COMPARISONS / f"{cid}.json").read_bytes()
    data, md = load_comparison(root, env)
    assert md.endswith(f"<!-- guard-comparison-sha256: {hashlib.sha256(raw).hexdigest()} -->\n")
    assert compare_render.footer_digest(md) == hashlib.sha256(raw).hexdigest()
    assert set(data["input_integrity"]) == {"earlier", "later"}
    titles = dict(compare_render.CLASS_TITLES)
    sections = re.split(r"\n## ", md)
    for x in data["entries"]:
        section = next(s for s in sections if s.startswith(titles[x["class"]]))
        assert f"| {x['entry']} |" in section
        for r in x["reasons"]:
            assert compare_render.md_text(r["text"]) in section
    after = manifest(root)
    new = [x for x in after if x not in before]
    assert [x[0] for x in new] == [COMPARISONS, f"{COMPARISONS}/{cid}.json", f"{COMPARISONS}/{cid}.md"]
    assert [x for x in before if x not in after] == []


# ------------------------------------------------------------------------------ AC-002G-07a…07e
def test_07a_relative_accepted_absolute_dotdot_outside_refused(tmp_path):
    root = project(tmp_path)
    for name in (f"./{REPORTS}/{E_ID}.json", f"x-ipe-docs//secure-code/reports/guard/{E_ID}.md"):
        env, _ = run_compare(root, (name,), (L_ID,))
        assert env["ok"], env
    before = manifest(root)
    bad = [
        str(root / REPORTS / f"{E_ID}.json"),
        f"{REPORTS}/../guard/{E_ID}.json",
        f"../proj/{REPORTS}/{E_ID}.json",
        f"x-ipe-docs/secure-code/reports/{E_ID}.json",
        "C:/x/" + E_ID + ".json",
        f"{REPORTS}/{E_ID}.json/",
    ]
    preload()
    for name in bad:
        with AccessRecorder() as rec:
            env, _ = run_compare(root, (name,), (L_ID,))
        refused(env, "REPORT_NAME_INVALID")
        real = os.path.realpath(root)
        assert rec.content_opens(root) == [] and [p for p in rec.stats if p.startswith(real + os.sep)] == []
    assert manifest(root) == before


def test_07b_basename_and_subfolder_refused(tmp_path):
    root = project(tmp_path)
    before = manifest(root)
    for name in (
        f"{REPORTS}/{E_ID}.JSON",
        f"{REPORTS}/{E_ID}.txt",
        f"{REPORTS}/{E_ID}.json.bak",
        f"{REPORTS}/x{E_ID}.json",
        f"{REPORTS}/comparisons/{E_ID}.json",
        f"{REPORTS}/sub/{E_ID}.json",
        f"{REPORTS}/{E_ID.upper()}.json",
        E_ID + ".json",
    ):
        with AccessRecorder() as rec:
            env, _ = run_compare(root, (name,), (L_ID,))
        refused(env, "REPORT_NAME_INVALID")
        assert rec.content_opens(root) == []
    assert manifest(root) == before


@posix_only
def test_07c_symlinked_component_refused(tmp_path):
    parts = REPORTS.split("/")
    for i in range(len(parts)):
        root = project(tmp_path, f"c{i}")
        comp = root.joinpath(*parts[: i + 1])
        real = tmp_path / f"real{i}"
        comp.rename(real)
        comp.symlink_to(real, target_is_directory=True)
        before = manifest(root)
        outside = manifest(real)
        for earlier in (E_ID, f"{REPORTS}/{E_ID}.json"):
            with AccessRecorder() as rec:
                env, _ = run_compare(root, (earlier,), (L_ID,))
            refused(env, "PATH_UNSAFE")
            assert rec.content_opens(root) == [] and rec.content_opens(real) == []
        assert manifest(root) == before and manifest(real) == outside


@posix_only
def test_07d_twin_link_or_special_refused(tmp_path):
    for case in ("json-link", "md-link", "fifo", "folder"):
        root = project(tmp_path, case)
        target = root / REPORTS / f"{E_ID}.{'md' if case == 'md-link' else 'json'}"
        copy = tmp_path / f"{case}-copy"
        target.rename(copy)
        if case.endswith("link"):
            target.symlink_to(copy)
        elif case == "fifo":
            os.mkfifo(target)
        else:
            target.mkdir()
        before = manifest(root)
        with AccessRecorder() as rec:
            env, _ = run_compare(root)
        refused(env, "PATH_UNSAFE")
        assert rec.content_opens(root) == [] and manifest(root) == before
    root = project(tmp_path, "missing-json")
    (root / REPORTS / f"{E_ID}.json").unlink()
    refused(run_compare(root)[0], "NOT_CONCLUDED")
    shutil.rmtree(root / GUARD / E_ID)
    refused(run_compare(root)[0], "RUN_NOT_FOUND")
    root = project(tmp_path, "missing-md")
    (root / REPORTS / f"{E_ID}.md").unlink()
    env, _ = run_compare(root)
    assert env["ok"] and env["data"]["earlier"]["input_integrity"] == "unresolved"


@posix_only
def test_07e_comparisons_link_or_file_refused_absent_created(tmp_path):
    for case in ("link", "file", "dangling"):
        root = project(tmp_path, case)
        outside = tmp_path / f"outside-{case}"
        outside.mkdir()
        comp = root / COMPARISONS
        if case == "link":
            comp.symlink_to(outside, target_is_directory=True)
        elif case == "dangling":
            comp.symlink_to(tmp_path / "nowhere")
        else:
            comp.write_text("not a folder")
        before, before_out = manifest(root), manifest(outside)
        refused(run_compare(root)[0], "PATH_UNSAFE")
        assert manifest(root) == before and manifest(outside) == before_out
    root = project(tmp_path, "absent")
    assert not (root / COMPARISONS).exists()
    env, _ = run_compare(root)
    assert env["ok"] and (root / COMPARISONS).is_dir() and not (root / COMPARISONS).is_symlink()


# ------------------------------------------------------------------------------ AC-002G-07f
def _force_ids(monkeypatch, suffixes):
    import secrets as secrets_module

    real = secrets_module.token_hex
    queue = list(suffixes)

    def token_hex(n=None):
        return queue.pop(0) if n == 4 and queue else real(n)

    monkeypatch.setattr(compare.module.secrets, "token_hex", token_hex)
    monkeypatch.setattr(compare.module.guard_model, "utc_now", lambda: "2026-10-23T12:05:01Z")
    return lambda s: f"gc-20261023T120501Z-{s}"


@posix_only
def test_07f_existing_name_never_overwritten(tmp_path, monkeypatch):
    root = project(tmp_path)
    comp = root / COMPARISONS
    comp.mkdir()
    cid = _force_ids(monkeypatch, ["00000001", "00000002", "00000003", "00000004", "00000005"])
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    (comp / f"{cid('00000001')}.json").write_text("existing")
    (comp / f"{cid('00000002')}.md").symlink_to(outside)
    (comp / f"{cid('00000003')}.json").symlink_to(tmp_path / "nowhere")
    existing = manifest(comp)

    def appear(step):
        if step == "before_json_link" and not (comp / f"{cid('00000004')}.json").exists():
            (comp / f"{cid('00000004')}.json").write_text("raced in")

    monkeypatch.setattr(compare_io.module, "_fail_point", appear)
    env, _ = run_compare(root)
    assert env["ok"], env
    final = cid("00000005")
    assert env["data"]["comparison_id"] == final
    assert env["data"]["collisions"] == [
        f"{cid('00000001')}.json",
        f"{cid('00000002')}.md",
        f"{cid('00000003')}.json",
        f"{cid('00000004')}.json",
    ]
    assert outside.read_text() == "keep me"
    assert [x for x in manifest(comp) if x[0] in {e[0] for e in existing}] == existing
    assert (comp / f"{cid('00000004')}.json").read_text() == "raced in"
    raw = (comp / f"{final}.json").read_bytes()
    md = (comp / f"{final}.md").read_text()
    assert json.loads(raw)["comparison_id"] == final and md.startswith(f"# Guard Report Comparison {final}\n")
    assert env["data"]["files"]["structured"].endswith(f"{final}.json")
    assert compare_render.footer_digest(md) == hashlib.sha256(raw).hexdigest()
    assert not [p for p in comp.iterdir() if p.name.endswith(".tmp")]


@posix_only
def test_07f_markdown_name_raced_then_new_candidate(tmp_path, monkeypatch):
    root = project(tmp_path)
    cid = _force_ids(monkeypatch, ["0000000a", "0000000b"])

    def appear(step):
        target = root / COMPARISONS / f"{cid('0000000a')}.md"
        if step == "before_markdown_link" and not target.exists() and not target.is_symlink():
            target.write_text("raced markdown")

    monkeypatch.setattr(compare_io.module, "_fail_point", appear)
    env, _ = run_compare(root)
    assert env["ok"] and env["data"]["comparison_id"] == cid("0000000b")
    names = sorted(p.name for p in (root / COMPARISONS).iterdir())
    assert names == [f"{cid('0000000a')}.md", f"{cid('0000000b')}.json", f"{cid('0000000b')}.md"]


@posix_only
def test_07f_eight_collisions_refused(tmp_path, monkeypatch):
    root = project(tmp_path)
    comp = root / COMPARISONS
    comp.mkdir()
    suffixes = [f"{i:08x}" for i in range(1, 9)]
    cid = _force_ids(monkeypatch, suffixes)
    for s in suffixes:
        (comp / f"{cid(s)}.json").write_text("taken")
    before = manifest(root)
    env, _ = run_compare(root)
    refused(env, "COMPARISON_COLLISION")
    assert len(env["data"]["collisions"]) == 8 and manifest(root) == before


# ------------------------------------------------------------------------------ AC-002G-07g
HOOKS = ("after_checks", "before_json_link", "before_markdown_link", "before_final_verification")
SUBSTITUTIONS = ("link_outside", "moved_outside_preexisting", "moved_outside_created", "output_name_link")


@posix_only
@pytest.mark.parametrize("hook", HOOKS)
@pytest.mark.parametrize("how", SUBSTITUTIONS)
def test_07g_substitution_never_writes_outside(tmp_path, monkeypatch, hook, how):
    root = project(tmp_path)
    comp = root / COMPARISONS
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.txt").write_text("victim")
    if how != "moved_outside_created":
        comp.mkdir()
    links: list[tuple[str, str]] = []
    real_link = os.link
    fired = []
    test_events: list[tuple[int, int]] = []

    def rec_link(src, dst, *a, **k):
        links.append(("after" if fired else "before", os.fspath(dst)))
        return real_link(src, dst, *a, **k)

    def hook_fn(step):
        if step != hook or fired:
            return
        fired.append(step)
        start = len(rec.events)
        if how == "link_outside":
            comp.rename(root / REPORTS / "comparisons-moved")
            comp.symlink_to(outside, target_is_directory=True)
        elif how.startswith("moved_outside"):
            comp.rename(outside / "moved")
            comp.symlink_to(outside / "moved", target_is_directory=True)
        else:
            names = sorted(p.name for p in comp.iterdir() if p.name.startswith("gc-"))
            victim = outside / "victim.txt"
            target_name = names[0] if names else "gc-placeholder.json"
            if names:
                (comp / target_name).unlink()
            (comp / target_name).symlink_to(victim)
        test_events.append((start, len(rec.events)))

    monkeypatch.setattr(os, "link", rec_link)
    monkeypatch.setattr(compare_io.module, "_fail_point", hook_fn)
    preload()
    with AccessRecorder() as rec:
        env, _ = run_compare(root)
    assert fired == [hook]
    assert (outside / "victim.txt").read_text() == "victim"
    outside_files = [p for p in outside.rglob("*") if p.name.startswith(("gc-", ".gc-"))]
    assert outside_files == []
    if how == "moved_outside_created":
        moved = outside / "moved"
        assert not moved.exists() or list(moved.iterdir()) == []
    if env["ok"]:  # completed inside the project, folder identity confirmed at the final verification
        assert how == "output_name_link" and hook in ("after_checks", "before_json_link")
        assert comp.is_dir() and not comp.is_symlink()
        cid = env["data"]["comparison_id"]
        assert (comp / f"{cid}.json").is_file() and (comp / f"{cid}.md").is_file()
    else:
        if how != "output_name_link":  # no final-name link after the folder mismatch was detectable
            assert [n for when, n in links if when == "after"] == []
        assert [p for p in gc_entries(root) if not p.endswith("gc-placeholder.json")] == []
    skipped = {i for a, b in test_events for i in range(a, b)}
    for index, (event, args) in enumerate(rec.events):
        if index in skipped:
            continue
        if event in ("os.remove", "os.rmdir"):
            path, dir_fd = re.match(r"\('([^']*)', (\S+)\)", args).groups()
            assert "/" not in path and dir_fd != "None", (event, args)


# ------------------------------------------------------------------------------ AC-002G-07j
FAIL_POINTS = (
    "folder_create",
    "json_write",
    "json_fsync",
    "before_json_link",
    "after_json_dir_fsync",
    "markdown_write",
    "markdown_fsync",
    "before_markdown_link",
    "before_final_dir_fsync",
    "folder_fsync",
    "before_final_verification",
)


@posix_only
@pytest.mark.parametrize("point", FAIL_POINTS)
def test_07j_injected_failures_leave_no_partial(tmp_path, monkeypatch, point):
    root = project(tmp_path)
    before = manifest(root)

    def fail(step):
        if step == point:
            raise OSError(errno.EIO, f"injected failure at {step}")

    monkeypatch.setattr(compare_io.module, "_fail_point", fail)
    env, _ = run_compare(root)
    refused(env, "COMPARISON_WRITE_FAILED")
    assert env["data"]["step"] == point
    assert manifest(root) == before and not (root / COMPARISONS).exists()
    if point != "folder_create":  # with a pre-existing comparisons/ only the command's own files are removed
        root2 = project(tmp_path, "existing")
        (root2 / COMPARISONS).mkdir()
        before = manifest(root2)
        refused(run_compare(root2)[0], "COMPARISON_WRITE_FAILED")
        assert manifest(root2) == before


@posix_only
@pytest.mark.parametrize("code", ["EPERM", "ENOTSUP", "ENOSYS"])
@pytest.mark.parametrize("nth", [1, 2])
def test_07j_hardlink_unsupported_refused(tmp_path, monkeypatch, code, nth):
    root = project(tmp_path)
    before = manifest(root)
    calls = []
    real_link = os.link

    def link(*a, **k):
        calls.append(a)
        if len(calls) == nth:
            raise OSError(getattr(errno, code), "no hard links")
        return real_link(*a, **k)

    monkeypatch.setattr(os, "link", link)
    env, _ = run_compare(root)
    refused(env, "HARDLINK_UNSUPPORTED")
    assert env["data"]["step"] == ("json_link" if nth == 1 else "markdown_link")
    assert len(calls) == nth
    assert manifest(root) == before and not (root / COMPARISONS).exists()


# ------------------------------------------------------------------------------ AC-002G-07k
@posix_only
def test_07k_write_call_order(tmp_path, monkeypatch):
    root = project(tmp_path)
    names: dict[int, str] = {}
    calls: list[tuple] = []
    real = {n: getattr(os, n) for n in ("open", "write", "fsync", "link", "unlink", "mkdir", "close")}

    def r_open(path, flags, mode=0o777, *, dir_fd=None):
        fd = real["open"](path, flags, mode, dir_fd=dir_fd)
        names[fd] = os.path.basename(os.fspath(path)) if not isinstance(path, int) else "?"
        calls.append(
            (
                "open",
                names[fd],
                "excl"
                if flags & os.O_EXCL
                else "rdonly"
                if not flags & (os.O_WRONLY | os.O_RDWR)
                else "other",
            )
        )
        return fd

    def r_write(fd, data):
        calls.append(("write", names.get(fd, "?")))
        return real["write"](fd, data)

    def r_fsync(fd):
        calls.append(("fsync", names.get(fd, "?")))
        return real["fsync"](fd)

    def r_link(src, dst, **k):
        calls.append(("link", os.path.basename(src), os.path.basename(dst)))
        return real["link"](src, dst, **k)

    def r_unlink(path, *, dir_fd=None):
        calls.append(("unlink", os.path.basename(os.fspath(path))))
        return real["unlink"](path, dir_fd=dir_fd)

    for name, fn in (
        ("open", r_open),
        ("write", r_write),
        ("fsync", r_fsync),
        ("link", r_link),
        ("unlink", r_unlink),
    ):
        monkeypatch.setattr(os, name, fn)
    preload()
    env, _ = run_compare(root)
    monkeypatch.undo()
    assert env["ok"], env
    cid = env["data"]["comparison_id"]
    j, m = f"{cid}.json", f"{cid}.md"
    tmp = [c[1] for c in calls if c[0] == "open" and c[2] == "excl"]
    assert len(tmp) == 2 and tmp[0].startswith(f".{j}.") and tmp[1].startswith(f".{m}.")
    expected = [
        ("open", tmp[0], "excl"),
        ("write", tmp[0]),
        ("fsync", tmp[0]),
        ("link", tmp[0], j),
        ("unlink", tmp[0]),
        ("fsync", "comparisons"),
        ("open", j, "rdonly"),
        ("open", tmp[1], "excl"),
        ("write", tmp[1]),
        ("fsync", tmp[1]),
        ("link", tmp[1], m),
        ("unlink", tmp[1]),
        ("fsync", "comparisons"),
        ("open", j, "rdonly"),
        ("open", m, "rdonly"),
    ]
    it = iter(calls)
    for step in expected:
        assert any(c == step for c in it), (step, calls)
    first_json_link = calls.index(("link", tmp[0], j))
    md_link = calls.index(("link", tmp[1], m))
    assert ("fsync", "comparisons") in calls[first_json_link:md_link]


CRASH_CHILD = textwrap.dedent(
    """
    import os, sys
    sys.path.insert(0, sys.argv[1])
    from x_ipe_secure_code import cli
    from x_ipe_secure_code.guard import compare_io

    def crash(step):
        if step == sys.argv[3]:
            os._exit(9)

    compare_io._fail_point = crash
    cli.main(["guard", "compare", "--project", sys.argv[2], "--earlier", sys.argv[4], "--later", sys.argv[5],
              "--json"])
    """
)


@posix_only
@pytest.mark.parametrize(
    "point", ["after_json_dir_fsync", "before_markdown_link", "after_markdown_link", "before_final_dir_fsync"]
)
def test_07k_crash_points(tmp_path, point):
    root = project(tmp_path)
    env = dict(os.environ)
    env.update(write_audit.child_env([tmp_path]))
    out = subprocess.run(
        [sys.executable, "-c", CRASH_CHILD, str(SRC), str(root), point, E_ID, L_ID],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
    )
    assert out.returncode == 9, out.stderr
    comp = root / COMPARISONS
    finals = sorted(p.name for p in comp.iterdir() if not p.name.startswith("."))
    for name in finals:
        if name.endswith(".md"):
            twin = comp / (name[:-3] + ".json")
            assert twin.is_file()
            footer = compare_render.footer_digest((comp / name).read_text())
            assert footer == hashlib.sha256(twin.read_bytes()).hexdigest()
    if point in ("after_json_dir_fsync", "before_markdown_link"):
        assert [n for n in finals if n.endswith(".md")] == [] and len(finals) == 1
    else:
        assert len(finals) == 2


@posix_only
@pytest.mark.parametrize("failure", ["parent_fsync_eio", "folder_open_eio", "folder_open_unsafe"])
def test_07j_failure_right_after_folder_creation_removes_it(tmp_path, monkeypatch, failure):
    from x_ipe_secure_code.knowledge import durable

    root = project(tmp_path)
    before = manifest(root)
    if failure == "parent_fsync_eio":
        real_fsync = os.fsync
        calls = []

        def fsync(fd):
            calls.append(fd)
            if len(calls) == 1:  # fsync(reports/guard) right after mkdir(comparisons)
                raise OSError(errno.EIO, "injected fsync failure")
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", fsync)
    else:
        real_dir = durable.Tree.dir

        def tree_dir(self, rel, **kw):
            if rel.endswith("/comparisons"):
                if failure == "folder_open_eio":
                    raise OSError(errno.EIO, "injected open failure")
                raise durable.unsafe("injected: not a real folder")
            return real_dir(self, rel, **kw)

        monkeypatch.setattr(durable.Tree, "dir", tree_dir)
    env, _ = run_compare(root)
    refused(env, "PATH_UNSAFE" if failure == "folder_open_unsafe" else "COMPARISON_WRITE_FAILED")
    assert not (root / COMPARISONS).exists()
    assert manifest(root) == before
