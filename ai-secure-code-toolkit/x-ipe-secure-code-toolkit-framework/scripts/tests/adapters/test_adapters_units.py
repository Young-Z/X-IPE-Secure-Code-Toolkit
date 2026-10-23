"""Unit tests for the Adapter contract and the Opengrep Adapter (FEATURE-002-B)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from x_ipe_secure_code.adapters import (
    ADAPTERS,
    digests,
    opengrep,
    process,
    provided,
    reserved_id,
    reserved_name,
    rules,
    safe_io,
)

FIXTURES = Path(__file__).parent / "fixtures"
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX execution only")


# ---------- contract and namespace (AC-002B-04c)


def test_registry_and_reserved_namespace():
    assert provided() == ["opengrep", "trivy"] and ADAPTERS["trivy"] is not None and ADAPTERS["strix"] is None
    assert reserved_name("OpenGrep") and reserved_name("opengrep") and not reserved_name("semantic-review")
    assert reserved_id("opengrep-1-1") and reserved_id("OPENGREP-x") and not reserved_id("E1")


# ---------- official digests and host platform (AC-002B-01a, 05b)


def test_digest_table_matches_validation_record():
    builds = digests.TABLE
    assert len(builds) == 7 and {b.version for b in builds.values()} == {"1.31.0"}
    validated = [b.asset for b in builds.values() if b.validated]
    assert validated == ["opengrep_manylinux_aarch64"]
    linux = digests.lookup("sha256:2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d")
    assert (linux.os, linux.arch, linux.libc) == ("linux", "aarch64", "glibc")
    assert digests.lookup("sha256:" + "0" * 64) is None


def test_host_platform_matching(monkeypatch):
    build = digests.lookup("sha256:035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb")
    assert digests.matches(build, {"os": "macos", "arch": "aarch64", "libc": None})
    assert not digests.matches(build, {"os": "macos", "arch": "x86", "libc": None})
    musl = digests.lookup("sha256:b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9")
    assert not digests.matches(musl, {"os": "linux", "arch": "aarch64", "libc": "glibc"})
    monkeypatch.setattr(digests.sys, "platform", "linux")
    monkeypatch.setattr(digests.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(digests.platform, "libc_ver", lambda: ("glibc", "2.36"))
    assert digests.host_platform() == {"os": "linux", "arch": "aarch64", "libc": "glibc"}


def test_no_network_code_in_adapters():
    src = Path(opengrep.__file__).parent
    for path in src.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for module in ("urllib", "http.client", "socket", "requests"):
            assert f"import {module}" not in text and f"from {module}" not in text, (path, module)


# ---------- safe I/O (AC-002B-01c, 03k)


@posix_only
def test_open_nofollow_refuses_symlinks_and_copies_hash(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f.txt").write_text("hello")
    os.symlink(tmp_path / "d" / "f.txt", tmp_path / "d" / "link.txt")
    os.symlink(tmp_path / "d", tmp_path / "dlink")
    for rel in ("d/link.txt", "dlink/f.txt"):
        with pytest.raises(safe_io.UnsafePath):
            safe_io.open_nofollow(tmp_path, rel)
    fd = safe_io.open_nofollow(tmp_path, "d/f.txt")
    dest = tmp_path / "out" / "f.txt"
    digest, size = safe_io.copy_hash(fd, dest, limit=100)
    assert digest == "sha256:" + hashlib.sha256(b"hello").hexdigest() and size == 5
    assert dest.read_text() == "hello"
    fd = safe_io.open_nofollow(tmp_path, "d/f.txt")
    with pytest.raises(safe_io.TooLarge):
        safe_io.copy_hash(fd, tmp_path / "out2", limit=3)


def test_copy_hash_completes_short_writes(tmp_path, monkeypatch):
    data = bytes(range(256)) * 40
    (tmp_path / "src.bin").write_bytes(data)
    real_write = os.write

    def short_write(fd, buf):
        return real_write(fd, bytes(buf[:7]))

    fd = safe_io.open_nofollow(tmp_path, "src.bin")
    monkeypatch.setattr(safe_io.os, "write", short_write)
    digest, size = safe_io.copy_hash(fd, tmp_path / "dest.bin", limit=len(data))
    monkeypatch.undo()
    assert (tmp_path / "dest.bin").read_bytes() == data
    assert digest == "sha256:" + hashlib.sha256(data).hexdigest() and size == len(data)


def test_copy_hash_zero_byte_write_is_an_error(tmp_path, monkeypatch):
    (tmp_path / "src.bin").write_bytes(b"abc")
    fd = safe_io.open_nofollow(tmp_path, "src.bin")
    monkeypatch.setattr(safe_io.os, "write", lambda fd, buf: 0)
    with pytest.raises(OSError):
        safe_io.copy_hash(fd, tmp_path / "dest.bin", limit=10)


def test_hash_file_absolute(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(b"abc")
    assert safe_io.hash_path(p) == "sha256:" + hashlib.sha256(b"abc").hexdigest()


# ---------- rule files (AC-002B-02b, 02d)


def _rule(**over):
    rule = {
        "id": "py-sql",
        "languages": ["python"],
        "severity": "ERROR",
        "message": "m",
        "pattern": "$C.execute(...)",
    }
    rule.update(over)
    return rule


def test_rules_load_and_dump_single():
    loaded = rules.load_rules(json.dumps({"rules": [_rule(), _rule(id="py-two")]}).encode())
    assert [r["id"] for r in loaded] == ["py-sql", "py-two"]
    again = rules.load_rules(rules.dump_single(loaded[1]).encode())
    assert again == [loaded[1]]


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("rules: [", "YAML"),
        ("a: &x 1\nb: *x\n", "alias"),
        ("rules:\n  - id: a\n    id: b\n", "duplicate"),
        ("rules: {}", "rules"),
        ("rules:\n  - languages: [python]\n    pattern: x\n", "id"),
        ("rules:\n  - id: a\n    pattern: x\n", "languages"),
        ("rules:\n  - id: a\n    languages: [python]\n    mode: taint\n", "not supported"),
        ("rules:\n  - id: a\n    languages: [python]\n    options: {interfile: true}\n", "not supported"),
        ("rules:\n  - id: a\n    languages: [python]\n    paths: {include: [x]}\n", "not supported"),
        ("rules:\n  - id: 'a b'\n    languages: [python]\n    pattern: x\n", "id"),
        ("!!python/object/apply:os.system ['true']", "YAML"),
    ],
)
def test_rules_refusals(text, fragment):
    with pytest.raises(rules.RuleError) as exc:
        rules.load_rules(text.encode())
    assert fragment.lower() in str(exc.value).lower()


def test_rules_depth_and_count_limits(monkeypatch):
    monkeypatch.setattr(rules, "MAX_RULES", 2)
    with pytest.raises(rules.RuleError):
        rules.load_rules(json.dumps({"rules": [_rule(id=f"r{i}") for i in range(3)]}).encode())
    deep = (
        "rules:\n  - id: a\n    languages: [python]\n    pattern-either:\n"
        + "      "
        + "[" * 40
        + "x"
        + "]" * 40
    )
    with pytest.raises(rules.RuleError):
        rules.load_rules(deep.encode())


def test_rule_set_conflicts():
    with pytest.raises(rules.RuleError) as exc:
        rules.check_set([_rule(id="foo"), _rule(id="foo")])
    assert "duplicate" in str(exc.value)
    with pytest.raises(rules.RuleError) as exc:
        rules.check_set([_rule(id="foo"), _rule(id="a.foo")])
    assert "ambiguous" in str(exc.value)
    rules.check_set([_rule(id="foo"), _rule(id="bar")])


# ---------- process runner (AC-002B-03g)


def _script(tmp_path, body):
    path = tmp_path / "tool.py"
    path.write_text(f"#!{sys.executable}\nimport os, sys, time, subprocess\n{body}\n")
    path.chmod(0o700)
    return path


@posix_only
def test_process_runs_with_minimal_env(tmp_path):
    tool = _script(tmp_path, "print(sorted(os.environ)); print(os.getcwd())")
    out = tmp_path / "out.txt"
    env = {"HOME": str(tmp_path), "PATH": os.defpath}
    res = process.run([str(tool)], tmp_path, env, time.monotonic() + 30, out, 1024)
    assert res.exit == 0 and not res.timed_out and not res.oversized
    printed = out.read_text().splitlines()
    assert "HOME" in printed[0] and "SECRET" not in printed[0] and printed[1] == str(tmp_path.resolve())


@posix_only
def test_process_timeout_kills_group_including_children(tmp_path):
    marker = tmp_path / "child.pid"
    tool = _script(
        tmp_path,
        f"p = subprocess.Popen(['sleep', '60']); open({str(marker)!r}, 'w').write(str(p.pid)); "
        "time.sleep(60)",
    )
    res = process.run(
        [str(tool)], tmp_path, {"PATH": os.defpath}, time.monotonic() + 1.5, tmp_path / "o", 1024
    )
    assert res.timed_out and res.seconds < 15
    pid = int(marker.read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@posix_only
def test_process_output_cap(tmp_path):
    tool = _script(tmp_path, "sys.stdout.write('x' * 5_000_000); sys.stdout.flush(); time.sleep(30)")
    res = process.run(
        [str(tool)], tmp_path, {"PATH": os.defpath}, time.monotonic() + 20, tmp_path / "o", 100_000
    )
    assert res.oversized and not res.timed_out


@posix_only
def test_process_stderr_tail(tmp_path):
    tool = _script(tmp_path, "sys.stderr.write('a' * 10000 + 'END'); sys.exit(7)")
    res = process.run([str(tool)], tmp_path, {"PATH": os.defpath}, time.monotonic() + 30, tmp_path / "o", 10)
    assert res.exit == 7 and res.stderr_tail.endswith("END") and len(res.stderr_tail) <= 4096


@posix_only
def test_process_should_stop_kills_group_and_confirms(tmp_path):
    """FEATURE-002-C AC-002C-04b: the owning process stops the tool and observes its group exit."""
    marker = tmp_path / "child.pid"
    tool = _script(
        tmp_path,
        f"p = subprocess.Popen(['sleep', '60']); open({str(marker)!r}, 'w').write(str(p.pid)); "
        "time.sleep(60)",
    )
    start = time.monotonic()
    res = process.run(
        [str(tool)],
        tmp_path,
        {"PATH": os.defpath},
        time.monotonic() + 60,
        tmp_path / "o",
        1024,
        should_stop=lambda: marker.exists() and time.monotonic() - start > 0.5,
    )
    assert res.cancelled and not res.timed_out and res.exit is None and res.seconds < 15
    assert res.group_gone is True
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)


@posix_only
def test_process_should_stop_before_spawn_runs_nothing(tmp_path):
    flag = tmp_path / "ran"
    tool = _script(tmp_path, f"open({str(flag)!r}, 'w').write('x')")
    res = process.run(
        [str(tool)],
        tmp_path,
        {"PATH": os.defpath},
        time.monotonic() + 30,
        tmp_path / "o",
        1024,
        should_stop=lambda: True,
    )
    assert res.cancelled and res.group_gone and not flag.exists()


@posix_only
def test_process_group_probe_reports_survivor_as_not_gone(tmp_path, monkeypatch):
    """A probe that still finds the group (or a reused id) is reported as not confirmed (safe side)."""
    tool = _script(tmp_path, "time.sleep(60)")
    real_killpg = os.killpg

    def killpg(pgid, sig):
        if sig == 0:
            return None
        return real_killpg(pgid, sig)

    monkeypatch.setattr(process.os, "killpg", killpg)
    monkeypatch.setattr(process, "_live_members", lambda pgid: True)  # a live survivor (or a reused id)
    monkeypatch.setattr(process, "GROUP_WAIT", 0.3)
    calls = []
    res = process.run(
        [str(tool)],
        tmp_path,
        {"PATH": os.defpath},
        time.monotonic() + 30,
        tmp_path / "o",
        1024,
        should_stop=lambda: calls.append(1) or len(calls) > 3,
    )
    assert res.cancelled and res.group_gone is False


# ---------- Opengrep normalization and accounting (AC-002B-03b…03f, 03i)


def _fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def test_argv_uses_only_staged_paths(tmp_path):
    argv = opengrep.build_argv(
        tmp_path / "bin" / "opengrep",
        tmp_path / "rules" / "1-1.yaml",
        [tmp_path / "src" / "a"],
        include_ignored=True,
    )
    assert argv[:5] == [
        str(tmp_path / "bin" / "opengrep"),
        "scan",
        "--json",
        "--verbose",
        "--disable-version-check",
    ]
    assert argv[argv.index("--config") + 1] == str(tmp_path / "rules" / "1-1.yaml")
    assert "--x-ignore-semgrepignore-files" in argv and argv[-1] == str(tmp_path / "src" / "a")
    assert "--metrics" not in argv
    assert not any(a.startswith(("p/", "r/")) or a == "auto" or "://" in a for a in argv)


def test_status_mapping():
    ok = process.ProcessOutcome(0, False, False, "", 1.0)
    assert opengrep.status_of(ok, {"errors": []}) == "completed"
    assert opengrep.status_of(ok, {"errors": [{"type": "x"}]}) == "completed_with_errors"
    assert opengrep.status_of(ok, None) == "failed"
    assert opengrep.status_of(process.ProcessOutcome(7, False, False, "", 1.0), {"errors": []}) == "failed"
    assert opengrep.status_of(process.ProcessOutcome(None, True, False, "", 1.0), None) == "timed_out"
    assert opengrep.status_of(process.ProcessOutcome(None, False, True, "", 1.0), None) == "failed"


def test_sanitize_masks_strings_and_removes_matched_source():
    doc = _fixture("w-verbose-two-files")
    doc["results"][0]["extra"]["message"] = "leak ghp_" + "a" * 36
    doc["errors"] = [{"type": "x", "message": 'password = "Zq8vLr2mNp4tXw9y"'}]
    clean = opengrep.sanitize(doc, "/samples/w/")
    text = json.dumps(clean)
    assert "ghp_" not in text and "Zq8vLr2mNp4tXw9y" not in text
    assert clean["results"][0]["extra"]["lines"] == "[removed: matched source]"
    assert (
        clean["results"][0]["path"]
        == "src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java"
    )
    assert "abstract_content" not in text


def test_results_normalized_and_attributed():
    doc = opengrep.sanitize(_fixture("w-verbose-two-files"), "/samples/w/")
    found, unattributed = opengrep.results(doc, "java-sql-string-concat")
    assert unattributed == []
    f = found[0]
    assert f["path"] == "src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java"
    assert (f["line"], f["end_line"], f["tool_severity"], f["severity"], f["cwe"]) == (
        73,
        76,
        "ERROR",
        "high",
        "CWE-89",
    )
    assert f["rule_id"] == "java-sql-string-concat"
    _, wrong = opengrep.results(doc, "other-rule")
    assert len(wrong) == 1


@pytest.mark.parametrize(
    ("tool", "guard"),
    [("ERROR", "high"), ("WARNING", "medium"), ("INFO", "low"), ("EXPERIMENT", "unknown"), (None, "unknown")],
)
def test_severity_map(tool, guard):
    assert opengrep.SEVERITY_MAP.get(tool, "unknown") == guard


def test_cwe_extraction():
    assert opengrep.cwe_of({"cwe": ["CWE-79: Improper Neutralization", "CWE-80"]}) == "CWE-79"
    assert opengrep.cwe_of({"cwe": "CWE-89"}) == "CWE-89"
    assert opengrep.cwe_of({}) is None


def test_accounting_scanned_skipped_unaccounted():
    doc = opengrep.sanitize(_fixture("m-verbose"), "/samples/m/")
    files = ["registration.py", "server.py", "tests/test_server.py", "public/index.html"]
    acc = opengrep.account(files, [doc])
    assert acc["scanned"] == ["registration.py", "server.py"]
    assert acc["skipped"] == [{"path": "tests/test_server.py", "reason": "semgrepignore_patterns_match"}]
    assert acc["unaccounted"] == ["public/index.html"]


def test_accounting_rule_applied_to_no_file_and_skipped_rules():
    doc = opengrep.sanitize(_fixture("file-target"), "/samples/m/")
    assert opengrep.rule_gaps(doc) == []
    empty = {"paths": {"scanned": []}, "skipped_rules": [], "errors": [], "results": []}
    assert opengrep.rule_gaps(empty) == ["rule applied to no file"]
    skipped = {
        "paths": {"scanned": ["a.py"]},
        "skipped_rules": [{"rule_id": "x"}],
        "errors": [],
        "results": [],
    }
    assert opengrep.rule_gaps(skipped) == ["rule skipped by the tool"]


def test_python_parse_check(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n")
    (tmp_path / "A.java").write_text("class (")
    assert opengrep.unparseable_python(tmp_path, ["ok.py", "bad.py", "A.java"]) == ["bad.py"]


# ---------- staging parity with the open-time digest (AC-002B-03a, 03k)


@posix_only
def test_stage_digest_equals_snapshot_and_links_not_copied(tmp_path):
    from x_ipe_secure_code.guard import targets

    root = tmp_path / "p"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n")
    (root / "src" / "pkg" / "b.py").write_text("y = 2\n")
    os.symlink(root / "src" / "a.py", root / "src" / "link.py")
    os.mkfifo(root / "src" / "fifo")
    (root / ".git").mkdir()
    expected = targets.snapshot(root, "src", "dir")["digest"]
    staged = targets.stage(root, "src", "dir", tmp_path / "stage", 10_000, 100)
    assert staged["digest"] == expected
    assert sorted(staged["files"]) == ["src/a.py", "src/pkg/b.py"]
    assert sorted(staged["irregular"]) == ["src/fifo", "src/link.py"]
    assert (tmp_path / "stage" / "src" / "pkg" / "b.py").read_text() == "y = 2\n"
    assert not (tmp_path / "stage" / "src" / "link.py").exists()
    whole = targets.stage(root, ".", "dir", tmp_path / "stage2", 10_000, 100)
    assert whole["digest"] == targets.snapshot(root, ".", "dir")["digest"]
    with pytest.raises(safe_io.TooLarge):
        targets.stage(root, "src", "dir", tmp_path / "stage3", 3, 100)
    with pytest.raises(safe_io.TooLarge):
        targets.stage(root, "src", "dir", tmp_path / "stage4", 10_000, 1)
    file_stage = targets.stage(root, "src/a.py", "file", tmp_path / "stage5", 100, 1)
    assert file_stage["digest"] == targets.snapshot(root, "src/a.py", "file")["digest"]


# ---------- code review regressions (TASK-030)


def test_argv_disables_git_ignore():
    argv = opengrep.build_argv(Path("/s/bin/opengrep"), Path("/s/rules/1-1.yaml"), [Path("/s/src/a")], False)
    assert "--no-git-ignore" in argv


@pytest.mark.parametrize(
    "doc",
    [
        {"results": [], "paths": {"scanned": 3}},
        {"results": [], "paths": {"scanned": [], "skipped": "x"}},
        {"results": [1], "paths": {"scanned": []}},
        {"results": [], "paths": {"scanned": [1]}},
        {"results": [], "paths": {"scanned": []}, "errors": ["oops"]},
        {"results": [], "paths": {"scanned": []}, "skipped_rules": 5},
    ],
)
def test_parse_rejects_malformed_shapes(tmp_path, doc):
    path = tmp_path / "out.json"
    path.write_text(json.dumps(doc))
    assert opengrep.parse(path) is None


def test_results_tolerate_odd_positions():
    found, _ = opengrep.results(
        {
            "results": [{"check_id": "r", "path": "a.py", "start": [1], "end": 5}],
            "paths": {"scanned": ["a.py"]},
        },
        "r",
    )
    assert found[0]["line"] is None and found[0]["end_line"] is None


@posix_only
def test_stage_non_utf8_name_is_irregular_and_serializable(tmp_path):
    from x_ipe_secure_code.atomic import dumps_json
    from x_ipe_secure_code.guard import targets

    root = tmp_path / "p"
    (root / "src").mkdir(parents=True)
    try:
        fd = os.open(os.fsencode(root / "src") + b"/bad\xff.py", os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(fd, b"x = 1\n")
        os.close(fd)
    except (OSError, UnicodeError):
        pytest.skip("file system rejects non-UTF-8 names")
    staged = targets.stage(root, "src", "dir", tmp_path / "stage", 10_000, 100)
    assert staged["digest"] == targets.snapshot(root, "src", "dir")["digest"]
    assert staged["files"] == [] and staged["irregular"] == ["src/bad\\xff.py"]
    dumps_json(staged)


@posix_only
@pytest.mark.parametrize("has_waitid", [True, False])
def test_process_stop_and_exit_paths_with_and_without_waitid(tmp_path, monkeypatch, has_waitid):
    """Both leader-supervision strategies stop the group and report its exit (no waitid: macOS < 3.13)."""
    if has_waitid and not process.HAS_WAITID:
        pytest.skip("os.waitid not available on this Python")
    monkeypatch.setattr(process, "HAS_WAITID", has_waitid)
    marker = tmp_path / "child.pid"
    tool = _script(
        tmp_path,
        f"p = subprocess.Popen(['sleep', '60']); open({str(marker)!r}, 'w').write(str(p.pid)); "
        "time.sleep(60)",
    )
    res = process.run(
        [str(tool)],
        tmp_path,
        {"PATH": os.defpath},
        time.monotonic() + 60,
        tmp_path / "o",
        1024,
        should_stop=lambda: marker.exists(),
    )
    assert res.cancelled and res.group_gone
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)
    quick = _script(tmp_path, "print('done')")
    ok = process.run(
        [str(quick)], tmp_path, {"PATH": os.defpath}, time.monotonic() + 30, tmp_path / "o2", 1024
    )
    assert ok.exit == 0 and not ok.cancelled and ok.group_gone


@posix_only
def test_group_probe_counts_exited_zombie_members_as_gone():
    """Bug fix TASK-039: killed Opengrep workers linger as zombies; exited members are not survivors."""
    z = subprocess.Popen(["true"], start_new_session=True)
    try:
        if process.HAS_WAITID:
            os.waitid(os.P_PID, z.pid, os.WEXITED | os.WNOWAIT)  # exited, still unreaped (zombie)
        else:
            time.sleep(1.0)
        try:
            os.killpg(z.pid, 0)
        except ProcessLookupError:
            pytest.skip("this platform does not report zombie-only groups to signal 0")
        except PermissionError:
            pass  # macOS answers EPERM for a zombie-only group
        assert process._group_gone(z.pid) is True
    finally:
        z.wait()


@posix_only
def test_group_probe_live_member_is_not_gone():
    live = subprocess.Popen(["sleep", "30"], start_new_session=True)
    try:
        assert process._group_gone(live.pid, wait=0.3) is False
    finally:
        live.kill()
        live.wait()


def test_live_members_parses_proc_bytes_with_odd_names(tmp_path):
    """Review fix TASK-039: process names are raw bytes (truncated UTF-8, spaces, parentheses)."""
    proc = tmp_path / "proc"
    (proc / "self").mkdir(parents=True)
    (proc / "self" / "stat").write_bytes(b"1 (x) S 0 1 1")

    def entry(pid: int, comm: bytes, state: bytes, pgrp: int) -> None:
        (proc / str(pid)).mkdir()
        (proc / str(pid) / "stat").write_bytes(b"%d (" % pid + comm + b") " + state + b" 1 %d 1 0" % pgrp)

    entry(10, "a日本語のプログラム".encode()[:15], b"Z", 77)
    entry(11, b"we) ird (x", b"Z", 77)
    assert process._live_members(77, proc=proc) is False
    entry(12, b"\xff\xfe worker", b"S", 77)
    assert process._live_members(77, proc=proc) is True
    assert process._live_members(78, proc=proc) is False
