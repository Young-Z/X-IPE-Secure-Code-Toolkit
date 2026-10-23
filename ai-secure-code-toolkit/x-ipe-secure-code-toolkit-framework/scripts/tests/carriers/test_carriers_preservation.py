"""FEATURE-003-B integration tests: idempotency, preservation and concurrency (AC-003B-04a…04i)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest
from carhelp import (
    AGENTS,
    BEGIN,
    END,
    ENV,
    FRONT_MATTER,
    HOST,
    INSTR,
    KINDS,
    PATHS,
    RECORD,
    SYSP,
    allow,
    baseline_001a,
    begin_count,
    codes,
    entry,
    hold_project_lock,
    init_001a_sequence,
    inner,
    listing,
    sandbox,
    sha_text,
    simulate_no_lock_platform,
    split_outside,
    toolkit_copy,
    watch_writes,
    write_audit,
)
from conftest import LAUNCHER

from x_ipe_secure_code.environments import PROFILES


def _ok(proc, out):
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return out


# ---------------------------------------------------------------- AC-003B-04a

@pytest.mark.parametrize("style", ["lf", "crlf"])
def test_04a_outside_bytes_identical_lf_crlf_non_ascii(tmp_path, style):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    nl = "\r\n" if style == "crlf" else "\n"
    outside = {}
    for kind in KINDS:
        head, block, tail = split_outside(box.read(PATHS[kind]))
        lead = "Équipe — règles ü 日本\nMentions secure-code but is ours.\n\n"
        if kind == "github-instructions":
            new_head = head.decode() + lead  # user text between the front matter and the markers
        else:
            new_head = lead + head.decode()
        new = (new_head + block.decode() + tail.decode() + "\nTrailing user text ✓\n").replace("\n", nl)
        box.write(PATHS[kind], new.encode("utf-8"))
        outside[kind] = split_outside(box.read(PATHS[kind]))
    box.edit_definition()
    out = _ok(*box.carriers())
    assert [entry(out, k)["state"] for k in KINDS] == ["updated"] * 3
    for kind in KINDS:
        head, block, tail = split_outside(box.read(PATHS[kind]))
        assert head == outside[kind][0] and tail == outside[kind][2]  # bytes outside the boundaries identical
        assert block != outside[kind][1] and b"Keep the change small." in block
        if style == "crlf":
            assert block.count(b"\n") == block.count(b"\r\n")  # managed content in the file's newline style
        else:
            assert b"\r" not in block
    assert box.read(INSTR).startswith(FRONT_MATTER.replace("\n", nl).encode())


# ---------------------------------------------------------------- AC-003B-04b

def test_04b_unchanged_inputs_write_nothing_record_identical(tmp_path):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    before, record = box.hashes(), box.read(RECORD)
    with watch_writes() as writes:
        out = _ok(*box.select_all())
        again = _ok(*box.carriers())
    assert writes == []
    assert box.hashes() == before and box.read(RECORD) == record
    for result in (out, again):
        assert [entry(result, k)["state"] for k in KINDS] == ["current"] * 3
        assert result["data"]["record_written"] is False
    for kind in KINDS:
        assert begin_count(box.read(PATHS[kind])) == 1


# ---------------------------------------------------------------- AC-003B-04c

def test_04c_toolkit_mentions_outside_markers_not_taken_over(tmp_path):
    box = sandbox(tmp_path)
    body = inner(box.text(AGENTS))
    mention = ("# Team\n\nWe use `secure-code`, x-ipe-secure-code-toolkit-copilot and "
               "x-ipe-secure-code-toolkit-guard; the AI Secure Code Toolkit is great.\n\n" + body + "\n")
    box.write(AGENTS, mention + box.text(AGENTS))
    box.edit_definition()
    out = _ok(*box.carriers())
    assert entry(out, "host-entry")["state"] == "updated"
    assert "FRAGMENT_EDITED" not in codes(out) and AGENTS not in out["data"].get("differences", {})
    assert box.text(AGENTS).startswith(mention)  # neither taken over nor replaced
    assert begin_count(box.read(AGENTS)) == 1

    head, _block, tail = split_outside(box.read(AGENTS))
    box.write(AGENTS, head + tail)  # only the pasted copy without markers remains
    out = _ok(*box.carriers())
    item = entry(out, "host-entry")
    assert item["state"] == "appended"
    assert "similar toolkit text found outside the fragment" in item["note"]
    assert box.read(AGENTS).startswith(head + tail) and begin_count(box.read(AGENTS)) == 1


# ---------------------------------------------------------------- AC-003B-04d

def _corrupt(data: bytes, how: str) -> bytes:
    if how == "non-utf8":
        return data + b"\xff\xfe\x00"
    text = data.decode()
    if how == "unmatched":
        return text.replace(END + "\n", "").encode()
    if how == "reversed":
        return text.replace(BEGIN, "@@B@@").replace(END, BEGIN).replace("@@B@@", END).encode()
    return (text + BEGIN + "\nsecond copy\n" + END + "\n").encode()  # duplicate


def _expected_code(kind: str, how: str) -> str:
    if how == "non-utf8":
        return "HOST_ENTRY_UNREADABLE" if kind == "host-entry" else "CARRIER_UNREADABLE"
    return "FRAGMENT_DUPLICATE" if how == "duplicate" else "FRAGMENT_MALFORMED"


@pytest.mark.parametrize("how", ["unmatched", "reversed", "duplicate", "non-utf8"])
@pytest.mark.parametrize("kind", KINDS)
def test_04d_malformed_duplicate_reversed_or_non_utf8_refuses_whole_run(tmp_path, kind, how):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    box.write(PATHS[kind], _corrupt(box.read(PATHS[kind]), how))
    box.edit_definition()  # the other carriers would need an update
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.carriers()
    assert proc.returncode == 1 and not out["ok"]
    assert codes(out) == [_expected_code(kind, how)]
    assert PATHS[kind] in out["problems"][0]["message"]
    assert box.hashes() == before and writes == []


def test_04d_every_affected_carrier_named_in_one_refusal(tmp_path):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    plan = {"host-entry": "duplicate", "github-instructions": "reversed", "system-prompt": "non-utf8"}
    for kind, how in plan.items():
        box.write(PATHS[kind], _corrupt(box.read(PATHS[kind]), how))
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.carriers()
    assert proc.returncode == 1
    found = {(p["code"], next(rel for rel in PATHS.values() if rel in p["message"])) for p in out["problems"]}
    assert found == {(_expected_code(kind, how), PATHS[kind]) for kind, how in plan.items()}
    assert box.hashes() == before and writes == []


# ---------------------------------------------------------------- AC-003B-04e

@pytest.mark.parametrize("case", ["agents-file-link", "instructions-folder-link", "carriers-folder-link",
                                  "claude-md-to-agents-md"])
def test_04e_symlinked_carrier_path_or_folder_refused(tmp_path, case):
    env = "claude-code" if case == "claude-md-to-agents-md" else ENV
    box = sandbox(tmp_path, env=env)
    args: tuple[str, ...] = ()
    if case == "agents-file-link":
        target = box.path("docs/agents.md")
        target.parent.mkdir()
        target.write_bytes(box.read(AGENTS))
        box.path(AGENTS).unlink()
        box.path(AGENTS).symlink_to(target)
        named = AGENTS
    elif case == "instructions-folder-link":
        box.path("docs/instr").mkdir(parents=True)
        box.path(".github/instructions").symlink_to(box.path("docs/instr"), target_is_directory=True)
        args, named = ("--select", "github-instructions"), ".github/instructions"
    elif case == "carriers-folder-link":
        box.path("docs/carriers").mkdir(parents=True)
        box.path(".x-ipe/private/secure-code/carriers").symlink_to(box.path("docs/carriers"),
                                                                    target_is_directory=True)
        args = ("--select", "system-prompt", "--system-prompt-host", HOST)
        named = ".x-ipe/private/secure-code/carriers"
    else:
        box.write(AGENTS, "# agents\n")
        box.path("CLAUDE.md").unlink()
        box.path("CLAUDE.md").symlink_to(box.path(AGENTS))
        named = "CLAUDE.md"
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.carriers(*args)
    assert proc.returncode == 1 and "PATH_UNSAFE" in codes(out)
    assert any(named in p["message"] for p in out["problems"] if p["code"] == "PATH_UNSAFE")
    assert box.hashes() == before and writes == []


# ---------------------------------------------------------------- AC-003B-04f

def test_04f_write_failure_reports_written_record_unchanged_rerun_converges(tmp_path, monkeypatch):
    from x_ipe_secure_code import carriers

    box = sandbox(tmp_path)
    real = carriers.atomic_write_bytes
    calls = {"n": 0}

    def flaky(path, data, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, data, **kwargs)

    monkeypatch.setattr(carriers, "atomic_write_bytes", flaky)
    record = box.read(RECORD)
    with allow(box.root):
        result = carriers.run(str(box.root), ENV, select=["github-instructions", "system-prompt"],
                              deselect=[], regenerate=[], accept=[], host=HOST)
    assert not result.ok and result.problems[-1].code == "IO_ERROR"
    assert result.data["written_before_failure"] == [INSTR]
    assert box.read(RECORD) == record  # the install record is not updated
    assert box.path(INSTR).exists() and not box.path(SYSP).exists()

    monkeypatch.setattr(carriers, "atomic_write_bytes", real)
    out = _ok(*box.select_all())
    assert [entry(out, k)["state"] for k in KINDS] == ["current", "current", "created"]
    member = box.record()["carriers"]
    assert member["selected"] == list(KINDS)
    for kind in KINDS:
        assert begin_count(box.read(PATHS[kind])) == 1
    assert member["entries"]["github-instructions"]["fragment_sha256"] == sha_text(inner(box.text(INSTR)))


# ---------------------------------------------------------------- AC-003B-04g

def test_04g_concurrent_runs_complete_or_refuse_locked(tmp_path):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    box.edit_definition()  # every run has something to write
    env = dict(os.environ)
    env.update(write_audit().child_env([box.root, box.trust, box.tmp / ".tmp"]))
    commands = [["init", "--env", ENV], ["carriers", "--env", ENV], ["init", "--env", ENV],
                ["carriers", "--env", ENV], ["carriers", "--env", ENV], ["init", "--env", ENV]]
    with watch_writes() as writes:
        started = time.monotonic()
        procs = [subprocess.Popen([sys.executable, str(LAUNCHER), "--test-trust-dir", str(box.trust),
                                   *argv, "--project", str(box.root), "--json"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
                 for argv in commands]
        results = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=120)
            results.append((proc.returncode, json.loads(stdout), time.monotonic() - started, stderr))
    for code, out, elapsed, stderr in results:
        if out["ok"]:
            assert code == 0, stderr
            continue
        assert codes(out) == ["LOCKED"] and code == 1, out  # complete under the lock, or refuse
        assert any("retry" in step.lower() for step in out["next_steps"])
        assert elapsed <= 10.0 + 5.0  # bounded wait (atomic.LOCK_TIMEOUT) plus scheduling margin
    for kind in KINDS:
        assert begin_count(box.read(PATHS[kind])) == 1
    record = box.record()
    assert record["fragment_sha256"] == sha_text(inner(box.text(AGENTS)))
    for kind in ("github-instructions", "system-prompt"):
        recorded = record["carriers"]["entries"][kind]["fragment_sha256"]
        assert recorded == sha_text(inner(box.text(PATHS[kind])))
    by_pid: dict[int, list[float]] = {}
    for item in writes:
        by_pid.setdefault(item["pid"], []).append(item["t"])
    spans = sorted((min(ts), max(ts)) for ts in by_pid.values())
    for (_s1, e1), (s2, _e2) in zip(spans, spans[1:], strict=False):
        assert e1 <= s2, spans  # no product write while another run held the lock
    final = _ok(*box.carriers())
    assert [entry(final, k)["state"] for k in KINDS] == ["current"] * 3


# ---------------------------------------------------------------- AC-003B-04h

def test_04h_held_lock_init_and_carriers_refuse_locked_after_bounded_wait(tmp_path):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    box.edit_definition()
    before, names = box.hashes(), listing(box.root)
    with hold_project_lock(box.root, 40), watch_writes() as writes:
        for run in (box.init, box.carriers):
            start = time.monotonic()
            proc, out = run()
            elapsed = time.monotonic() - start
            assert proc.returncode == 1 and codes(out) == ["LOCKED"], proc.stdout + proc.stderr
            assert any("retry" in step.lower() for step in out["next_steps"])
            assert 9.5 <= elapsed <= 10.0 + 5.0  # the existing 10.0 s lock timeout, then refusal
    assert writes == []
    assert box.hashes() == before and listing(box.root) == names  # nothing written, no lock file


# ---------------------------------------------------------------- AC-003B-04i (Unit, simulated platform)

def test_04i_windows_simulated_carriers_lock_unavailable_init_unchanged(tmp_path, monkeypatch):
    from x_ipe_secure_code import carriers
    from x_ipe_secure_code.project_init import initialize_project

    box = sandbox(tmp_path)
    era = toolkit_copy(tmp_path, era="001A")
    before, names = box.hashes(), listing(box.root)
    flock_calls = simulate_no_lock_platform(monkeypatch)
    with allow(box.root):
        result = carriers.run(str(box.root), ENV, select=[], deselect=[], regenerate=[], accept=[], host=None)
    assert not result.ok and [p.code for p in result.problems] == ["LOCK_UNAVAILABLE"]
    assert "B11" in result.problems[0].message + " ".join(result.next_steps)  # interim, open gap
    assert box.hashes() == before and listing(box.root) == names  # no lock file, nothing written

    for env, profile in PROFILES.items():
        root = tmp_path / f"win {env} ü"
        root.mkdir()

        def run_init(*args, json_out=True, root=root, env=env):
            replace = [args[1]] if args else None
            with allow(root):
                res = initialize_project(str(root), env, replace, str(era))
            return (0 if res.ok else 1), (res.to_json() if json_out else res.to_text())

        steps = init_001a_sequence(run_init, root, profile.host_entry)
        assert steps == baseline_001a()["sequences"][env]  # exactly the delivered FEATURE-001-A behaviour
        assert not any("lock" in rel for rel in listing(root / ".x-ipe"))
    assert flock_calls == []  # no lock attempt at all on that platform


def test_project_lock_creates_no_file(tmp_path):
    from x_ipe_secure_code.atomic import ProjectLock

    box = sandbox(tmp_path)
    parent_before, names = listing(box.root.parent), listing(box.root)
    _ok(*box.carriers())
    _ok(*box.init())
    with ProjectLock(box.root):
        assert listing(box.root) == names
    assert listing(box.root) == names and listing(box.root.parent) == parent_before
