"""Crash-atomic provisioning journal, deterministic recovery and coherent read-only status (FEATURE-002-D).

AC-002D-02c (interrupted operations reported, previous state kept) and AC-002D-08a (status coherent and
read-only). Crashes are injected by raising `SystemExit` at the four points of the technical design:
before the pointer swap (journal written), after the swap before the state write, after the state
replacement, and after GC started; recovery then runs in a fresh call.
"""

# ruff: noqa: F811
from __future__ import annotations

import json

import pytest
from conftest import posix_only, tree_hashes
from trivyhelp import (  # noqa: F401 - fixture reuse
    CACHE,
    GUARD,
    POM_COMPLETE,
    calls,
    env,
    gen_dir,
    grant_for,
    linux,
    planned,
    pointer,
    provision,
    remove,
    scan,
    state,
    tcheck,
    trc,
    trivy,
    trivy_status,
    write,
)

from x_ipe_secure_code.guard import runs
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.knowledge import durable

pytestmark = posix_only


class _Lazy:
    def __init__(self, name):
        self._name = name

    def __getattr__(self, attr):
        import importlib

        return getattr(importlib.import_module(f"x_ipe_secure_code.adapters.{self._name}"), attr)

    def __setattr__(self, attr, value):
        if attr == "_name":
            object.__setattr__(self, attr, value)
            return
        import importlib

        setattr(importlib.import_module(f"x_ipe_secure_code.adapters.{self._name}"), attr, value)


trivy_cache, trivy_journal = _Lazy("trivy_cache"), _Lazy("trivy_journal")
POINTS = ("before-swap", "after-swap", "after-state", "after-gc-started")


def journal_path(env):
    return env["project"] / CACHE / "journal.json"


def generations(env, component="vulnerability_db"):
    folder = env["project"] / CACHE / "gen" / component
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


def crash(point):
    """Make the next final provisioning commit crash at `point` (the process 'dies': SystemExit).

    Returns a function restoring the real functions (the fixture's host and digest patches stay active).
    """
    real_commit, real_write, real_gc = runs.commit_state, runs.write_state, trivy_cache.collect_garbage

    def commit(root, st, *, expected_revision, on_commit=None):
        if on_commit is None:
            return real_commit(root, st, expected_revision=expected_revision)
        if point == "before-swap":
            raise SystemExit("crash before swap")
        if point == "after-swap":

            def die(*_a, **_k):
                raise SystemExit("crash after swap")

            runs.write_state = die
        if point == "after-state":

            def write_then_die(root_, st_):
                real_write(root_, st_)
                raise SystemExit("crash after state replacement")

            runs.write_state = write_then_die
        return real_commit(root, st, expected_revision=expected_revision, on_commit=on_commit)

    def gc_dies(*_a, **_k):
        raise SystemExit("crash after GC started")

    runs.commit_state = commit
    if point == "after-gc-started":
        trivy_cache.collect_garbage = gc_dies

    def restore():
        runs.commit_state, runs.write_state, trivy_cache.collect_garbage = real_commit, real_write, real_gc

    return restore


def crashed_provision(env, vid, point):
    restore = crash(point)
    try:
        with pytest.raises(SystemExit):
            provision(env, vid, ["vulnerability_db"])
    finally:
        restore()


@pytest.fixture
def journaled(env, trivy, request):
    """Generation A provisioned; a second provisioning of the vulnerability DB (generation B) crashes."""
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    grant_for(env, vid)
    assert provision(env, vid, ["vulnerability_db"]).ok
    old_bytes = (env["project"] / CACHE / "components.json").read_bytes()
    gen_a = pointer(env)["components"]["vulnerability_db"]["generation"]
    crashed_provision(env, vid, request.param)
    return {"vid": vid, "old": old_bytes, "gen_a": gen_a, "point": request.param}


@pytest.mark.parametrize("journaled", POINTS, indirect=True)
def test_crash_points_leave_the_documented_intermediate_state(env, journaled):
    j, point = journaled, journaled["point"]
    on_disk = (env["project"] / CACHE / "components.json").read_bytes()
    entries = state(env, j["vid"]).get("tool_provisioning", [])
    if point == "after-gc-started":
        assert on_disk != j["old"] and len(entries) == 2
        return
    assert journal_path(env).exists()
    journal = json.loads(journal_path(env).read_text())
    assert journal["schema"] == "ai-secure-code-toolkit/trivy-journal/v1" and journal["op"] == "provision"
    assert journal["verification_id"] == j["vid"] and journal["new_generations"]
    if point == "before-swap":
        assert on_disk == j["old"] and len(entries) == 1
    elif point == "after-swap":
        assert on_disk != j["old"] and len(entries) == 1
    else:
        assert on_disk != j["old"] and len(entries) == 2


@pytest.mark.parametrize("journaled", ["before-swap"], indirect=True)
def test_crash_before_swap_rolls_back(env, journaled):
    _recover_and_check_rolled_back(env, journaled)


@pytest.mark.parametrize("journaled", ["after-swap"], indirect=True)
def test_crash_after_swap_rolls_back(env, journaled):
    _recover_and_check_rolled_back(env, journaled)


def _recover_and_check_rolled_back(env, j):
    trivy_journal.recover(env["project"])
    assert (env["project"] / CACHE / "components.json").read_bytes() == j["old"]
    assert generations(env) == [j["gen_a"]] and not journal_path(env).exists()
    entries = state(env, j["vid"])["tool_provisioning"]
    assert entries[-1]["outcome"] == "interrupted" and entries[-1]["previous"] == "kept"
    trivy_journal.recover(env["project"])  # idempotent
    assert (env["project"] / CACHE / "components.json").read_bytes() == j["old"]
    assert len(state(env, j["vid"])["tool_provisioning"]) == len(entries)


@pytest.mark.parametrize("journaled", ["after-state"], indirect=True)
def test_crash_after_state_replacement_rolls_forward(env, journaled):
    j = journaled
    new = json.loads(journal_path(env).read_text())
    trivy_journal.recover(env["project"])
    gen_b = pointer(env)["components"]["vulnerability_db"]["generation"]
    assert gen_b != j["gen_a"] and not journal_path(env).exists()
    assert "vulnerability_db/" + gen_b in new["new_generations"]
    assert generations(env) == [gen_b]  # replaced generation collected
    trivy_journal.recover(env["project"])
    assert pointer(env)["components"]["vulnerability_db"]["generation"] == gen_b


@pytest.mark.parametrize("journaled", ["after-gc-started"], indirect=True)
def test_crash_before_journal_removal_rolls_forward(env, journaled):
    j = journaled
    gen_b = pointer(env)["components"]["vulnerability_db"]["generation"]
    trivy_journal.recover(env["project"])
    trivy_cache.collect_garbage(env["project"])
    assert pointer(env)["components"]["vulnerability_db"]["generation"] == gen_b != j["gen_a"]
    assert not journal_path(env).exists() and generations(env) == [gen_b]
    entries = state(env, j["vid"])["tool_provisioning"]
    assert entries[-1]["operations"][0]["outcome"] == "completed"


@pytest.mark.parametrize("trigger", ["scan", "provision", "remove", "conclude"])
@pytest.mark.parametrize("journaled", ["before-swap"], indirect=True)
def test_recovery_runs_before_scan_provision_remove_gc_conclude(env, journaled, trivy, trigger):
    j = journaled
    assert journal_path(env).exists()
    if trigger == "scan":
        scan(env, j["vid"], [trc()])
    elif trigger == "provision":
        provision(env, j["vid"], ["checks_bundle"])
    elif trigger == "remove":
        remove(env, ["java_db"])
    else:
        guard.conclude(str(env["project"]), j["vid"])
    assert not journal_path(env).exists()
    assert pointer(env)["components"]["vulnerability_db"]["generation"] == j["gen_a"]
    assert generations(env) == [j["gen_a"]]


@pytest.mark.parametrize("journaled", ["before-swap"], indirect=True)
def test_gc_keeps_generations_referenced_by_a_journal(env, journaled):
    journal = json.loads(journal_path(env).read_text())
    trivy_cache.collect_garbage(env["project"])
    for gen in journal["new_generations"]:
        assert (env["project"] / CACHE / "gen" / gen).exists()


@pytest.mark.parametrize("journaled", ["after-swap"], indirect=True)
def test_status_evaluates_journal_read_only(env, journaled, trivy):
    before = tree_hashes(env["project"] / ".x-ipe")
    invoked = len(calls(trivy))
    t = trivy_status(env)
    assert tree_hashes(env["project"] / ".x-ipe") == before and len(calls(trivy)) == invoked
    assert t["recovery_pending"] is True and journal_path(env).exists()
    # not committed (state lacks the entry): the effective state is the old pointer
    assert t["components"]["vulnerability_db"]["generation"] == journaled["gen_a"]
    assert t["components"]["vulnerability_db"]["state"] == "present"


# ======================================================================= coherent lock-free status read
def _transition_on_second_journal_read(monkeypatch, apply, every=False):
    real = durable.read
    seen = {"journal": 0, "applied": 0}

    def read(dfd, name):
        if name == "journal.json":
            seen["journal"] += 1
            if seen["journal"] % 2 == 0 and (every or not seen["applied"]):
                apply()  # the transition happens between the first and the second read of a pass
                seen["applied"] += 1
        return real(dfd, name)

    monkeypatch.setattr(durable, "read", read)
    return seen


def _evaluate(env):
    return trivy_journal.evaluate(env["project"])


@pytest.mark.parametrize(
    "transition", ["journal-creation", "pointer-swap", "state-commit", "journal-removal"]
)
def test_status_coherent_read_retries_on_transition(env, trivy, monkeypatch, transition):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    grant_for(env, vid)
    assert provision(env, vid, ["vulnerability_db"]).ok
    gen_a = pointer(env)["components"]["vulnerability_db"]["generation"]
    point = {
        "journal-creation": "before-swap",
        "pointer-swap": "before-swap",
        "state-commit": "after-swap",
        "journal-removal": "after-state",
    }[transition]
    crashed_provision(env, vid, point)
    cache = env["project"] / CACHE
    journal_bytes = journal_path(env).read_bytes()
    journal = json.loads(journal_bytes)
    if transition == "journal-creation":
        journal_path(env).unlink()

        def apply():
            journal_path(env).write_bytes(journal_bytes)
    elif transition == "pointer-swap":
        import base64

        def apply():
            (cache / "components.json").write_bytes(base64.b64decode(journal["new_pointer"]["bytes_b64"]))
    elif transition == "state-commit":

        def apply():
            st = runs.read_state(env["project"], vid)
            st.setdefault("tool_provisioning", []).append(
                {
                    "n": journal["provisioning"],
                    "attempt": journal["attempt"],
                    "adapter": "trivy",
                    "operations": [],
                }
            )
            st["revision"] += 1
            runs.write_state(env["project"], st)
    else:

        def apply():
            journal_path(env).unlink()

    seen = _transition_on_second_journal_read(monkeypatch, apply)
    view = _evaluate(env)
    assert seen["applied"] == 1 and view["cache"] == "coherent" and view["attempts"] >= 2
    gen = view["components"]["vulnerability_db"]["generation"]
    if transition in ("state-commit", "journal-removal"):
        assert gen != gen_a  # the post-transition (committed) snapshot, never a mix
    else:
        assert gen == gen_a
    assert view["recovery_pending"] is (transition != "journal-removal")


def test_status_reports_busy_when_cache_keeps_changing(env, trivy, monkeypatch):
    write(env, {"pom.xml": POM_COMPLETE})
    vid = planned(env, [tcheck()])
    grant_for(env, vid)
    assert provision(env, vid, ["vulnerability_db"]).ok
    cache = env["project"] / CACHE
    pointer_path = cache / "components.json"
    original = pointer_path.read_bytes()
    flip = {"n": 0}

    def apply():
        flip["n"] += 1
        data = json.loads(original)
        data["revision"] = data.get("revision", 0) + flip["n"]
        pointer_path.write_text(json.dumps(data))

    journal_path(env).write_text(
        json.dumps(
            {
                "schema": "ai-secure-code-toolkit/trivy-journal/v1",
                "op": "provision",
                "verification_id": vid,
                "provisioning": 99,
                "attempt": "a-99",
                "old_pointer": None,
                "new_pointer": None,
                "new_generations": [],
                "replaced_generations": [],
            }
        )
    )
    _transition_on_second_journal_read(monkeypatch, apply, every=True)
    before = {p: p.read_bytes() for p in (env["project"] / ".x-ipe").rglob("*") if p.is_file()}
    view = _evaluate(env)
    assert view["cache"] == "busy" and view["recovery_pending"] is None
    for comp in view["components"].values():
        assert comp["state"] == "unreadable" and comp["reason"].startswith("busy:")
    after = {p: p.read_bytes() for p in before}
    changed = [p for p in before if after[p] != before[p] and p != pointer_path]
    assert changed == []  # evaluate itself wrote nothing
