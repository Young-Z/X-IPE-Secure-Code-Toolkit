"""FEATURE-001-E integration/unit tests: private Reference cache (AC-001E-03a…03c, 03h…03k, 08a, 08b, 08e,
08g, 08h). Entries are built by a test-only helper (no network) except where a fetch is the subject."""

from __future__ import annotations

import json
import os
import stat
import threading
from datetime import timedelta

import pytest
import refhelp
from conftest import tree_hashes
from knowledge.exithelp import item, need_symlinks
from netguard import network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CACHE,
    CWE79,
    CWE89,
    REQUIREMENT,
    T0,
    built_entry,
    mod,
    rule_item,
    seed,
)

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures


def entry_file(env, rule=CWE79):
    files = [p for p in env.entry_files() if json.loads(p.read_text())["rule"] == rule]
    assert len(files) == 1, files
    return files[0]


def resolved(env, rule=CWE79):
    return env.entry(rule)


# AC-001E-03a
def test_entry_fields_and_policy_state_digest_inputs(renv, clock):
    renv.standard(CWE79)
    before = tree_hashes(renv.project / "x-ipe-docs")
    published = seed(renv)
    assert published.written and published.generation == 1
    path = entry_file(renv)
    data = json.loads(path.read_text())
    assert path.parent == renv.project / CACHE / "entries" and path.name == data["key"] + ".json"
    assert data["fetched_at"] == "2026-10-24T01:00:00Z" and data["expires_at"] == "2026-10-31T01:00:00Z"
    assert data["canonical_url"] == renv.url("/docs/cwe/79.html")
    assert data["registration_digest"] == renv.registration_digest()
    assert data["parser_version"] == "reference-parse/1" and data["response_digest"].startswith("sha256:")
    cache = mod("reference.cache")
    assert data["policy_state_digest"] == cache.policy_state_digest(
        CWE79, "Cross-site Scripting", "unknown", renv.url("/docs/cwe/79.html"), REQUIREMENT
    )
    assert "body" not in data and data["text"] == REQUIREMENT
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((renv.project / CACHE).stat().st_mode) == 0o700
    assert tree_hashes(renv.project / "x-ipe-docs") == before


def test_policy_state_digest_exclusions():
    cache = mod("reference.cache")
    base = dict(
        rule=CWE79,
        title="T",
        applicability="unknown",
        entry_url="http://127.0.0.1:1/docs/cwe/79.html",
        text="Requirement",
    )
    digest = cache.policy_state_digest(**base)
    for key, value in (
        ("title", "T2"),
        ("applicability", ["python"]),
        ("entry_url", "http://127.0.0.1:1/x"),
        ("text", "Other"),
        ("rule", CWE89),
    ):
        assert cache.policy_state_digest(**{**base, key: value}) != digest
    assert cache.policy_state_digest(**base, parser_version="reference-parse/2") != digest
    # fetch-instance metadata is not an input: two entries differing only there share the digest
    common = dict(
        kind="rule",
        rule={"rule": CWE79, "title": "T", "applicability": "unknown"},
        explore_url=None,
        canonical_url=base["entry_url"],
        reg_digest="sha256:" + "a" * 64,
        text="Requirement",
        masking={"applied": False, "kinds": []},
        links=[],
        links_truncated=False,
    )
    one = cache.build_entry(
        **common,
        fetched_at=T0,
        http_status=200,
        content_type="text/html",
        response_digest="sha256:" + "1" * 64,
    )
    two = cache.build_entry(
        **{
            **common,
            "reg_digest": "sha256:" + "b" * 64,
            "masking": {"applied": True, "kinds": ["credential.token"]},
        },
        fetched_at=T0 + timedelta(days=3),
        http_status=203,
        content_type="text/plain",
        response_digest="sha256:" + "2" * 64,
    )
    assert one["policy_state_digest"] == two["policy_state_digest"] == digest


# AC-001E-03b
def test_reads_never_renew(renv, clock):
    renv.standard(CWE79)
    seed(renv)
    raw = entry_file(renv).read_bytes()
    for delta in (dict(days=1), dict(days=5, hours=23)):
        clock.advance(**delta)
        found = resolved(renv)
        assert found["availability"] == "available" and found["retrieval_status"] == "cached", found
        assert found["source_evidence"]["expires_at"] == "2026-10-31T01:00:00Z"
    assert entry_file(renv).read_bytes() == raw and renv.srv.count == 0


# AC-001E-03c
@pytest.mark.parametrize("delta", [dict(days=7), dict(days=8)])
def test_expired_entry_missing_cache_expired(renv, clock, delta):
    renv.standard(CWE79)
    seed(renv)
    clock.advance(**delta)
    found = resolved(renv)
    assert found["availability"] == "missing" and found["reason"] == "cache_expired", found
    assert found["fetched_at"] == "2026-10-24T01:00:00Z" and found["expires_at"] == "2026-10-31T01:00:00Z"
    assert "requirement" not in found and REQUIREMENT not in json.dumps(found)


# AC-001E-03h
@pytest.mark.parametrize("case", ["future", "digest", "truncated_json", "schema"])
def test_future_or_corrupt_entry_cache_invalid(renv, clock, case):
    renv.standard(CWE79)
    seed(renv)
    path = entry_file(renv)
    data = json.loads(path.read_text())
    if case == "future":
        clock.advance(hours=-1)
    elif case == "digest":
        data["text"] = "Tampered requirement"
        path.write_text(json.dumps(data))
    elif case == "truncated_json":
        path.write_bytes(path.read_bytes()[:-40])
    else:
        data["schema"] = "ai-secure-code-toolkit/reference-cache-entry/v9"
        path.write_text(json.dumps(data))
    found = resolved(renv)
    assert found["availability"] == "missing" and found["reason"] == "cache_invalid", found
    assert "Tampered" not in json.dumps(found) and "requirement" not in found


# AC-001E-03i
def test_key_mismatch_registration_or_parser_version(renv, clock):
    cache = mod("reference.cache")
    key = cache.cache_key("rule", CWE79, "http://127.0.0.1:1/docs/cwe/79.html", "sha256:" + "a" * 64)
    assert cache.cache_key("rule", CWE79, "http://127.0.0.1:1/docs/cwe/79.html", "sha256:" + "b" * 64) != key
    assert (
        cache.cache_key(
            "rule", CWE79, "http://127.0.0.1:1/docs/cwe/79.html", "sha256:" + "a" * 64, "reference-parse/2"
        )
        != key
    )
    renv.standard(CWE79)
    entry, _ = built_entry(renv)
    durable = mod("knowledge.durable")
    with durable.Tree(renv.project) as tree:
        other = cache.cache_key(
            "rule", CWE79, entry["canonical_url"], entry["registration_digest"], "reference-parse/0"
        )
        assert cache.read_state(tree, other, T0).state == "not_cached"
    old = {**entry, "parser_version": "reference-parse/0", "generation": 1}
    old["key"] = cache.cache_key(
        "rule", CWE79, old["canonical_url"], old["registration_digest"], "reference-parse/0"
    )
    old["policy_state_digest"] = cache.policy_state_digest(
        CWE79, old["title"], old["applicability"], old["canonical_url"], old["text"], "reference-parse/0"
    )
    old["entry_digest"] = cache.entry_digest(old)
    folder = renv.project / CACHE / "entries"
    folder.mkdir(parents=True)
    (folder / f"{old['key']}.json").write_text(json.dumps(old))
    found = resolved(renv)
    assert found["availability"] == "missing" and found["reason"] == "not_cached", found
    seed(renv)
    assert resolved(renv)["retrieval_status"] == "cached"


# AC-001E-03j
def test_clean_removes_only_expired_invalid_orphaned(renv, clock):
    renv.standard(CWE79, CWE89)
    seed(renv, CWE89)
    clock.advance(days=3)
    seed(renv, CWE79)
    clock.advance(days=5)
    cache = mod("reference.cache")
    entries = renv.project / CACHE / "entries"
    orphan, _ = built_entry(renv, CWE79, record_over={"title": "Old title"})
    orphan = {**orphan, "generation": 1}
    orphan["entry_digest"] = cache.entry_digest(orphan)
    (entries / f"{orphan['key']}.json").write_text(json.dumps(orphan))
    (entries / ("f" * 64 + ".json")).write_text("{not json")
    (entries / ".abc.123.dead.tmp").write_text("partial")
    protected = {
        d: tree_hashes(renv.project / "x-ipe-docs" / "secure-code" / d)
        for d in ("knowledge", "scopes", "presets", "tags")
    }
    result = renv.service.cache_clean(str(renv.project))
    assert result.ok, result.to_dict()
    reasons = sorted(r["reason"] for r in result.data["removed"])
    assert reasons == ["expired", "invalid", "orphaned", "stale_temporary"], result.data
    left = [json.loads(p.read_text()) for p in renv.entry_files()]
    assert [(e["rule"], e["title"]) for e in left] == [(CWE79, "Cross-site Scripting")]
    assert {d: tree_hashes(renv.project / "x-ipe-docs" / "secure-code" / d) for d in protected} == protected
    assert resolved(renv, CWE79)["retrieval_status"] == "cached"


# AC-001E-03k
def test_capacity_evicts_expired_then_not_written(renv, clock):
    renv.standard(CWE79, CWE89)
    renv.register(rule_item("CWE/2024-top25/CWE-20", renv.url("/docs/cwe/20.html"), "Input Validation"))
    seed(renv, CWE89)
    clock.advance(days=8)
    size = entry_file(renv, CWE89).stat().st_size
    capacity = size + size // 2
    first = seed(renv, CWE79, capacity=capacity)
    assert first.written, first
    assert [json.loads(p.read_text())["rule"] for p in renv.entry_files()] == [CWE79]
    kept = entry_file(renv, CWE79).read_bytes()
    second = seed(renv, "CWE/2024-top25/CWE-20", capacity=capacity)
    assert not second.written and second.note == "cache_not_written: capacity"
    assert entry_file(renv, CWE79).read_bytes() == kept and len(renv.entry_files()) == 1


# AC-001E-08a
def test_concurrent_fetch_same_key_one_complete_entry(renv, clock):
    renv.standard(CWE79)
    cache = mod("reference.cache")
    built = [built_entry(renv, text=f"Requirement version {n}.") for n in range(2)]
    barrier = threading.Barrier(3)
    results, seen, stop = [], [], threading.Event()
    durable = mod("knowledge.durable")

    def publish(entry, generation):
        barrier.wait()
        results.append(
            cache.publish(
                renv.project,
                entry,
                start_generation=generation,
                fetch_digest=entry["registration_digest"],
                capacity=1 << 26,
            )
        )

    def reader():
        barrier.wait()
        with durable.Tree(renv.project) as tree:
            while not stop.is_set():
                seen.append(cache.read_state(tree, built[0][0]["key"], clock.now).state)

    workers = [threading.Thread(target=publish, args=b) for b in built] + [threading.Thread(target=reader)]
    for w in workers:
        w.start()
    for w in workers[:2]:
        w.join()
    stop.set()
    workers[2].join()
    assert sorted((r.written, r.note) for r in results) == [
        (False, "superseded_by_newer_fetch"),
        (True, None),
    ]
    assert len(renv.entry_files()) == 1 and set(seen) <= {"not_cached", "valid"}
    assert resolved(renv)["retrieval_status"] == "cached"


# AC-001E-08b
def test_interrupted_commit_ignored_and_cleaned(renv, clock, monkeypatch):
    renv.standard(CWE79)
    durable = mod("knowledge.durable")
    real_replace = os.replace

    def crash(src, dst, *args, **kwargs):
        if len(str(dst)) == 69 and str(dst).endswith(".json"):
            raise OSError(5, "simulated crash after staging")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", crash)
    monkeypatch.setattr(durable, "_remove_quietly", lambda *a, **k: None)
    with pytest.raises(OSError):
        seed(renv)
    monkeypatch.undo()
    entries = renv.project / CACHE / "entries"
    assert [p.name for p in entries.iterdir() if p.name.endswith(".tmp")]
    assert renv.entry_files() == []
    assert resolved(renv)["reason"] == "not_cached"
    cleaned = renv.service.cache_clean(str(renv.project))
    assert [r["reason"] for r in cleaned.data["removed"]] == ["stale_temporary"]
    assert list(entries.iterdir()) == []


# AC-001E-08e (cache part)
@pytest.mark.parametrize("where", ["cache_dir", "entries", "entry_file", "lock"])
def test_symlinks_refused_cache(renv, clock, tmp_path, where):
    need_symlinks(tmp_path)
    renv.standard(CWE79)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("untouched")
    private = renv.project / ".x-ipe/private/secure-code"
    if where == "cache_dir":
        (private / "reference-cache").symlink_to(outside, target_is_directory=True)
    elif where == "entries":
        (private / "reference-cache").mkdir(mode=0o700)
        (private / "reference-cache" / "entries").symlink_to(outside, target_is_directory=True)
    elif where == "entry_file":
        seed(renv)
        path = entry_file(renv)
        path.unlink()
        path.symlink_to(sentinel)
    else:
        (private / "locks" / "reference-cache.lock").symlink_to(sentinel)
    if where != "entry_file":
        with pytest.raises(mod("knowledge.durable").StoreError) as caught:
            seed(renv)
        assert caught.value.code == "PATH_UNSAFE"
    found = resolved(renv)
    assert found["availability"] == "missing" and found["reason"] in ("cache_invalid", "not_cached")
    cleaned = renv.service.cache_clean(str(renv.project))
    assert not cleaned.ok and cleaned.problems[0].code == "PATH_UNSAFE", cleaned.to_dict()
    assert sorted(os.listdir(outside)) == ["sentinel.txt"] and sentinel.read_text() == "untouched"


# AC-001E-08g (commit-time re-checks)
def test_commit_registration_changed_or_superseded(renv, clock):
    renv.standard(CWE79)
    cache = mod("reference.cache")
    entry, generation = built_entry(renv)
    ops = mod("reference.registry_ops")
    upd = ops.update(
        str(renv.project),
        rule=CWE79,
        registration_digest=renv.registration_digest(),
        changes={"title": "Renamed"},
        trust_paths=renv.paths,
    )
    assert upd.ok, upd.to_dict()
    late = cache.publish(
        renv.project,
        entry,
        start_generation=generation,
        fetch_digest=entry["registration_digest"],
        capacity=1 << 26,
    )
    assert not late.written and late.note == "registration_changed" and renv.entry_files() == []
    one, gen = built_entry(renv, text="First requirement.")
    two, gen2 = built_entry(renv, text="Second requirement.")
    assert gen == gen2 == 0
    assert cache.publish(
        renv.project, two, start_generation=gen2, fetch_digest=two["registration_digest"], capacity=1 << 26
    ).written
    older = cache.publish(
        renv.project, one, start_generation=gen, fetch_digest=one["registration_digest"], capacity=1 << 26
    )
    assert not older.written and older.note == "superseded_by_newer_fetch"
    assert json.loads(entry_file(renv).read_text())["text"] == "Second requirement."
    assert renv.load(item(CWE79)).ok
    three, gen3 = built_entry(renv, text="Third requirement.")
    local = cache.publish(
        renv.project,
        three,
        start_generation=gen3,
        fetch_digest=three["registration_digest"],
        capacity=1 << 26,
    )
    assert not local.written and local.local


# AC-001E-08h
def test_capacity_and_clean_under_one_lock(renv, clock):
    renv.standard(CWE79, CWE89)
    rules = [f"CWE/2024-top25/CWE-{n}" for n in range(100, 106)]
    renv.register(*[rule_item(r, renv.url(f"/docs/cwe/{r[-3:]}.html"), f"Rule {r}") for r in rules])
    seed(renv, CWE89)
    size = entry_file(renv, CWE89).stat().st_size
    clock.advance(days=8)
    seed(renv, CWE79)
    capacity = size * 3
    entries = renv.project / CACHE / "entries"
    over, stop = [], threading.Event()

    def watch():
        while not stop.is_set():
            total = 0
            for p in list(entries.iterdir()):
                if len(p.name) == 69 and p.name.endswith(".json"):
                    try:
                        total += p.stat().st_size
                    except FileNotFoundError:
                        pass
            if total > capacity:
                over.append(total)

    def publish(rule):
        seed(renv, rule, capacity=capacity)

    def clean():
        renv.service.cache_clean(str(renv.project))

    watcher = threading.Thread(target=watch)
    watcher.start()
    workers = [threading.Thread(target=publish, args=(r,)) for r in rules] + [threading.Thread(target=clean)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    stop.set()
    watcher.join()
    assert over == []
    states = [resolved(renv, r).get("retrieval_status") for r in (CWE79, *rules)]
    assert states[0] == "cached"  # the valid, unexpired entry was never evicted or cleaned
    assert sum(1 for s in states if s == "cached") <= 3


# AC-001E-08g / review finding 4: kind-aware revalidation at publication (registry changed while fetching)
@pytest.mark.parametrize(
    "case",
    [
        "rule-update",
        "rule-remove",
        "source-update",
        "source-remove",
        "explore-source-update",
        "explore-source-remove",
        "local-import",
    ],
)
def test_publish_revalidation_kind_aware(renv, clock, monkeypatch, case):
    from refhelp import page, source_item

    explore = case.startswith("explore")
    if case == "explore-source-remove":
        renv.register(source_item("CWE/explore", port=renv.srv.port, path_prefix="/docs/cwe/"))
    else:
        renv.standard(CWE79)
    renv.serve("/docs/cwe/79.html", page("cwe-79.html"))
    vid = renv.granted()
    ops = mod("reference.registry_ops")
    p = str(renv.project)
    parse = mod("reference.parse")
    real = parse.extract

    def change():
        if case == "rule-update":
            assert ops.update(
                p,
                rule=CWE79,
                registration_digest=renv.registration_digest(),
                changes={"title": "Changed"},
                trust_paths=renv.paths,
            ).ok
        if case in ("rule-remove", "source-remove"):
            shown = ops.remove_preview(p, CWE79, "withdrawn", trust_paths=renv.paths)
            assert ops.remove_confirm(
                p,
                CWE79,
                "withdrawn",
                shown.data["impact_digest"],
                renv.registration_digest(),
                trust_paths=renv.paths,
            ).ok
        if case == "source-remove":
            assert ops.remove_source(p, "CWE/2024-top25", renv.source_digest(), trust_paths=renv.paths).ok
        if case in ("source-update", "explore-source-update"):
            assert ops.update(
                p,
                source="CWE/2024-top25",
                registration_digest=renv.source_digest(),
                changes={"path_prefix": "/docs/"},
                trust_paths=renv.paths,
            ).ok
        if case == "explore-source-remove":
            assert ops.remove_source(
                p, "CWE/explore", renv.source_digest("CWE/explore"), trust_paths=renv.paths
            ).ok
        if case == "local-import":
            assert renv.load(item(CWE79)).ok

    def wrapped(*args, **kwargs):
        out = real(*args, **kwargs)
        change()  # after the response was received, before publication (no fetch lock is held here)
        return out

    monkeypatch.setattr(parse, "extract", wrapped)
    if explore:
        source = "CWE/explore" if case == "explore-source-remove" else "CWE/2024-top25"
        result = renv.explore(vid, renv.url("/docs/cwe/79.html"), source)
    else:
        result = renv.fetch(vid)
    if case == "local-import":
        assert result.ok and result.data["outcome"] == "local_used", result.to_dict()
    else:
        assert not result.ok and result.data["detail"] == "registration_changed", result.to_dict()
    assert renv.entry_files() == [] and not (renv.project / CACHE / "state.json").exists()
    assert renv.srv.count == 1
