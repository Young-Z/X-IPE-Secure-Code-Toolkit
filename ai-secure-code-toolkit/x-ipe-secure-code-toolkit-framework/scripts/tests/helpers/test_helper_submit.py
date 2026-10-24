"""FEATURE-002-F submission (AC-002F-01a, 02a–02c, 02e–02g, 03a, 12d; design §5)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import os

import pytest
from helperhelp import (  # noqa: F401 - fixture reuse
    METHOD,
    TMP,
    Flow,
    env,
    fake,
    flow,
    helper_check,
    helper_run,
    henv,
    mod,
    no_runtime,
    state_of,
)


def refused(out, code, *texts):
    assert not out.ok and out.problems[0].code == code, out.to_text()
    for text in texts:
        assert text in out.problems[0].message, out.problems[0].message


def stored_helpers(env, vid):
    return state_of(env, vid).get("helpers") or []


# ---------- AC-002F-01a
def test_01a_check_binding_refusals(flow):
    vid = helper_run(flow.env)
    gen = flow.generation(vid)
    for over, text in (
        ({"check": None}, "missing: check"),
        ({"check": "C9"}, "not a planned check"),
        ({"method": "semantic-review"}, "not a helper method"),
        ({"method": "helper.other"}, "not a helper method"),
    ):
        refused(flow.submit(vid, flow.request(vid, gen, **over)), "HELPER_INVALID", text)
    other = helper_run(flow.env)
    refused(
        flow.submit(other, flow.request(other, gen)), "ATTEMPT_INVALID", "belongs to another verification"
    )
    assert (
        stored_helpers(flow.env, vid) == []
        and not (flow.root / ".x-ipe/private/secure-code/guard" / vid / "helpers").exists()
    )


# ---------- AC-002F-02a
@pytest.mark.parametrize(
    "field", ["goal", "read_scope", "judgement_basis", "language", "script_file", "samples"]
)
def test_02a_missing_field_named(flow, field):
    vid = helper_run(flow.env)
    doc = flow.request(vid, flow.generation(vid))
    del doc[field]
    refused(flow.submit(vid, doc), "HELPER_INVALID", f"missing: {field}")
    assert stored_helpers(flow.env, vid) == []


def test_02a_stored_declaration_has_all_fields(flow):
    vid = helper_run(flow.env)
    out = flow.submit(vid)
    assert out.ok, out.to_text()
    h = stored_helpers(flow.env, vid)[0]
    assert {h[k] is not None for k in ("check", "goal", "read_scope", "judgement_basis", "language")} == {
        True
    }
    assert h["language"] == "python" and h["script"]["sha256"].startswith("sha256:")
    stored = flow.root / ".x-ipe/private/secure-code/guard" / vid / h["script"]["file"]
    assert stored.read_text().startswith("RULE =") and stored.stat().st_mode & 0o777 == 0o444


# ---------- AC-002F-02b
def test_02b_scope_rules(flow):
    vid = helper_run(flow.env)
    gen = flow.generation(vid)
    root = flow.root
    os.symlink(root / "src" / "config", root / "src" / "linked")
    os.mkfifo(root / "src" / "fifo")
    cases = [
        (["src/linked"], "symbolic link"),
        (["src/linked/app.yaml"], "symbolic link"),
        (["../outside"], "inside the project"),
        (["/etc"], "inside the project"),
        (["src/fifo"], "not a regular file or folder"),
        (["README.md"], "not inside a verification target"),
        (["src/nope"], "does not exist"),
    ]
    for scope, text in cases:
        refused(flow.submit(vid, flow.request(vid, gen, read_scope=scope)), "HELPER_INVALID", text)
    big = root / "src" / "big"
    big.mkdir()
    (big / "huge.bin").write_bytes(b"\0" * (5 * 1024 * 1024 + 1))
    refused(flow.submit(vid, flow.request(vid, gen, read_scope=["src/big"])), "HELPER_LIMIT", "L-05")
    assert stored_helpers(flow.env, vid) == []


def test_02b_scope_with_a_link_inside_refused(flow):
    vid = helper_run(flow.env)
    os.symlink("app.yaml", flow.root / "src" / "config" / "alias.yaml")
    refused(flow.submit(vid), "HELPER_INVALID", "symbolic link")


# ---------- AC-002F-02c
def test_02c_compile_probe_syntax_version_unavailable(flow):
    vid = helper_run(flow.env)
    out = flow.submit(vid)
    assert out.ok and out.data["status"] == "checked", out.to_text()
    creates = flow.fake.creates()
    assert [c for c in creates if "x-ipe.secure-code.purpose=compile" in c] == creates and len(creates) == 1
    assert "/helper/launcher.py" in creates[0] and "compile" in creates[0]
    assert not any("/input" in a for a in creates[0])
    import json

    flow.fake.set(
        runs={
            "compile": {
                "mode": "stdout",
                "stdout": json.dumps(
                    {"ok": False, "version": [3, 12, 4], "error": "invalid syntax (line 3)"}
                ),
            }
        }
    )
    syntax = flow.submit(vid)
    refused(syntax, "HELPER_CHECK_FAILED", "syntax: invalid syntax (line 3)")
    flow.fake.set(
        runs={
            "compile": {
                "mode": "stdout",
                "stdout": json.dumps({"ok": True, "version": [3, 12, 9], "error": ""}),
            }
        }
    )
    refused(flow.submit(vid), "HELPER_CHECK_FAILED", "version: image interpreter changed")
    flow.fake.set(runs={}, fail={"version": {"exit": 1, "stderr": "Cannot connect to the Docker daemon"}})
    refused(flow.submit(vid), "HELPER_CHECK_FAILED", "compile probe unavailable")
    states = [h["status"] for h in stored_helpers(flow.env, vid)]
    assert states == ["checked", "check_failed", "check_failed", "check_failed"]
    assert all(e["step"] != "target_run_started" for h in stored_helpers(flow.env, vid) for e in h["events"])


# ---------- AC-002F-02e
def test_02e_state_checked_not_reviewed(flow):
    vid = helper_run(flow.env)
    out = flow.submit(vid)
    shown = mod("grant").show(str(flow.root), vid)
    entry = shown.data["helpers"][0]
    assert entry["state"] == "checked" and entry["review"] == "not reviewed"
    assert entry["grant"] == "not granted" and entry["execution"] == "not executed"
    assert out.data["checks"]["statement"].startswith("Static rules are defence in depth only")


# ---------- AC-002F-02f (no probe for oversize/over-deep scripts)
def test_02f_oversize_and_deep_no_probe(flow):
    vid = helper_run(flow.env)
    gen = flow.generation(vid)
    doc = flow.request(vid, gen, script_file=flow.file("big.py", "x = 1\n" * 2001))
    refused(flow.submit(vid, doc), "HELPER_CHECK_FAILED", "L-03")
    gen2 = flow.generation(vid)
    deep = "x = " + "[" * 60 + "]" * 60 + "\n"
    refused(
        flow.submit(vid, flow.request(vid, gen2, script_file=flow.file("deep.py", deep))),
        "HELPER_CHECK_FAILED",
        "L-04",
    )
    assert flow.fake.creates() == []


# ---------- AC-002F-02g
def test_02g_sixth_helper_refused(flow):
    vid = helper_run(flow.env)
    for _ in range(5):
        assert flow.submit(vid).ok
    refused(flow.submit(vid), "HELPER_LIMIT", "at most 5 helpers")
    assert len(stored_helpers(flow.env, vid)) == 5


# ---------- AC-002F-03a
def test_03a_samples_origin_limits(flow):
    vid = helper_run(flow.env)
    gen = flow.generation(vid)
    pos = {
        "kind": "positive",
        "origin": {"type": "synthetic"},
        "path": "src/config/app.yaml",
        "content_file": flow.file("p.yaml", "debug: true\n"),
    }
    neg = {**pos, "kind": "negative", "content_file": flow.file("n.yaml", "debug: false\n")}
    cases = [
        ([pos], "at least one positive and one negative"),
        ([neg], "at least one positive and one negative"),
        (
            [{**pos, "content_file": "src/config/db.yaml"}, neg],
            "a verification target file cannot be a sample",
        ),
        (
            [{**pos, "content_file": flow.file("copy.yaml", "host: db\n")}, neg],
            "a verification target file cannot be a sample",
        ),
        (
            [
                {**pos, "origin": {"type": "formal_example", "rule": "CWE/4.14/CWE-79", "example": "python"}},
                neg,
            ],
            "formal example has no explicit safe/unsafe label",
        ),
        ([{**pos, "path": "README.md"}, neg], "not under the read scope"),
    ]
    for samples, text in cases:
        refused(flow.submit(vid, flow.request(vid, gen, samples=samples)), "HELPER_INVALID", text)
    refused(flow.submit(vid, flow.request(vid, gen, samples=[pos] * 6 + [neg])), "HELPER_LIMIT", "L-02")
    huge = {**pos, "content_file": flow.file("huge.yaml", "a" * (64 * 1024 + 1))}
    refused(flow.submit(vid, flow.request(vid, gen, samples=[huge, neg])), "HELPER_LIMIT", "L-02")
    assert flow.submit(vid, flow.request(vid, gen, samples=[pos, neg])).ok
    stored = stored_helpers(flow.env, vid)[0]["samples"]
    assert [(s["kind"], s["origin"]["type"]) for s in stored] == [
        ("positive", "synthetic"),
        ("negative", "synthetic"),
    ]
    assert all(s["sha256"].startswith("sha256:") for s in stored)


# ---------- AC-002F-12d
def test_12d_declaration_immutable(flow):
    vid = helper_run(flow.env)
    first = flow.submit(vid)
    h1 = stored_helpers(flow.env, vid)[0]
    changed = flow.submit(vid, flow.request(vid, flow.generation(vid), read_scope=["src"]))
    assert changed.ok and changed.data["helper"] != first.data["helper"]
    assert stored_helpers(flow.env, vid)[0] == {**h1, "events": stored_helpers(flow.env, vid)[0]["events"]}
    assert stored_helpers(flow.env, vid)[1]["helper_digest"] != h1["helper_digest"]
    # no command edits a stored declaration: a request naming an existing helper id is not accepted
    refused(
        flow.submit(vid, {**flow.request(vid, flow.generation(vid)), "id": first.data["helper"]}),
        "HELPER_INVALID",
        "unknown fields: id",
    )


def test_05a_submit_without_runtime_check_failed_no_host_fallback(henv, no_runtime):
    flow = Flow(henv)
    vid = helper_run(henv)
    out = flow.submit(vid)
    refused(out, "HELPER_CHECK_FAILED", "compile probe unavailable", "no container runtime CLI")
    assert stored_helpers(henv, vid)[0]["status"] == "check_failed"
    assert (henv["project"] / TMP).is_dir()
    assert METHOD in {e["method"] for e in state_of(henv, vid)["evidence"]}
