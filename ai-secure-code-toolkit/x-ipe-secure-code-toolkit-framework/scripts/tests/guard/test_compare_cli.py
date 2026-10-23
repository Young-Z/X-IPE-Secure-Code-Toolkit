"""FEATURE-002-G: `secure-code guard compare` envelopes, refusals, integrity and bounds.

AC-002G-01b, 01c, 01g, 05a…05l, 06b, 06f; NFR-002G-5 limit tests; DAO-012 binding condition 2 (peak RSS).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import textwrap
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta

import pytest
import write_audit
from comparehelp import (
    CANARY,
    COMPARISONS,
    E_ID,
    GUARD,
    L_ID,
    OG_METHOD,
    R1,
    R2,
    REPORTS,
    X_ID,
    AccessRecorder,
    check,
    compare,
    compare_bounds,
    evidence,
    finding,
    freeze_clock,
    load_comparison,
    make_project,
    manifest,
    og,
    og_run,
    put,
    put_pair,
    result,
    run_compare,
)
from conftest import SRC

from x_ipe_secure_code import cli
from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.guard import report
from x_ipe_secure_code.project_init import initialize_project

MIB64 = 64 * 1024 * 1024


def refused(env, code):
    assert env["ok"] is False, env
    assert env["problems"][0]["code"] == code, env
    assert env["next_steps"] and env["next_steps"][0], env
    return env


def project_pair(tmp_path, e=None, lv=None, **kw):
    root = make_project(tmp_path)
    e, lv = put_pair(root, e, lv, **kw)
    return root, e, lv


# ------------------------------------------------------------------------------ AC-002G-01b / 01c / 01g
def test_01b_refuses_wrong_count_or_same_verification(tmp_path):
    root, _, _ = project_pair(tmp_path)
    before = manifest(root)
    md_name = f"{REPORTS}/{E_ID}.md"
    for earlier, later in (
        ((E_ID,), ()),
        ((E_ID, L_ID), (X_ID,)),
        ((E_ID, L_ID), ()),
        ((E_ID,), (E_ID,)),
        ((f"{REPORTS}/{E_ID}.json",), (md_name,)),
        ((), ()),
    ):
        env, code = run_compare(root, earlier, later)
        refused(env, "COMPARE_REQUEST_INVALID")
        assert code == 1 and "exactly two" in env["next_steps"][0]
    assert manifest(root) == before


def test_01c_refuses_unknown_open_badformat_outside(tmp_path):
    root, _, _ = project_pair(tmp_path)
    (root / GUARD / X_ID).mkdir()
    before = manifest(root)
    cases = [
        (("gv-20261011T000000Z-00000000",), "RUN_NOT_FOUND"),
        ((X_ID,), "NOT_CONCLUDED"),
        (("gv-bad",), "REPORT_NAME_INVALID"),
        ((f"../{REPORTS}/{E_ID}.json",), "REPORT_NAME_INVALID"),
        ((f"other/{REPORTS}/{E_ID}.json",), "REPORT_NAME_INVALID"),
    ]
    for earlier, code in cases:
        with AccessRecorder() as rec:
            env, _ = run_compare(root, earlier, (L_ID,))
        refused(env, code)
        assert rec.content_opens(root) == [] and rec.write_opens(root) == []
    env, _ = run_compare(root, (X_ID,), (L_ID,))
    assert f"guard conclude --run {X_ID}" in env["next_steps"][0]
    assert manifest(root) == before


def test_01g_refuses_reversed_equal_unknown_end_times(tmp_path):
    root, e, lv = project_pair(tmp_path)
    before = manifest(root)
    env, _ = run_compare(root, (L_ID,), (E_ID,))
    refused(env, "END_ORDER_INVALID")
    assert env["data"]["earlier"] == {"verification_id": L_ID, "ended_at": lv["ended_at"]}
    assert env["data"]["later"] == {"verification_id": E_ID, "ended_at": e["ended_at"]}
    assert "Swap" in env["next_steps"][0]
    assert manifest(root) == before
    root2, _, _ = project_pair(tmp_path / "eq", lv=result(L_ID, opened=e["opened_at"], ended=e["ended_at"]))
    env, _ = run_compare(root2)
    refused(env, "END_ORDER_INVALID")
    assert "Name other reports" in env["next_steps"][0]
    bad = result(L_ID)
    bad["ended_at"] = "not a time"
    root3, _, _ = project_pair(tmp_path / "unknown", lv=bad)
    env, _ = run_compare(root3)
    refused(env, "RESULT_INVALID")
    assert env["data"]["json_path"] == "$.ended_at" and env["data"]["end_times"]["later"] == "unknown"
    assert env["data"]["end_times"]["earlier"] == e["ended_at"]
    assert "Name other reports" in env["next_steps"][0]
    assert not (root2 / COMPARISONS).exists() and not (root3 / COMPARISONS).exists()


# ------------------------------------------------------------------------------ AC-002G-05a / 05b / 05k
def test_05a_unsupported_schema_refused(tmp_path):
    lv = result(L_ID)
    lv["schema"] = "ai-secure-code-toolkit/guard-result/v2"
    root, _, _ = project_pair(tmp_path, lv=lv)
    env, _ = run_compare(root)
    refused(env, "RESULT_SCHEMA_UNSUPPORTED")
    assert env["data"]["found"] == "ai-secure-code-toolkit/guard-result/v2"
    assert env["data"]["supported"] == ["ai-secure-code-toolkit/guard-result/v1"]
    assert not (root / COMPARISONS).exists()


def test_05b_invalid_json_id_mismatch_rule_and_path(tmp_path):
    root, _, _ = project_pair(tmp_path)
    path = root / REPORTS / f"{L_ID}.json"
    cases = [
        (b"{not json " + CANARY.encode(), "json.syntax", "$"),
        (b'{"a": 1, "a": 2}', "json.duplicate_key", "$"),
        (b'{"a": NaN}', "json.constant", "$"),
        (b"[1, 2]", "json.object", "$"),
        (dumps_json({**result(L_ID), "verification_id": E_ID}), "id.file_name", "$.verification_id"),
    ]
    bad = result(L_ID, findings=[finding("F1", line=3)])
    bad["findings"][0]["final_severity"] = CANARY
    cases.append((dumps_json(bad), "enum", "$.findings[0].final_severity"))
    for raw, rule, json_path in cases:
        path.write_bytes(raw)
        before = manifest(root)
        env, _ = run_compare(root)
        refused(env, "RESULT_INVALID")
        assert (env["data"]["rule"], env["data"]["json_path"]) == (rule, json_path)
        assert CANARY not in json.dumps(env)
        assert manifest(root) == before


def test_05b_encoding_and_canonical(tmp_path, monkeypatch):
    root, _, _ = project_pair(tmp_path)
    raw = dumps_json(result(L_ID)).replace(b'"request": "verify the login change"', b'"request": "x\\ud800"')
    (root / REPORTS / f"{L_ID}.json").write_bytes(raw)
    env, _ = run_compare(root)
    refused(env, "RESULT_INVALID")
    assert (env["data"]["rule"], env["data"]["json_path"]) == ("json.encoding", "$.request")
    put(root, result(L_ID))

    def broken(_doc):
        raise TypeError("not serializable")

    monkeypatch.setattr(compare.module, "dumps_json", broken)
    env, _ = run_compare(root)
    refused(env, "RESULT_INVALID")
    assert env["data"]["rule"] == "canonical.serialization"
    assert not (root / COMPARISONS).exists()


def test_05k_inconsistent_and_invalid_refused(tmp_path):
    bad = result(L_ID)
    bad["artifact"]["targets"][0]["kind"] = "folder"
    root, _, _ = project_pair(tmp_path, lv=bad, md=b"edited markdown\n")
    before = manifest(root)
    env, _ = run_compare(root)
    refused(env, "RESULT_INVALID")
    assert manifest(root) == before and not (root / COMPARISONS).exists()


# ------------------------------------------------------------------------------ AC-002G-05c…05l
def integrity_of(tmp_path, e=None, lv=None, l_md="render", l_canonical=True, name="p"):
    root = make_project(tmp_path, name)
    put(root, e or result(E_ID))
    raw = put(root, lv or result(L_ID), md=l_md, canonical=l_canonical)
    before = manifest(root)
    env, _ = run_compare(root)
    assert env["ok"], env
    data, md = load_comparison(root, env)
    after = manifest(root, exclude=COMPARISONS)
    assert [x for x in before if not x[0].startswith(COMPARISONS)] == after  # compared runs untouched
    return env, data, md, raw


def _first_block(md):
    return [p for p in md.split("\n\n") if p.strip()][1]


def test_05c_unresolved_used_structured_warning_first(tmp_path):
    lv = result(L_ID, findings=[finding("G1", line=3)])
    rendered = report.render(json.loads(dumps_json(lv)))
    variants = {
        "missing": (None, True, ["markdown_missing"]),
        "differs": (
            (rendered.replace("## Scope", "## Scope edited")).encode(),
            True,
            ["markdown_canonical_rendering"],
        ),
        "footer": (
            rendered[:-70].encode() + b"<!-- guard-result-sha256: " + b"0" * 64 + b" -->\n",
            True,
            ["footer_digest", "markdown_canonical_rendering"],
        ),
        "noncanonical": (
            "render",
            False,
            ["result_canonical_serialization", "footer_digest"],
        ),
    }
    for name, (md_bytes, canonical, failed) in variants.items():
        if name == "noncanonical":
            root = make_project(tmp_path, name)
            put(root, result(E_ID))
            raw = put(root, lv, md=None, canonical=False)
            (root / REPORTS / f"{L_ID}.md").write_bytes(report.render(json.loads(raw)).encode())
            env, _ = run_compare(root)
            data, md = load_comparison(root, env)
        else:
            env, data, md, _ = integrity_of(tmp_path, lv=lv, l_md=md_bytes, l_canonical=canonical, name=name)
        assert env["data"]["later"]["input_integrity"] == "unresolved", name
        assert data["input_integrity"]["later"]["state"] == "unresolved"
        assert data["input_integrity"]["later"]["failed_checks"] == failed, name
        assert data["input_integrity"]["earlier"] == {
            "verification_id": E_ID,
            "state": "consistent",
            "failed_checks": [],
            "markdown_present": True,
            "statement": None,
        }
        assert _first_block(md).startswith(f"> **Input integrity unresolved for run later ({L_ID})")
        assert all(x["input_integrity"] == ["later"] for x in data["entries"] if x["later"])


def test_05c_markdown_over_limit_not_read(tmp_path):
    root = make_project(tmp_path)
    put(root, result(E_ID))
    put(root, result(L_ID), md=None)
    with open(root / REPORTS / f"{L_ID}.md", "wb") as handle:
        handle.truncate(MIB64 + 1)
    with AccessRecorder() as rec:
        env, _ = run_compare(root)
    data, _ = load_comparison(root, env)
    assert data["input_integrity"]["later"]["failed_checks"] == ["markdown_oversized"]
    assert str((root / REPORTS / f"{L_ID}.md").resolve()) not in rec.content_opens(root)


def test_05d_raw_evidence_removed_comparison_completes(tmp_path):
    root, _, _ = project_pair(tmp_path)
    (root / GUARD / E_ID).rmdir()
    env, _ = run_compare(root)
    data, md = load_comparison(root, env)
    assert data["runs"]["earlier"]["raw_evidence"] == "not available"
    assert data["runs"]["later"]["raw_evidence"] == "available"
    assert data["statements"]["evidence_basis"] == (
        "The comparison is based only on recorded findings, never on raw evidence."
    )
    assert "Raw evidence of the earlier run: not available" in md


def test_05e_ids_end_times_sha_and_provenance_limits(tmp_path):
    root = make_project(tmp_path)
    e_raw = put(root, result(E_ID))
    l_raw = put(root, result(L_ID))
    env, _ = run_compare(root)
    data, md = load_comparison(root, env)
    for role, raw, vid in (("earlier", e_raw, E_ID), ("later", l_raw, L_ID)):
        run = data["runs"][role]
        assert run["verification_id"] == vid and run["result_sha256"] == hashlib.sha256(raw).hexdigest()
        assert run["ended_at"] == json.loads(raw)["ended_at"]
    prov = data["statements"]["provenance"]
    assert "resolved from the supplied project's report store" in prov
    assert "cannot be proven" in prov and "copied in from another project is not detected" in prov
    assert "edited consistently cannot be detected" in prov
    assert report.md_text(prov) in md


def test_05f_old_v1_without_optional_sections(tmp_path):
    checks = [check("C1", R1, ("src",), (OG_METHOD,)), check("C2", R2)]
    ev = [evidence("E1", ("C2",)), evidence("E2", ("C1",), kind="runtime", method="opengrep")]
    e = result(E_ID, checks=checks, ev=ev, runs=[og_run(1)], findings=[og("O1", line=3)])
    lv = result(L_ID, checks=checks, ev=ev)
    for key in ("adapter_runs", "budget", "cancellation"):
        del lv[key]
    env, data, _, _ = integrity_of(tmp_path, e=e, lv=lv)
    assert data["input_integrity"]["later"]["state"] == "consistent"
    assert data["runs"]["later"]["adapter_runs"] == "not recorded in this result"
    assert data["runs"]["later"]["cancellation"]["state"] == "not recorded in this result"
    (x,) = data["entries"]
    assert x["class"] == "not_comparable" and x["reasons"][0]["code"] == "method_differs"


def test_05g_body_changed_footer_unchanged(tmp_path):
    rendered = report.render(json.loads(dumps_json(result(L_ID))))
    edited = rendered.replace("## Ledger", "## Ledger (edited)")
    assert report.footer_digest(edited) == report.footer_digest(rendered)
    _, data, _, _ = integrity_of(tmp_path, l_md=edited.encode())
    assert data["input_integrity"]["later"]["failed_checks"] == ["markdown_canonical_rendering"]


def test_05h_footer_changed(tmp_path):
    rendered = report.render(json.loads(dumps_json(result(L_ID))))
    digest = report.footer_digest(rendered)
    _, data, _, _ = integrity_of(tmp_path, l_md=rendered.replace(digest, "f" * 64).encode())
    assert data["input_integrity"]["later"]["failed_checks"] == [
        "footer_digest",
        "markdown_canonical_rendering",
    ]


def test_05i_json_changed_only(tmp_path):
    original = result(L_ID)
    md = report.render(json.loads(dumps_json(original))).encode()
    edited = result(L_ID, findings=[finding("G1", line=3)])
    _, data, md_text, _ = integrity_of(tmp_path, lv=edited, l_md=md)
    integ = data["input_integrity"]["later"]
    assert integ["failed_checks"] == ["footer_digest", "markdown_canonical_rendering"]
    assert "it cannot be told which file was changed" in integ["statement"]
    assert "This comparison used the structured result" in integ["statement"]
    assert [x["later"]["finding"] for x in data["entries"]] == ["G1"]


def test_05j_both_changed_consistently_limit_stated(tmp_path):
    edited = result(L_ID, findings=[finding("G1", line=3)])
    _, data, md, _ = integrity_of(tmp_path, lv=edited)
    assert data["input_integrity"]["later"]["state"] == "consistent"
    assert "edited consistently cannot be detected" in data["statements"]["provenance"]


def test_05l_older_renderer_unresolved_no_tamper_claim(tmp_path):
    rendered = report.render(json.loads(dumps_json(result(L_ID))))
    older = rendered.replace("## Evidence Retention", "## Evidence retention")  # an older renderer's heading
    _, data, md, _ = integrity_of(tmp_path, l_md=older.encode())
    statement = data["input_integrity"]["later"]["statement"]
    assert "edited, or the report was rendered by a different toolkit version" in statement
    assert "tamper" not in (statement + md).lower()


# ------------------------------------------------------------------------------ AC-002G-06b / 06f
def test_06b_deterministic_except_id_and_time(tmp_path):
    root, _, _ = project_pair(tmp_path, lv=result(L_ID, findings=[finding("G1", line=3)]))
    first, _ = run_compare(root)
    second, _ = run_compare(root)
    a, _ = load_comparison(root, first)
    b, _ = load_comparison(root, second)
    assert a["comparison_id"] != b["comparison_id"]
    for doc in (a, b):
        del doc["comparison_id"], doc["created_at"]
    assert a == b


def test_06f_cleanup_and_expiry_keep_comparisons_envelope(tmp_path, monkeypatch):
    root = make_project(tmp_path)
    # delivered `guard cleanup` needs an initialized project
    assert initialize_project(str(root), "github-copilot").ok
    put_pair(root, result(E_ID), result(L_ID, findings=[finding("G1", line=3)]))
    env, _ = run_compare(root)
    data = env["data"]
    assert data["comparison_id"].startswith("gc-") and data["earlier"]["verification_id"] == E_ID
    assert data["later"]["verification_id"] == L_ID
    assert data["counts"] == {
        "new": 1,
        "still_present": 0,
        "not_observed_this_time": 0,
        "not_comparable": 0,
        "total": 1,
        "still_present_with_differences": 0,
    }
    assert data["files"] == {
        "structured": f"{COMPARISONS}/{data['comparison_id']}.json",
        "markdown": f"{COMPARISONS}/{data['comparison_id']}.md",
    }
    before = {p.name: p.read_bytes() for p in (root / COMPARISONS).iterdir()}
    expired = datetime(2026, 10, 23, 9, 17, tzinfo=UTC) + timedelta(days=40)
    freeze_clock(monkeypatch, expired.strftime("%Y-%m-%dT%H:%M:%SZ"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert cli.main(["guard", "cleanup", "--project", str(root), "--json"]) == 0
    removed = json.loads(buf.getvalue())["data"]["removed"]
    assert {r["verification_id"] for r in removed} == {E_ID, L_ID}  # evidence expired
    assert {p.name: p.read_bytes() for p in (root / COMPARISONS).iterdir()} == before
    assert "comparisons" not in buf.getvalue()


# ------------------------------------------------------------------------------ NFR-002G-5 limits
def _padded(vid, pad):
    doc = result(vid)
    doc["zz_padding"] = pad  # an unconsumed key: never validated or output, still bounded
    return doc


def _exact_bytes(vid, size):
    """A canonical result of exactly `size` bytes (strings below the 1 MiB string limit)."""
    doc = _padded(vid, [])
    base = len(dumps_json(doc))
    chunk = compare_bounds.MAX_STRING_BYTES - 16
    item_overhead = len(dumps_json(_padded(vid, ["x"]))) - base - 1
    remaining, pad = size - base, []
    while remaining > 0:
        n = min(chunk, remaining - item_overhead - 2)
        pad.append("x" * max(n, 1))
        remaining = size - len(dumps_json(_padded(vid, pad)))
        if remaining < item_overhead + 3:
            break
    doc = _padded(vid, pad)
    diff = size - len(dumps_json(doc))
    pad[-1] += "x" * diff
    raw = dumps_json(_padded(vid, pad))
    assert len(raw) == size
    return raw


def _exact_values(vid, values):
    base = compare_bounds.measure(dumps_json(_padded(vid, []))).values
    raw = dumps_json(_padded(vid, [0] * (values - base)))
    assert compare_bounds.measure(raw).values == values
    return raw


def _exact_depth(vid, depth):
    pad: list = []
    for _ in range(depth - 2):
        pad = [pad]
    raw = dumps_json(_padded(vid, pad))
    assert compare_bounds.measure(raw).depth == depth
    return raw


def _string(vid, size, *, key=False, escaped=False, literal=False):
    if escaped:
        text = "\\u00e9" * (size // 2) + ("a" if size % 2 else "")
    elif literal:
        text = "é" * (size // 2) + ("a" if size % 2 else "")
    else:
        text = "x" * size
    body = f'"{text}": 1' if key else f'"pad": "{text}"'
    raw = dumps_json(result(vid))[:-2] + f",\n  {body}\n}}\n".encode()
    assert compare_bounds.measure(raw).longest == size
    return raw


def _limit_case(tmp_path, name, raw_e):
    root = make_project(tmp_path, name)
    put(root, result(E_ID))
    (root / REPORTS / f"{E_ID}.json").write_bytes(raw_e)
    put(root, result(L_ID))
    return root


def _assert_too_large(env, root, before, limit, limit_value, rule):
    refused(env, "RESULT_TOO_LARGE")
    d = env["data"]
    assert (d["limit"], d["limit_value"], d["rule"], d["role"], d["verification_id"]) == (
        limit,
        limit_value,
        rule,
        "earlier",
        E_ID,
    )
    assert "not declared invalid" in env["problems"][0]["message"]
    assert "Comparison not possible" in env["problems"][0]["message"]
    assert env["next_steps"] == ["Name other reports to compare; these limits are fixed (NFR-002G-5)"]
    assert "xxxxxxxx" not in json.dumps(env)
    assert manifest(root) == before


def test_nfr5_limits_below_and_above(tmp_path, monkeypatch):
    b = compare_bounds
    cases = [
        ("bytes", lambda n: _exact_bytes(E_ID, n), b.MAX_INPUT_BYTES, "max_input_bytes", "bound.bytes"),
        ("depth", lambda n: _exact_depth(E_ID, n), b.MAX_DEPTH, "max_depth", "bound.depth"),
        ("values", lambda n: _exact_values(E_ID, n), b.MAX_VALUES, "max_values", "bound.values"),
        ("string", lambda n: _string(E_ID, n), b.MAX_STRING_BYTES, "max_string_bytes", "bound.string"),
        ("key", lambda n: _string(E_ID, n, key=True), b.MAX_STRING_BYTES, "max_string_bytes", "bound.string"),
        (
            "escaped",
            lambda n: _string(E_ID, n, escaped=True),
            b.MAX_STRING_BYTES,
            "max_string_bytes",
            "bound.string",
        ),
        (
            "literal",
            lambda n: _string(E_ID, n, literal=True),
            b.MAX_STRING_BYTES,
            "max_string_bytes",
            "bound.string",
        ),
    ]
    for name, make, limit_value, limit, rule in cases:
        root = _limit_case(tmp_path, f"{name}-ok", make(limit_value))
        env, _ = run_compare(root)
        assert env["ok"], (name, env)
        root = _limit_case(tmp_path, f"{name}-over", make(limit_value + 1))
        before = manifest(root)
        env, _ = run_compare(root)
        _assert_too_large(env, root, before, limit, limit_value, rule)
    for size, oversized in ((MIB64, False), (MIB64 + 1, True)):
        root = make_project(tmp_path, f"md-{size}")
        put(root, result(E_ID))
        put(root, result(L_ID), md=None)
        with open(root / REPORTS / f"{L_ID}.md", "wb") as handle:
            handle.write(b"x" * size)
        env, _ = run_compare(root)
        data, _ = load_comparison(root, env)
        failed = data["input_integrity"]["later"]["failed_checks"]
        assert ("markdown_oversized" in failed) is oversized and failed
    root = _limit_case(tmp_path, "memory", dumps_json(result(E_ID)))
    before = manifest(root)

    def exhausted(_doc):
        raise MemoryError

    monkeypatch.setattr(compare.module, "dumps_json", exhausted)
    env, _ = run_compare(root)
    _assert_too_large(env, root, before, "memory", None, "bound.memory")


def test_nfr5_prescan_refuses_before_parse(tmp_path, monkeypatch):
    b = compare_bounds
    fixtures = {
        "values": _exact_values(E_ID, b.MAX_VALUES + 1),
        "depth": _exact_depth(E_ID, b.MAX_DEPTH + 1),
        "string": _string(E_ID, b.MAX_STRING_BYTES + 1),
    }

    def parse_forbidden(*_a, **_k):
        raise AssertionError("json.loads called before the pre-scan refused")

    for name, raw in fixtures.items():
        root = _limit_case(tmp_path, f"pre-{name}", raw)
        buf = io.StringIO()
        with monkeypatch.context() as m, redirect_stdout(buf):
            m.setattr(compare.module.json, "loads", parse_forbidden)
            cli.main(
                ["guard", "compare", "--project", str(root), "--earlier", E_ID, "--later", L_ID, "--json"]
            )
        refused(json.loads(buf.getvalue()), "RESULT_TOO_LARGE")


def _available_memory():
    if sys.platform.startswith("linux"):
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        return None
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        page = int(out.split("page size of ")[1].split(" ")[0]) if "page size of " in out else 4096
        pages = 0
        for line in out.splitlines():
            name, _, value = line.partition(":")
            if name.strip() in ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"):
                pages += int(value.strip().rstrip("."))
        return pages * page
    return None


PEAK_CHILD = textwrap.dedent(
    """
    import io, json, resource, sys
    from contextlib import redirect_stdout
    sys.path.insert(0, sys.argv[1])
    from x_ipe_secure_code import cli
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(["guard", "compare", "--project", sys.argv[2], "--earlier", sys.argv[3],
                         "--later", sys.argv[4], "--json"])
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak = peak if sys.platform == "darwin" else peak * 1024
    print(json.dumps({"ok": json.loads(buf.getvalue())["ok"], "peak_rss_bytes": peak}))
    """
)
GIB = 1024**3


def test_nfr5_peak_memory_at_limits(tmp_path, record_property):
    if os.name == "nt":
        pytest.skip("Windows: peak RSS not measured (resource module unavailable)")
    available = _available_memory()
    if available is None or available < 4 * GIB:
        pytest.skip(f"blocked / not measured: available memory {available} bytes is below 4 GiB or unknown")
    b = compare_bounds
    peaks = {}
    for name, make in (
        ("bytes", lambda vid: _exact_bytes(vid, b.MAX_INPUT_BYTES)),
        ("values", lambda vid: _exact_values(vid, b.MAX_VALUES)),
    ):
        root = make_project(tmp_path, f"peak-{name}")
        for vid in (E_ID, L_ID):
            put(root, result(vid))
            raw = make(vid)
            (root / REPORTS / f"{vid}.json").write_bytes(raw)
            (root / REPORTS / f"{vid}.md").write_bytes(report.render(json.loads(raw)).encode())
        env = dict(os.environ)
        env.update(write_audit.child_env([tmp_path]))
        out = subprocess.run(
            [sys.executable, "-c", PEAK_CHILD, str(SRC), str(root), E_ID, L_ID],
            capture_output=True,
            text=True,
            timeout=900,
            env=env,
            cwd=tmp_path,
        )
        assert out.returncode == 0, out.stderr[-2000:]
        line = json.loads(out.stdout.strip().splitlines()[-1])
        assert line["ok"] is True
        peaks[name] = line["peak_rss_bytes"]
        record_property(f"peak_rss_bytes_{name}", line["peak_rss_bytes"])
    print(f"PEAK_RSS {json.dumps(peaks)}")
    assert max(peaks.values()) <= 3 * GIB, peaks


# ------------------------------------------------------------------------------ code-review fixes (TASK-076)
def test_05c_unrenderable_result_is_unresolved_not_a_crash(tmp_path):
    lv = result(L_ID)
    # a strictly valid result whose unconsumed budget makes the delivered renderer raise OverflowError
    lv["budget"] = {"model_usage": {}, "total_seconds": 10**400, "defaulted": False}
    root = make_project(tmp_path)
    put(root, result(E_ID))
    put(root, lv, md=b"# Guard Verification Report\n")
    env, _ = run_compare(root)
    assert env["ok"], env
    data, md = load_comparison(root, env)
    assert data["input_integrity"]["later"]["state"] == "unresolved"
    assert "markdown_canonical_rendering" in data["input_integrity"]["later"]["failed_checks"]
    assert _first_block(md).startswith(f"> **Input integrity unresolved for run later ({L_ID})")


def test_01c_result_vanishing_between_check_and_read_refused(tmp_path, monkeypatch):
    root, _, _ = project_pair(tmp_path)
    real_read = compare.module.Inputs.read

    def vanished(self, name, cap):
        return None if name == f"{L_ID}.json" else real_read(self, name, cap)

    monkeypatch.setattr(compare.module.Inputs, "read", vanished)
    before = manifest(root)
    env, _ = run_compare(root)
    refused(env, "RUN_NOT_FOUND")
    assert env["data"] == {"role": "later", "verification_id": L_ID}
    assert manifest(root) == before
