"""FEATURE-002-G: comparability before classification (AC-002G-04a…04l, 05f unit part)."""

from __future__ import annotations

from comparehelp import (
    E_ID,
    L_ID,
    OG_METHOD,
    R1,
    R2,
    TV_METHOD,
    build,
    check,
    codes,
    components,
    dg,
    entry_of,
    evidence,
    finding,
    og,
    og_run,
    result,
    row,
    target,
    tv,
    tv_run,
)

E_FINDING = [finding("F1", line=3)]


def gone(l_doc, e_doc=None):
    """Classify E's unpaired finding F1 against the later run `l_doc`."""
    cmp = build(e_doc or result(E_ID, findings=E_FINDING), l_doc)
    return entry_of(cmp, "F1"), cmp


def reasons(entry, code):
    return [r for r in entry["reasons"] if r["code"] == code]


def test_04a_scope_differs():
    for l_doc in (
        result(
            L_ID,
            targets=[target("lib")],
            checks=[check("C1", R1, ("lib",)), check("C2", R2, ("lib",))],
            ev=[evidence("E1", paths=("lib",))],
        ),
        result(L_ID, context=("src/a.py",)),
        result(L_ID, suggested=("src/a.py",)),
    ):
        x, _ = gone(l_doc)
        assert x["class"] == "not_comparable" and "scope_differs" in codes(x)
        (r,) = reasons(x, "scope_differs")
        assert r["text"] == "artifact scope differs" and r["earlier"] == "target" and r["later"] != "target"


def test_04b_policy_differs():
    not_adopted = result(
        L_ID,
        adopted=[{"rule": R2, "state_digest": dg("policy:" + R2), "at_conclusion": "unchanged"}],
        checks=[check("C2", R2)],
    )
    digest = result(L_ID)
    digest["scope"]["adopted"][0]["state_digest"] = dg("other")
    changed = result(L_ID)
    changed["scope"]["adopted"][0]["at_conclusion"] = "changed"
    e_missing = result(E_ID, findings=E_FINDING)
    e_missing["scope"]["adopted"][0]["at_conclusion"] = "missing"
    for l_doc, e_doc in ((not_adopted, None), (digest, None), (changed, None), (result(L_ID), e_missing)):
        x, _ = gone(l_doc, e_doc)
        (r,) = reasons(x, "policy_differs")
        assert x["class"] == "not_comparable" and r["text"] == "Policy differs"
        assert r["earlier"] and r["later"] and r["earlier"] != r["later"]
    x, _ = gone(digest)
    (r,) = reasons(x, "policy_differs")
    assert dg("other") in r["later"] and dg("policy:" + R1) in r["earlier"]


def test_04c_not_covered_unconfirmed_excluded():
    x, _ = gone(result(L_ID, checks=[check("C1", R1, ("src/other.py",)), check("C2", R2)]))
    assert codes(x) == ["not_covered"] and x["reasons"][0]["text"] == "not covered"
    x, _ = gone(result(L_ID, ledger=[row("C1", R1, "unconfirmed", "not executed"), row("C2", R2)]))
    assert codes(x) == ["check_unconfirmed"] and x["reasons"][0]["text"] == "check unconfirmed"
    x, _ = gone(result(L_ID, exclusions=[{"rule": None, "check": "C1", "reason": "skip"}]))
    assert codes(x) == ["excluded_by_user"] and x["reasons"][0]["text"] == "excluded by the user"
    x, _ = gone(
        result(L_ID, checks=[check("C2", R2)], exclusions=[{"rule": R1, "check": None, "reason": "skip"}])
    )
    assert "excluded_by_user" in codes(x)


def test_04c_mixed_covering_checks_one_succeeds():
    l_doc = result(
        L_ID,
        checks=[check("C1", R1), check("C3", R1), check("C2", R2)],
        ledger=[row("C1", R1, "unconfirmed", "missing"), row("C3", R1), row("C2", R2)],
        ev=[evidence("E1", ("C3", "C2"))],
    )
    x, _ = gone(l_doc)
    assert x["class"] == "not_observed_this_time" and x["reasons"] == []


def test_04d_na_in_other_run():
    x, _ = gone(result(L_ID, checks=[check("C2", R2)], na=(R1,)))
    (r,) = reasons(x, "na_other_run")
    assert r["text"] == "N/A in the other run" and "no database" in r["detail"]
    x, _ = gone(result(L_ID, ledger=[row("C1", R1, "n/a", "objective: no HTML output"), row("C2", R2)]))
    (r,) = reasons(x, "na_other_run")
    assert "objective: no HTML output" in r["detail"]


TOOL_CHECKS = [check("C1", R1, ("src",), (OG_METHOD,)), check("C2", R2)]
TOOL_EV = [evidence("E1", ("C2",)), evidence("E2", ("C1",), kind="runtime", method="opengrep")]


def tool_gone(l_runs, e_run=None):
    e = result(E_ID, checks=TOOL_CHECKS, ev=TOOL_EV, runs=[e_run or og_run(1)], findings=[og("F1", line=3)])
    l_doc = result(L_ID, checks=TOOL_CHECKS, ev=TOOL_EV, runs=l_runs)
    return gone(l_doc, e)


def test_04e_tool_or_method_differs():
    cases = {
        "no opengrep run": [],
        "did not succeed": [og_run(1, status="failed")],
        "version differs": [og_run(1, version="1.40.0")],
        "rule configuration differs": [og_run(1, configs={"py-xss": dg("other config")})],
        "include-ignored setting differs": [og_run(1, include_ignored=True)],
    }
    for text, runs in cases.items():
        x, _ = tool_gone(runs)
        found = reasons(x, "method_differs")
        assert x["class"] == "not_comparable" and found, text
        assert any(text in (r["detail"] or "") for r in found), (text, found)
        assert all(r["text"] == "tool or method differs" for r in found)
    x, _ = tool_gone([og_run(1, version="1.40.0")])
    (r,) = reasons(x, "method_differs")
    assert (r["earlier"], r["later"]) == ("1.31.0", "1.40.0")


def test_04e_mixed_adapter_runs_one_succeeds():
    x, _ = tool_gone([og_run(1, status="failed"), og_run(2)])
    assert x["class"] == "not_observed_this_time" and x["reasons"] == []


def trivy_gone(l_run):
    checks = [check("C1", R1, ("src",), (TV_METHOD,)), check("C2", R2)]
    ev = [evidence("E1", ("C2",)), evidence("E2", ("C1",), kind="runtime", method="trivy")]
    e = result(
        E_ID,
        checks=checks,
        ev=ev,
        runs=[tv_run(1, used=("vulnerability_db", "checks_bundle"))],
        findings=[tv("F1")],
    )
    l_doc = result(L_ID, checks=checks, ev=ev, runs=[l_run])
    return gone(l_doc, e)


def test_04f_tool_data_differs():
    used = ("vulnerability_db", "checks_bundle")
    variants = {
        "vulnerability_db": tv_run(
            1, used=used, comps=components(vulnerability_db={"metadata": {"Version": 3}})
        ),
        "vulnerability_db ": tv_run(
            1,
            used=used,
            comps=components(
                vulnerability_db={"metadata": {"Version": 2, "UpdatedAt": "2026-10-23T00:00:00Z"}}
            ),
        ),
        "vulnerability_db  ": tv_run(
            1, used=used, comps=components(vulnerability_db={"content_digest": dg("x")})
        ),
        "checks_bundle": tv_run(
            1,
            used=used,
            comps=components(checks_bundle={"metadata": {"MajorVersion": 1, "Digest": dg("other")}}),
        ),
        "scanners": tv_run(1, used=used, scanners=("vuln", "secret")),
        "mode": tv_run(1, used=used, mode="image_archive"),
    }
    for name, run in variants.items():
        x, _ = trivy_gone(run)
        found = reasons(x, "tool_data_differs")
        assert x["class"] == "not_comparable" and found, name
        assert any(name.strip() in (r["detail"] or "") for r in found), (name, found)
        assert all(r["text"] == "tool data differs" and r["earlier"] != r["later"] for r in found)


def test_04g_tool_coverage_incomplete_counts_shown():
    x, _ = tool_gone([og_run(1, counts=(7, 2, 1))])
    (r,) = reasons(x, "tool_coverage_incomplete")
    assert r["text"] == "tool coverage incomplete"
    assert "scanned 7" in r["detail"] and "skipped 2" in r["detail"] and "unaccounted 1" in r["detail"]
    x, _ = tool_gone([og_run(1, gaps=("rule file unreadable",))])
    assert "tool_coverage_incomplete" in codes(x)


def test_04h_later_cancelled_check_unconfirmed():
    l_doc = result(
        L_ID,
        ledger=[row("C1", R1, "unconfirmed", "cancelled before execution"), row("C2", R2)],
        cancellation={
            "requested_at": "2026-10-23T09:15:00Z",
            "reason": "user stopped",
            "consumed_at_request": 1.0,
            "tool_termination": {"tool": "none"},
            "agent_attempts": [],
            "agent_note": "n",
            "remote_note": "r",
        },
    )
    x, _ = gone(l_doc)
    assert codes(x) == ["check_unconfirmed", "run_cancelled"]
    assert reasons(x, "run_cancelled")[0]["text"] == "later run cancelled"


def test_04i_target_unstable_or_incomplete():
    x, _ = gone(result(L_ID), result(E_ID, targets=[target("src", concl=dg("after"))], findings=E_FINDING))
    assert reasons(x, "target_unstable")[0]["text"] == "target unstable or incomplete in run earlier"
    x, _ = gone(result(L_ID, targets=[target("src", incomplete=True)]))
    assert reasons(x, "target_unstable")[0]["text"] == "target unstable or incomplete in run later"
    x, _ = gone(result(L_ID, targets=[target("src", concl="missing")]))
    assert x["class"] == "not_comparable" and "target_unstable" in codes(x)
    cmp = build(
        result(E_ID, targets=[target("src", incomplete=True)]), result(L_ID, findings=[finding("G1", line=3)])
    )
    assert reasons(entry_of(cmp, "G1", "later"), "target_unstable")[0]["text"].endswith("in run earlier")


def test_04j_location_deleted_both_directions():
    l_doc = result(L_ID, targets=[target("src"), target("src/a.py", kind="file", change="deleted")])
    x, _ = gone(l_doc)
    assert reasons(x, "location_deleted")[0]["text"] == "location deleted in the later run"
    e_doc = result(E_ID, targets=[target("src"), target("src/b.py", kind="file", change="deleted")])
    cmp = build(e_doc, result(L_ID, findings=[finding("G1", path="src/b.py", line=1)]))
    y = entry_of(cmp, "G1", "later")
    assert y["class"] == "not_comparable"
    assert reasons(y, "location_deleted")[0]["text"] == "location deleted in the earlier run"


def test_04k_no_common_targets():
    l_doc = result(
        L_ID,
        targets=[target("lib")],
        checks=[check("C1", R1, ("lib",)), check("C2", R2, ("lib",))],
        ev=[evidence("E1", paths=("lib",))],
        findings=[finding("G1", path="lib/b.py", line=1)],
    )
    x, cmp = gone(l_doc)
    assert x["class"] == "not_comparable" and entry_of(cmp, "G1", "later")["class"] == "not_comparable"
    assert cmp["comparability"]["shared_targets"] is False


def test_04l_all_reasons_listed_and_summary():
    l_doc = result(
        L_ID,
        checks=[check("C1", R1, ("src",), (OG_METHOD,)), check("C3", R1), check("C2", R2)],
        ledger=[row("C1", R1), row("C3", R1, "unconfirmed", "missing"), row("C2", R2)],
        ev=[evidence("E1", ("C2",))],
    )
    l_doc["scope"]["adopted"][0]["state_digest"] = dg("other")
    x, cmp = gone(l_doc)
    assert codes(x) == ["check_unconfirmed", "method_differs", "policy_differs"]
    details = " ".join(r["detail"] or "" for r in x["reasons"])
    assert "C1" in details and "C3" in details
    policy = reasons(x, "policy_differs")[0]
    assert policy["earlier"] and policy["later"]
    assert set(cmp["comparability"]) >= {
        "shared_targets",
        "scope",
        "policy",
        "coverage",
        "methods",
        "tools",
        "tool_data",
    }
    assert cmp["comparability"]["policy"]["differing"]


def test_05f_unit_tool_finding_against_run_without_adapter_records():
    e = result(E_ID, checks=TOOL_CHECKS, ev=TOOL_EV, runs=[og_run(1)], findings=[og("F1", line=3)])
    l_doc = result(L_ID, checks=TOOL_CHECKS, ev=TOOL_EV)
    del l_doc["adapter_runs"], l_doc["cancellation"]
    x, cmp = gone(l_doc, e)
    assert x["class"] == "not_comparable"
    assert any(
        "Adapter runs not recorded in run later" in (r["detail"] or "") for r in reasons(x, "method_differs")
    )
    assert cmp["runs"]["later"]["adapter_runs"] == "not recorded in this result"
    assert cmp["runs"]["later"]["cancellation"]["state"] == "not recorded in this result"
