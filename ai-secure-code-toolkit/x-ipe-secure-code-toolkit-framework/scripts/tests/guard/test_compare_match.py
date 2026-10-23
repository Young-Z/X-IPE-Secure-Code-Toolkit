"""FEATURE-002-G: identity, pairing and classification (AC-002G-02a…02k, 03a, 03b, 03d, 03f, 03g, 04m)."""

from __future__ import annotations

import json
import random

from comparehelp import (
    E_ID,
    FP_A,
    FP_B,
    L_ID,
    OG_METHOD,
    R1,
    R2,
    TV_METHOD,
    build,
    check,
    components,
    dg,
    entries,
    entry_of,
    evidence,
    finding,
    og,
    og_run,
    result,
    rich_pair,
    row,
    target,
    tv,
    tv_run,
)

TOOL_CHECKS = [check("C1", R1, ("src",), (OG_METHOD,)), check("C2", R2)]
TOOL_EV = [evidence("E1", ("C2",)), evidence("E2", ("C1",), kind="runtime", method="opengrep")]


def og_pair(e_findings, l_findings, e_run=None, l_run=None, **common):
    e = result(E_ID, checks=TOOL_CHECKS, ev=TOOL_EV, runs=[e_run or og_run(1)], findings=e_findings, **common)
    lv = result(
        L_ID, checks=TOOL_CHECKS, ev=TOOL_EV, runs=[l_run or og_run(1)], findings=l_findings, **common
    )
    return e, lv


def tv_pair(e_findings, l_findings, e_run=None, l_run=None):
    checks = [check("C1", R1, ("src",), (TV_METHOD,)), check("C2", R2)]
    ev = [evidence("E1", ("C2",)), evidence("E2", ("C1",), kind="runtime", method="trivy")]
    e = result(E_ID, checks=checks, ev=ev, runs=[e_run or tv_run(1)], findings=e_findings)
    lv = result(L_ID, checks=checks, ev=ev, runs=[l_run or tv_run(1)], findings=l_findings)
    return e, lv


def basis(cmp, fid):
    return entry_of(cmp, fid)["basis"]


def test_02a_same_rule_adapter_ruleid_path_line_exact():
    cmp = build(*og_pair([og("O1", line=5)], [og("P1", line=5)]))
    (x,) = entries(cmp)
    assert x["class"] == "still_present" and x["basis"] == ["exact"]
    assert (x["earlier"]["finding"], x["later"]["finding"]) == ("O1", "P1")


def test_02b_single_group_line_moved():
    cmp = build(*og_pair([og("O1", line=10)], [og("P1", line=14)]))
    assert entry_of(cmp, "O1")["class"] == "still_present"
    assert basis(cmp, "O1") == ["position (line moved 10→14)"]


def test_02c_fingerprint_first_regardless_of_line():
    cmp = build(
        *og_pair(
            [og("O1", line=5, fingerprint=FP_A), og("O2", line=9, fingerprint=FP_B)],
            [og("P1", line=20, fingerprint=FP_B), og("P2", line=30, fingerprint=FP_A)],
        )
    )
    assert entry_of(cmp, "O1")["later"]["finding"] == "P2" and basis(cmp, "O1") == ["fingerprint"]
    assert entry_of(cmp, "O2")["later"]["finding"] == "P1" and basis(cmp, "O2") == ["fingerprint"]
    cmp = build(*og_pair([og("O3", line=5, fingerprint=FP_A)], [og("P3", line=5, fingerprint=FP_B)]))
    x = entry_of(cmp, "O3")
    assert "fingerprint" not in x["basis"] and x["basis"] == ["exact"]
    assert {
        "attribute": "fingerprint",
        "earlier": "differs (not shown)",
        "later": "differs (not shown)",
    } in x["attribute_changes"]


def test_02d_exact_then_position_then_new():
    cmp = build(
        *og_pair(
            [og("O5", line=5), og("O40", line=40)], [og("P5", line=5), og("P41", line=41), og("P90", line=90)]
        )
    )
    assert entry_of(cmp, "O5")["later"]["finding"] == "P5" and basis(cmp, "O5") == ["exact"]
    assert entry_of(cmp, "O40")["later"]["finding"] == "P41"
    assert basis(cmp, "O40") == ["position (line moved 40→41)"]
    assert entry_of(cmp, "P90", "later")["class"] == "new"


def test_02e_declared_rename_pairs():
    e = result(
        E_ID,
        targets=[target("src/a.py", kind="file")],
        checks=[check("C1", R1, ("src/a.py",))],
        ev=[evidence("E1", ("C1",), ("src/a.py",))],
        findings=[finding("F1", path="src/a.py", line=3)],
    )
    lv = result(
        L_ID,
        targets=[target("src/b.py", kind="file", change="renamed", old_path="src/a.py")],
        checks=[check("C1", R1, ("src/b.py",))],
        ev=[evidence("E1", ("C1",), ("src/b.py",))],
        findings=[finding("G1", path="src/b.py", line=3)],
    )
    x = entry_of(build(e, lv), "F1")
    assert x["class"] == "still_present" and x["later"]["finding"] == "G1"
    assert "declared rename src/a.py→src/b.py" in x["basis"]


def test_02f_undeclared_move_not_observed_plus_new_annotated():
    e = result(E_ID, findings=[finding("F1", path="src/a.py", line=3)])
    lv = result(L_ID, findings=[finding("G1", path="src/c.py", line=3)])
    cmp = build(e, lv)
    gone, new = entry_of(cmp, "F1"), entry_of(cmp, "G1", "later")
    assert (gone["class"], new["class"]) == ("not_observed_this_time", "new")
    a, b = ([x for x in y["annotations"] if x["code"] == "possible_move"] for y in (gone, new))
    assert a[0]["text"] == "possibly the same finding moved (unverified)" and a[0]["refers_to"] == [
        new["entry"]
    ]
    assert b[0]["refers_to"] == [gone["entry"]]


def test_02g_semantic_weak_identity_and_cwe_split():
    e = result(E_ID, findings=[finding("F1", line=3, title="A", description="one")])
    lv = result(L_ID, findings=[finding("G7", line=8, title="B", description="two")])
    x = entry_of(build(e, lv), "F1")
    assert x["class"] == "still_present" and "semantic identity (weak)" in x["basis"]
    lv = result(L_ID, findings=[finding("G7", line=3, cwe="CWE-80")])
    cmp = build(e, lv)
    assert entry_of(cmp, "F1")["later"] is None and entry_of(cmp, "G7", "later")["earlier"] is None


def test_02h_trivy_vuln_version_change_is_attribute():
    cmp = build(
        *tv_pair(
            [tv("T1", installed="2.14.0", pkg_path="lib/x.jar")],
            [tv("U1", installed="2.17.1", pkg_path="lib/x.jar")],
        )
    )
    x = entry_of(cmp, "T1")
    assert x["class"] == "still_present" and x["later"]["finding"] == "U1"
    assert {"attribute": "installed_version", "earlier": "2.14.0", "later": "2.17.1"} in x[
        "attribute_changes"
    ]
    cmp = build(*tv_pair([tv("T1", pkg_path="lib/x.jar")], [tv("U1", pkg_path="lib/y.jar")]))
    assert entry_of(cmp, "T1")["later"] is None


def test_02i_merged_findings_via_survivor():
    fs = [finding("f1", line=1), finding("f2", line=2), finding("f3", line=3)]
    fs[0]["merged_into"] = fs[1]["merged_into"] = "f3"
    fs[2]["merged_from"] = ["f1", "f2"]
    cmp = build(result(E_ID, findings=fs), result(L_ID, findings=[finding("g3", line=3)]))
    assert len(entries(cmp)) == 1
    x = entry_of(cmp, "f3")
    assert x["later"]["finding"] == "g3" and x["earlier"]["merged"] == ["f1", "f2"]
    assert any(a["code"] == "merge" and "f1, f2" in a["text"] for a in x["annotations"])


def test_02j_same_local_id_different_rule_or_path_not_paired():
    e = result(E_ID, findings=[finding("F1", line=3)])
    for other in (finding("F1", line=3, rule=R2, check="C2"), finding("F1", line=3, path="src/z.py")):
        cmp = build(e, result(L_ID, findings=[other]))
        assert entry_of(cmp, "F1")["later"] is None and entry_of(cmp, "F1", "later")["earlier"] is None


def test_02k_semantic_ambiguous_position_order():
    e = result(E_ID, findings=[finding("F1"), finding("F2")])
    lv = result(L_ID, findings=[finding("G1")])
    cmp = build(e, lv)
    pair = entry_of(cmp, "F1")
    assert pair["later"]["finding"] == "G1"
    assert "position" in pair["basis"] and "semantic identity (weak)" in pair["basis"]
    assert entry_of(cmp, "F2")["class"] == "not_observed_this_time"


def _random_pair(rng):
    def some(prefix):
        out = []
        for i in range(rng.randint(0, 6)):
            kind = rng.choice(["sem", "og"])
            path = rng.choice(["src/a.py", "src/b.py", "lib/c.py"])
            line = rng.choice([None, 1, 2, 3])
            if kind == "sem":
                out.append(finding(f"{prefix}{i}", path=path, line=line, cwe=rng.choice(["CWE-79", None])))
            else:
                out.append(
                    og(f"{prefix}{i}", path=path, line=line, fingerprint=rng.choice([None, FP_A, FP_B]))
                )
        return out

    return og_pair(some("F"), some("G"), targets=[target("src"), target("lib")])


def test_03a_four_classes_counts_sum():
    rng = random.Random(7)
    for _ in range(60):
        cmp = build(*_random_pair(rng))
        classes = [x["class"] for x in entries(cmp)]
        assert set(classes) <= {"new", "still_present", "not_observed_this_time", "not_comparable"}
        c = cmp["counts"]
        assert (
            c["total"]
            == len(classes)
            == sum(c[k] for k in ("new", "still_present", "not_observed_this_time", "not_comparable"))
        )
        assert c["still_present"] == sum(1 for x in entries(cmp) if x["earlier"] and x["later"])


def test_03b_unpaired_gated_by_comparability():
    e = result(E_ID, findings=[finding("F1", line=3)])
    lv = result(L_ID, findings=[finding("G1", line=3, cwe="CWE-80")])
    cmp = build(e, lv)
    assert entry_of(cmp, "F1")["class"] == "not_observed_this_time"
    assert entry_of(cmp, "G1", "later")["class"] == "new"
    e = result(
        E_ID,
        findings=[finding("F1", line=3)],
        ledger=[row("C1", R1, "unconfirmed", "not executed"), row("C2", R2)],
    )
    lv = result(
        L_ID,
        findings=[finding("G1", line=3, cwe="CWE-80")],
        ledger=[row("C1", R1, "unconfirmed", "not executed"), row("C2", R2)],
    )
    cmp = build(e, lv)
    assert entry_of(cmp, "F1")["class"] == "not_comparable"
    assert entry_of(cmp, "G1", "later")["class"] == "not_comparable"


def test_03d_pair_shows_both_values_stays_still_present():
    e = result(E_ID, findings=[finding("F1", line=3, severity="high", review="confirmed", title="Old title")])
    lv = result(
        L_ID, findings=[finding("G1", line=9, severity="medium", review="false_positive", title="New")]
    )
    x = entry_of(build(e, lv), "F1")
    assert x["class"] == "still_present"
    changes = {c["attribute"]: (c["earlier"], c["later"]) for c in x["attribute_changes"]}
    assert changes["final_severity"] == ("high", "medium") and changes["review"] == (
        "confirmed",
        "false_positive",
    )
    assert changes["line"] == (3, 9) and changes["title"] == ("Old title", "New")


def test_03f_differences_noted_and_counted():
    e, lv = og_pair(
        [og("O1", line=5)],
        [og("P1", line=5)],
        l_run=og_run(1, version="1.32.0", configs={"py-xss": dg("changed")}, include_ignored=True),
    )
    lv["scope"]["adopted"][0]["state_digest"] = dg("new policy")
    cmp = build(e, lv)
    x = entry_of(cmp, "O1")
    assert x["class"] == "still_present"
    kinds = {n["kind"] for n in x["notes"]}
    assert {"policy", "adapter_build", "rule_configuration", "include_ignored"} <= kinds
    assert all(n["earlier"] != n["later"] for n in x["notes"])
    assert cmp["counts"]["still_present_with_differences"] == 1
    t_e, t_l = tv_pair(
        [tv("T1")],
        [tv("U1")],
        l_run=tv_run(1, comps=components(vulnerability_db={"metadata": {"Version": 3}})),
    )
    cmp_t = build(t_e, t_l)
    assert any(
        n["kind"] == "tool_data" and "vulnerability_db" in n["subject"]
        for n in entry_of(cmp_t, "T1")["notes"]
    )
    text = json.dumps(cmp, ensure_ascii=False)
    statement = cmp["statements"]["still_present_meaning"]
    assert "observed in both runs under the stated identity rule" in statement
    assert "same issue confirmed" not in text.replace(json.dumps(statement, ensure_ascii=False)[1:-1], "")


def test_03g_every_non_merged_finding_once():
    e, lv = rich_pair()
    cmp = build(e, lv)
    for role, doc in (("earlier", e), ("later", lv)):
        refs = [x[role]["finding"] for x in entries(cmp) if x[role]]
        survivors = [f["id"] for f in doc["findings"] if f["merged_into"] is None]
        assert sorted(refs) == sorted(survivors)
        merged = [m for x in entries(cmp) if x[role] for m in x[role]["merged"]]
        assert sorted(merged) == sorted(f["id"] for f in doc["findings"] if f["merged_into"] is not None)
    assert entry_of(cmp, "S1")["earlier"]["merged"] == ["M1", "M2"]


def test_04m_target_content_unchanged_annotation():
    same = target("src", digest=dg("tree"))
    cmp = build(
        result(E_ID, targets=[same], findings=[finding("F1", line=3)]),
        result(L_ID, targets=[same], findings=[]),
    )
    x = entry_of(cmp, "F1")
    assert x["class"] == "not_observed_this_time"
    assert {
        "code": "target_unchanged",
        "text": "target content unchanged between runs",
        "refers_to": [],
    } in x["annotations"]
    cmp = build(
        result(E_ID, targets=[same], findings=[finding("F1", line=3)]),
        result(L_ID, targets=[target("src", digest=dg("tree2"))]),
    )
    assert not [a for a in entry_of(cmp, "F1")["annotations"] if a["code"] == "target_unchanged"]
