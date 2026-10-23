"""FEATURE-002-G: bounded pre-scan, strict validation contract and delivered-writer realism.

AC-002G-05b (unit part), 05m…05s, 06c (refusal inside a secret finding), NFR-002G-5 (pre-scan);
DAO-012 binding condition 1 (table-driven lexical pre-scan tests + differential test).
"""

from __future__ import annotations

import copy
import json
import os
import random
import re
from collections.abc import Mapping, Sequence

import pytest
import test_guard
import test_guard_tool
import trivyhelp
from comparehelp import (
    CANARY,
    E_ID,
    L_ID,
    R1,
    R2,
    build,
    compare_bounds,
    compare_match,
    compare_render,
    compare_validate,
    dg,
    entries,
    finding,
    og,
    og_run,
    result,
    rich_pair,
    row,
    target,
    tv,
)
from conftest import FakeInteraction

from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.guard import cancel
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.guard.model import MAX_TEXT

env = test_guard.env  # fixture reuse without re-import (keeps ruff F811 quiet without config changes)
fake = test_guard_tool.fake
trivy = trivyhelp.trivy
linux = trivyhelp.linux
posix_only = pytest.mark.skipif(os.name == "nt", reason="Adapter execution is POSIX only")


def invalid(doc, file_id=None):
    with pytest.raises(compare_bounds.Invalid) as info:
        compare_validate.validate(doc, file_id or doc["verification_id"])
    return info.value.rule, info.value.path


# ------------------------------------------------------------------------------ pre-scan (NFR-002G-5)
LEXICAL = [
    # (JSON text, values, depth, longest decoded UTF-8 string)
    (b"{}", 1, 1, 0),
    (b"[]", 1, 1, 0),
    (b'"abc"', 1, 0, 3),
    (b"123", 1, 0, 0),
    (b"-1.5e+3", 1, 0, 0),
    (b"true", 1, 0, 0),
    (b"false", 1, 0, 0),
    (b"null", 1, 0, 0),
    (b'{"a": 1, "b": [true, false, null]}', 6, 2, 1),
    (b'{"key": "v"}', 2, 1, 3),
    (b"[0, -0, 1.5, 1e10, -2E-3]", 6, 1, 0),
    (b'["a\\"b"]', 2, 1, 3),
    (b'["a\\\\b"]', 2, 1, 3),
    (b'["{[,:]}"]', 2, 1, 6),
    (b'{"x{": "]}", "y": ","}', 3, 1, 2),
    (b'["\\" \\\\ \\/ \\b \\f \\n \\r \\t"]', 2, 1, 15),
    (b'["\\u0041"]', 2, 1, 1),
    (b'["\\u00e9"]', 2, 1, 2),
    (b'["\\u20ac"]', 2, 1, 3),
    (b'["\\ud83d\\ude00"]', 2, 1, 4),
    (b'["\\ud800"]', 2, 1, 3),
    (b'["\\udc00"]', 2, 1, 3),
    (b'["\\ud800\\u0041"]', 2, 1, 4),
    ('["é€😀"]'.encode(), 2, 1, 9),
    (b"[[[[]]]]", 4, 4, 0),
    (b" \n\t\r[ 1 , 2 ]\n", 3, 1, 0),
]
MALFORMED = [
    b'["abc\\',
    b'["\\u12',
    b'["abc',
    b"]]]}",
    b"{{{",
    b":::,,,",
    b'{"a" "b"}',
    b"[1 2 3",
    b"\\u",
    b'"\\ud800',
    b"",
    b"   ",
    b"[tru",
    b'{"a":}',
    b"\xff\xfe[1]",
]


@pytest.mark.parametrize("raw, values, depth, longest", LEXICAL)
def test_nfr5_prescan_lexical_table(raw, values, depth, longest):
    stats = compare_bounds.measure(raw)
    assert (stats.values, stats.depth, stats.longest) == (values, depth, longest)
    # just below each limit passes, just above is refused with the matching limit
    compare_bounds.measure(raw, max_depth=depth, max_values=values, max_string=longest)
    for limit, kwargs, value in (
        ("max_values", "max_values", values),
        ("max_depth", "max_depth", depth),
        ("max_string_bytes", "max_string", longest),
    ):
        if value == 0:
            continue
        with pytest.raises(compare_bounds.TooLarge) as info:
            compare_bounds.measure(raw, **{kwargs: value - 1})
        assert info.value.limit == limit and isinstance(info.value.byte_offset, int)


@pytest.mark.parametrize("raw", MALFORMED)
def test_nfr5_prescan_malformed_never_crashes(raw):
    stats = compare_bounds.measure(raw)
    assert stats.values >= 0
    compare_bounds.prescan(raw)  # syntax is left to json.loads


def test_nfr5_prescan_limit_edges_with_real_limits():
    b = compare_bounds
    deep_ok = b"[" * b.MAX_DEPTH + b"]" * b.MAX_DEPTH
    deep_bad = b"[" * (b.MAX_DEPTH + 1) + b"]" * (b.MAX_DEPTH + 1)
    assert b.prescan(deep_ok).depth == 64
    with pytest.raises(b.TooLarge) as info:
        b.prescan(deep_bad)
    assert (info.value.limit, info.value.rule, info.value.limit_value) == ("max_depth", "bound.depth", 64)
    for text, ok in (
        (b'["' + b"x" * b.MAX_STRING_BYTES + b'"]', True),
        (b'["' + b"x" * (b.MAX_STRING_BYTES + 1) + b'"]', False),
        (b'{"' + b"k" * (b.MAX_STRING_BYTES + 1) + b'": 1}', False),
        (b'["' + b"\\u00e9" * (b.MAX_STRING_BYTES // 2) + b'"]', True),
        (b'["' + b"\\u00e9" * (b.MAX_STRING_BYTES // 2) + b'a"]', False),
        (('["' + "é" * (b.MAX_STRING_BYTES // 2) + '"]').encode(), True),
        (('["' + "é" * (b.MAX_STRING_BYTES // 2) + 'a"]').encode(), False),
    ):
        if ok:
            assert b.prescan(text).longest <= b.MAX_STRING_BYTES
        else:
            with pytest.raises(b.TooLarge) as info:
                b.prescan(text)
            assert info.value.rule == "bound.string"


def _walk(doc):
    """Reference: iterative walk of a parsed document (values, depth, longest UTF-8 string incl. keys)."""
    values = depth = longest = 0
    stack = [(doc, 0)]
    while stack:
        value, level = stack.pop()
        values += 1
        if isinstance(value, dict):
            depth = max(depth, level + 1)
            for k, v in value.items():
                longest = max(longest, len(k.encode("utf-8", "surrogatepass")))
                stack.append((v, level + 1))
        elif isinstance(value, list):
            depth = max(depth, level + 1)
            stack += [(v, level + 1) for v in value]
        elif isinstance(value, str):
            longest = max(longest, len(value.encode("utf-8", "surrogatepass")))
    return values, depth, longest


def _random_doc(rng, level=0):
    kind = rng.choice(["obj", "list", "str", "num", "lit"] if level < 6 else ["str", "num", "lit"])
    if kind == "obj":
        suffixes = ["", "é", '"', "\\", "\u20ac"]
        return {f"k{i}" + rng.choice(suffixes): _random_doc(rng, level + 1) for i in range(rng.randint(0, 4))}
    if kind == "list":
        return [_random_doc(rng, level + 1) for _ in range(rng.randint(0, 4))]
    if kind == "str":
        return "".join(
            rng.choice(["a", "é", "\u20ac", "\U0001f600", '"', "\\", "/", "\n", "{", "]", ":", ","])
            for _ in range(rng.randint(0, 6))
        )
    if kind == "num":
        return rng.choice([0, -1, 3.25, 10**12, -2.5e-3])
    return rng.choice([True, False, None])


def test_nfr5_prescan_matches_iterative_walk_of_parsed_fixtures():
    rng = random.Random(2026)
    texts = [raw for raw, *_ in LEXICAL if b"\\ud800" not in raw and b"\\udc00" not in raw]
    texts += [dumps_json(d) for d in rich_pair()] + [dumps_json(result(E_ID))]
    for _ in range(200):
        doc = _random_doc(rng)
        texts += [json.dumps(doc).encode(), json.dumps(doc, ensure_ascii=False).encode(), dumps_json(doc)]
    texts += [b'["\\ud800"]', b'{"\\udc00": "\\ud83d\\ude00"}']
    for raw in texts:
        stats = compare_bounds.measure(raw)
        assert (stats.values, stats.depth, stats.longest) == _walk(json.loads(raw)), raw[:200]


# ------------------------------------------------------------------------------ strict validation
def test_rich_and_minimal_results_validate():
    for doc in (*rich_pair(), result(E_ID), result(L_ID, plan=None)):
        compare_validate.validate(doc, doc["verification_id"])


def _m(fn):
    def apply(doc):
        fn(doc)
        return doc

    return apply


TYPES_AND_ENUMS = [
    (_m(lambda d: d["findings"].__setitem__(0, "F1")), "type", "$.findings[0]"),
    (
        _m(lambda d: d["findings"][0]["location"].__setitem__("line", "3")),
        "type",
        "$.findings[0].location.line",
    ),
    (_m(lambda d: d.__setitem__("verdict", "passed")), "enum", "$.verdict"),
    (_m(lambda d: d["ledger"][0].__setitem__("state", "done")), "enum", "$.ledger[0].state"),
    (
        _m(lambda d: d["findings"][0].__setitem__("final_severity", "severe")),
        "enum",
        "$.findings[0].final_severity",
    ),
    (_m(lambda d: d["findings"][0].__setitem__("review", "ok")), "enum", "$.findings[0].review"),
    (
        _m(lambda d: d["artifact"]["targets"][0].__setitem__("kind", "folder")),
        "enum",
        "$.artifact.targets[0].kind",
    ),
    (
        _m(lambda d: d["artifact"]["targets"][0].__setitem__("change", "moved")),
        "enum",
        "$.artifact.targets[0].change",
    ),
    (
        _m(lambda d: d["plan"]["checks"][0]["methods"][0].__setitem__("kind", "guess")),
        "enum",
        "$.plan.checks[0].methods[0].kind",
    ),
    (
        _m(lambda d: d["adapter_runs"][0]["checks"]["C2"]["counts"].__setitem__("skipped", -1)),
        "range.count",
        "$.adapter_runs[0].checks{C2}.counts.skipped",
    ),
    (
        _m(lambda d: d["findings"][6]["tool"].__setitem__("tool_severity", {"x": 1})),
        "type",
        "$.findings[6].tool.tool_severity",
    ),
    (
        _m(lambda d: d["findings"][0]["location"].__setitem__("line", True)),
        "type",
        "$.findings[0].location.line",
    ),
]


@pytest.mark.parametrize("mutate, rule, path", TYPES_AND_ENUMS)
def test_05m_types_and_enums(mutate, rule, path):
    assert invalid(mutate(rich_pair()[0])) == (rule, path)


UNIQUENESS = [
    (
        _m(lambda d: d["artifact"]["targets"].append(copy.deepcopy(d["artifact"]["targets"][0]))),
        "unique.target_path",
        "$.artifact.targets[3].path",
    ),
    (
        _m(lambda d: d["scope"]["adopted"].append(copy.deepcopy(d["scope"]["adopted"][0]))),
        "unique.adopted_rule",
        "$.scope.adopted[5].rule",
    ),
    (
        _m(lambda d: d["plan"]["checks"].append(copy.deepcopy(d["plan"]["checks"][0]))),
        "unique.check_id",
        "$.plan.checks[4].id",
    ),
    (
        _m(lambda d: d["findings"].append(copy.deepcopy(d["findings"][3]))),
        "unique.finding_id",
        "$.findings[11].id",
    ),
    (
        _m(lambda d: d["adapter_runs"].append(copy.deepcopy(d["adapter_runs"][0]))),
        "unique.adapter_run",
        "$.adapter_runs[3].n",
    ),
    (
        _m(lambda d: d["ledger"].append(copy.deepcopy(d["ledger"][0]))),
        "unique.ledger_check",
        "$.ledger[6].check",
    ),
]


@pytest.mark.parametrize("mutate, rule, path", UNIQUENESS)
def test_05n_uniqueness(mutate, rule, path):
    assert invalid(mutate(rich_pair()[0])) == (rule, path)


REFERENTIAL = [
    (
        _m(lambda d: d["findings"][0].__setitem__("rule", "CWE/4.14/CWE-1")),
        "ref.finding_rule",
        "$.findings[0].rule",
    ),
    (_m(lambda d: d["findings"][0].__setitem__("check", "C9")), "ref.finding_check", "$.findings[0].check"),
    (_m(lambda d: d["findings"][0].__setitem__("check", "C2")), "ref.finding_check", "$.findings[0].check"),
    (
        _m(lambda d: d["findings"][0]["location"].__setitem__("path", "other/a.py")),
        "ref.finding_target",
        "$.findings[0].location.path",
    ),
    (
        _m(lambda d: d["plan"]["checks"][0]["object"].__setitem__(0, "elsewhere")),
        "ref.object_target",
        "$.plan.checks[0].object[0]",
    ),
    (
        _m(lambda d: d["plan"]["checks"][0].__setitem__("rule", "CWE/4.14/CWE-1")),
        "ref.check_rule",
        "$.plan.checks[0].rule",
    ),
    (_m(lambda d: d["ledger"].pop(0)), "ref.ledger_missing", "$.ledger"),
    (_m(lambda d: d["ledger"][0].__setitem__("check", "C9")), "ref.ledger_check", "$.ledger[0].check"),
    (
        _m(lambda d: d["ledger"][0].__setitem__("findings", ["F404"])),
        "ref.ledger_finding",
        "$.ledger[0].findings[0]",
    ),
    (
        _m(lambda d: d["risk_acceptances"][0].__setitem__("finding", "F404")),
        "ref.risk_acceptance_finding",
        "$.risk_acceptances[0].finding",
    ),
    (
        _m(lambda d: d["plan"]["not_applicable"][0].__setitem__("rule", "CWE/4.14/CWE-1")),
        "ref.na_rule",
        "$.plan.not_applicable[0].rule",
    ),
    (
        _m(lambda d: d["plan"]["exclusions"][1].__setitem__("rule", "CWE/4.14/CWE-1")),
        "ref.exclusion_rule",
        "$.plan.exclusions[1].rule",
    ),
    (
        _m(lambda d: d["plan"]["exclusions"][0].__setitem__("check", "C9")),
        "ref.exclusion_check",
        "$.plan.exclusions[0].check",
    ),
]


@pytest.mark.parametrize("mutate, rule, path", REFERENTIAL)
def test_05o_referential_integrity(mutate, rule, path):
    assert invalid(mutate(rich_pair()[0])) == (rule, path)


ADAPTER_REFS = [
    (_m(lambda d: d["findings"][6]["tool"].__setitem__("run", 9)), "ref.tool_run", "$.findings[6].tool.run"),
    (
        _m(lambda d: d["findings"][6]["tool"].__setitem__("run", 2)),
        "ref.tool_adapter",
        "$.findings[6].tool.adapter",
    ),
    (
        _m(lambda d: d["findings"][6].__setitem__("source", "semantic")),
        "ref.tool_source",
        "$.findings[6].source",
    ),
    (
        _m(lambda d: d["findings"][0].__setitem__("source", "opengrep")),
        "ref.tool_source",
        "$.findings[0].source",
    ),
    (
        _m(
            lambda d: d["adapter_runs"][0].__setitem__("checks", {"C9": d["adapter_runs"][0]["checks"]["C2"]})
        ),
        "ref.adapter_run_check",
        "$.adapter_runs[0].checks{C9}",
    ),
]


@pytest.mark.parametrize("mutate, rule, path", ADAPTER_REFS)
def test_05p_adapter_references(mutate, rule, path):
    assert invalid(mutate(rich_pair()[0])) == (rule, path)


DIGESTS_AND_TIMES = [
    (
        _m(lambda d: d["artifact"]["targets"][0].__setitem__("digest_at_open", "sha256:XYZ")),
        "format.digest",
        "$.artifact.targets[0].digest_at_open",
    ),
    (
        _m(lambda d: d["scope"]["adopted"][0].__setitem__("state_digest", "md5:00")),
        "format.digest",
        "$.scope.adopted[0].state_digest",
    ),
    (
        _m(lambda d: d["adapter_runs"][0]["rules"][0]["config_digests"].__setitem__("py-xss", "x")),
        "format.digest",
        "$.adapter_runs[0].rules[0].config_digests{py-xss}",
    ),
    (
        _m(lambda d: d["artifact"]["targets"][0].__setitem__("digest_at_open", "missing")),
        "format.digest",
        "$.artifact.targets[0].digest_at_open",
    ),
    (_m(lambda d: d.__setitem__("opened_at", "2026-10-20 10:15:00")), "format.timestamp", "$.opened_at"),
    (_m(lambda d: d.__setitem__("ended_at", "2026-02-30T10:15:00Z")), "format.timestamp", "$.ended_at"),
    (_m(lambda d: d.__setitem__("ended_at", "2026-10-20T10:00:00Z")), "order.timestamps", "$.ended_at"),
]


@pytest.mark.parametrize("mutate, rule, path", DIGESTS_AND_TIMES)
def test_05q_digests_and_timestamps(mutate, rule, path):
    assert invalid(mutate(rich_pair()[0])) == (rule, path)


def test_05q_sentinels_accepted_only_where_written():
    doc = result(
        E_ID,
        targets=[
            target("src", digest=dg("x"), concl="missing"),
            target("lib", digest="unreadable", concl="unsafe", incomplete=True),
        ],
        checks=[],
        ev=[],
        findings=(),
    )
    compare_validate.validate(doc, E_ID)
    doc["scope"]["adopted"][0]["state_digest"] = "missing"
    assert invalid(doc) == ("format.digest", "$.scope.adopted[0].state_digest")


TARGET_CHANGES = [
    (
        _m(lambda d: d["artifact"]["targets"][1].__setitem__("old_path", None)),
        "target.renamed_old_path",
        "$.artifact.targets[1].old_path",
    ),
    (
        _m(lambda d: d["artifact"]["targets"][0].__setitem__("old_path", "older")),
        "target.renamed_old_path",
        "$.artifact.targets[0].old_path",
    ),
    (
        _m(lambda d: d["artifact"]["targets"].append(target("new2", change="renamed", old_path="old"))),
        "target.old_path_unique",
        "$.artifact.targets[3].old_path",
    ),
    (
        _m(lambda d: d["artifact"]["targets"][2].__setitem__("digest_at_open", dg("x"))),
        "target.deleted_digest",
        "$.artifact.targets[2].digest_at_open",
    ),
]


@pytest.mark.parametrize("mutate, rule, path", TARGET_CHANGES)
def test_05r_target_change_consistency(mutate, rule, path):
    assert invalid(mutate(rich_pair()[1])) == (rule, path)


def _merge(doc, **links):
    by = {f["id"]: f for f in doc["findings"]}
    for fid, (into, sources) in links.items():
        by[fid]["merged_into"], by[fid]["merged_from"] = into, list(sources)
    return doc


def _merge_base():
    return result(E_ID, findings=[finding(f"F{i}", line=i) for i in range(1, 5)])


INVALID_MERGES = [
    (lambda: _merge(_merge_base(), F1=("F9", [])), "merge.unknown", "$.findings[0].merged_into"),
    (lambda: _merge(_merge_base(), F2=(None, ["F9"])), "merge.unknown", "$.findings[1].merged_from[0]"),
    (lambda: _merge(_merge_base(), F1=("F1", [])), "merge.self", "$.findings[0].merged_into"),
    (
        lambda: _merge(_merge_base(), F1=("F2", ["F2"]), F2=("F1", ["F1"])),
        "merge.cycle",
        "$.findings[0].merged_into",
    ),
    (lambda: _merge(_merge_base(), F1=("F2", [])), "merge.backref", "$.findings[0].merged_into"),
]


@pytest.mark.parametrize("make, rule, path", INVALID_MERGES)
def test_05s_invalid_merges_refused(make, rule, path):
    assert invalid(make()) == (rule, path)


def test_05s_chain_and_remerge_accepted_and_resolved():
    doc = _merge(_merge_base(), F1=("F4", []), F2=("F3", ["F1"]), F3=(None, ["F2"]), F4=(None, ["F1"]))
    compare_validate.validate(doc, E_ID)
    by = {f["id"]: f for f in doc["findings"]}
    assert compare_match.final_survivor("F1", by) == "F4" and compare_match.final_survivor("F2", by) == "F3"


# ------------------------------------------------------------------------------ consumed-leaf contract
def _parts(path):
    return re.findall(r"\.([^.\[{]+)|\[(\d+)\]|\{([^}]*)\}", path[1:])


def set_at(doc, path, value):
    node, parts = doc, _parts(path)
    for i, (key, index, data_key) in enumerate(parts):
        last = i == len(parts) - 1
        if index:
            slot = int(index)
        elif data_key:
            slot = data_key if data_key in node else sorted(node)[int(data_key)]
        else:
            slot = key
        if last:
            node[slot] = value
        else:
            node = node[slot]


BAD_VALUES = {
    "enum": "x-" + CANARY,
    "format.run_id": "gv-" + CANARY,
    "format.timestamp": "2026-13-40T00:00:00Z",
    "format.digest": "sha256:" + CANARY,
    "format.path": "../" + CANARY,
    "format.location": "../" + CANARY,
    "format.id": "-" + CANARY,
    "format.name": "-" + CANARY,
    "format.code": "lower " + CANARY,
    "format.rule": "",
    "format.ledger_check": "bad " + CANARY,
    "format.text": "\x00" + CANARY,
    "format.bounded_text": CANARY + "x" * MAX_TEXT,
    "format.short": CANARY * 10,
    "range.positive": 0,
    "range.count": -1,
}


def _wrong_type(leaf):
    if "object" in leaf.kinds or "list" in leaf.kinds:
        return CANARY
    if "int" in leaf.kinds:
        return True if "bool" not in leaf.kinds else [CANARY]
    return {"value": CANARY}


def test_every_contract_leaf_refuses_wrong_shape():
    e, lv = rich_pair()
    problems = []
    for leaf in compare_validate.CONTRACT:
        for doc in (e, lv):
            found = [p for _, p, present in compare_validate.instances(doc, leaf.pattern) if present]
            if found:
                break
        else:
            problems.append(f"no instance of {leaf.pattern} in the rich fixture")
            continue
        path = found[0]
        cases = [("type", _wrong_type(leaf))]
        if leaf.rule:
            cases.append((leaf.rule, BAD_VALUES[leaf.rule]))
        for rule, value in cases:
            mutated = copy.deepcopy(doc)
            set_at(mutated, path, value)
            try:
                compare_validate.validate(
                    mutated,
                    mutated["verification_id"]
                    if isinstance(mutated.get("verification_id"), str)
                    else doc["verification_id"],
                )
                problems.append(f"{leaf.pattern}: {rule} not refused")
            except compare_bounds.Invalid as exc:
                if (exc.rule, exc.path) != (rule, path) or CANARY in str(exc):
                    problems.append(
                        f"{leaf.pattern}: expected {rule} at {path}, got {exc.rule} at {exc.path}"
                    )
    assert problems == []


class RecDict(Mapping):
    def __init__(self, data, pattern, log, maps):
        self._d, self._p, self._log, self._maps = data, pattern, log, maps

    def _child(self, key):
        return self._p + ("{*}" if self._p in self._maps else f".{key}")

    def __getitem__(self, key):
        value = self._d[key]
        child = self._child(key)
        self._log.add(child)
        return wrap(value, child, self._log, self._maps)

    def __iter__(self):
        return iter(self._d)

    def __len__(self):
        return len(self._d)


class RecList(Sequence):
    def __init__(self, data, pattern, log, maps):
        self._d, self._p, self._log, self._maps = data, pattern, log, maps

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self._d)))]
        value = self._d[index]
        self._log.add(self._p + "[*]")
        return wrap(value, self._p + "[*]", self._log, self._maps)

    def __len__(self):
        return len(self._d)


def wrap(value, pattern, log, maps):
    if isinstance(value, dict):
        return RecDict(value, pattern, log, maps)
    if isinstance(value, list):
        return RecList(value, pattern, log, maps)
    return value


def test_contract_covers_every_consumed_leaf():
    e, lv = rich_pair()
    patterns = {leaf.pattern for leaf in compare_validate.CONTRACT}
    maps = {p[: p.index("{*}")] for p in patterns if "{*}" in p}
    log: set[str] = set()
    for doc in (e, lv):
        compare_validate.validate(doc, doc["verification_id"])
    cmp = compare_match.build(wrap(e, "$", log, maps), wrap(lv, "$", log, maps), build_facts())
    compare_render.markdown(
        {**cmp, "comparison_id": "gc-20261023T120501Z-5e6f7a8b", "created_at": "2026-10-23T12:05:01Z"},
        "0" * 64,
    )
    assert log - patterns == set(), "comparison reads fields outside the contract"
    assert patterns - log - compare_validate.VALIDATION_ONLY == set(), "stale contract rows"


def build_facts():
    from comparehelp import facts

    return facts()


# ------------------------------------------------------------------------------ 06c refusal inside a secret
def test_06c_refusal_inside_secret_finding_has_no_value():
    e, _ = rich_pair()
    secret = next(f for f in e["findings"] if "tool" in f and f["tool"].get("scanner") == "secret")
    secret["tool"]["secret"]["value"] = CANARY
    secret["location"]["line"] = CANARY
    rule, path = invalid(e)
    assert (rule, path) == ("type", f"$.findings[{e['findings'].index(secret)}].location.line")
    assert CANARY not in rule + path


# ------------------------------------------------------------------------------ realism (delivered writers)
def _flow_results(env):
    project = env["project"]
    vid_fail, _ = test_guard.full_run(env)
    vid_pass, _ = test_guard.full_run(env, finding=False)
    vid = test_guard.opened(env)
    assert test_guard.plan(env, vid, exclusions=[{"check": "C1", "reason": "user out of scope"}]).ok
    assert guard.conclude(str(project), vid).ok
    vid_cancel = test_guard.opened(env)
    assert test_guard.plan(env, vid_cancel).ok
    assert cancel.cancel(str(project), vid_cancel, "user stopped").ok
    accepted = guard.accept_risk(
        str(project), vid_fail, "F1", "accepted for release", interaction=FakeInteraction(answers=["F1"])
    )
    assert accepted.ok, accepted.to_text()
    return [vid_fail, vid_pass, vid, vid_cancel]


def _validate_all(env, vids):
    for vid in vids:
        raw = (env["project"] / test_guard.REPORTS / f"{vid}.json").read_bytes()
        doc = json.loads(raw)
        compare_bounds.prescan(raw)
        compare_validate.validate(doc, vid)
    return [json.loads((env["project"] / test_guard.REPORTS / f"{v}.json").read_bytes()) for v in vids]


def test_validator_accepts_delivered_results(env):
    docs = _validate_all(env, _flow_results(env))
    assert any(d["risk_acceptances"] for d in docs) and any(d["cancellation"] for d in docs)


def test_05s_chain_and_remerge_via_records_flow(env):
    project = str(env["project"])
    vid = test_guard.opened(env)
    assert test_guard.plan(env, vid).ok
    ev = test_guard.ev()
    f = test_guard.high_finding
    assert test_guard.record(
        env, vid, evidence=[ev], findings=[f("F1", location={"path": "src/login.py", "line": 1})]
    ).ok
    for fid, line, sources in (("F2", 2, ["F1"]), ("F3", 3, ["F2"]), ("F4", 4, ["F1"])):
        out = test_guard.record(
            env,
            vid,
            findings=[
                f(
                    fid,
                    location={"path": "src/login.py", "line": line},
                    merged_from=sources,
                    merge_evidence=["E1"],
                )
            ],
        )
        assert out.ok, out.to_text()
    assert test_guard.record(
        env, vid, ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F3", "F4"]}]
    ).ok
    assert guard.conclude(project, vid).ok
    (doc,) = _validate_all(env, [vid])
    by = {x["id"]: x for x in doc["findings"]}
    assert by["F1"]["merged_into"] == "F4" and "F1" in by["F2"]["merged_from"]
    later = {**copy.deepcopy(doc), "verification_id": L_ID}
    cmp = build(doc, later)
    survivors = sorted(x["earlier"]["finding"] for x in entries(cmp))
    assert survivors == ["F3", "F4"] and {x["class"] for x in entries(cmp)} == {"still_present"}
    merged = {x["earlier"]["finding"]: x["earlier"]["merged"] for x in entries(cmp)}
    assert merged == {"F3": ["F2"], "F4": ["F1"]}
    for x in entries(cmp):
        notes = [n for n in x["notes"] if n["kind"] == "merge"]
        assert notes and "F1" in json.dumps(notes)
    plain = copy.deepcopy(doc)
    plain["findings"] = [x for x in plain["findings"] if x["merged_into"] is None]
    for x in plain["findings"]:
        x["merged_from"] = []
    plain_cmp = build(plain, {**copy.deepcopy(plain), "verification_id": L_ID})
    assert [x["class"] for x in entries(plain_cmp)] == [x["class"] for x in entries(cmp)]


@posix_only
def test_validator_accepts_delivered_opengrep_result(env, fake):
    vid = test_guard_tool.planned(env, [test_guard_tool.check()])
    out = test_guard_tool.tool(env, vid, [test_guard_tool.tc()])
    assert out.ok, out.to_text()
    assert guard.conclude(str(env["project"]), vid).ok
    (doc,) = _validate_all(env, [vid])
    assert doc["adapter_runs"] and any("tool" in x for x in doc["findings"])


@posix_only
def test_validator_accepts_delivered_trivy_result(env, trivy):
    trivyhelp.write(env, {"pom.xml": trivyhelp.POM})
    vid = trivyhelp.planned(env, [trivyhelp.tcheck()])
    trivyhelp.provisioned(env, vid)
    assert trivyhelp.scan(env, vid, [trivyhelp.trc()]).ok
    fids = [x["id"] for x in trivyhelp.state(env, vid)["findings"] if x["source"] == "trivy"]
    ledger = {
        "schema": "ai-secure-code-toolkit/guard-record/v1",
        "ledger": [{"check": "C1", "state": "not_met", "evidence": ["trivy-1-1"], "findings": fids}],
    }
    assert guard.record(
        str(env["project"]), vid, test_guard.req(env, test_guard.with_attempt(env, vid, ledger))
    ).ok
    assert guard.conclude(str(env["project"]), vid).ok
    (doc,) = _validate_all(env, [vid])
    assert doc["adapter_runs"][0]["adapter"] == "trivy" and doc["adapter_runs"][0]["components"]


def test_minimal_fixture_helpers_are_valid():
    doc = result(E_ID, findings=[og("O1"), tv("T1", check="C1")], runs=[og_run(1, ("C1",))])
    with pytest.raises(compare_bounds.Invalid):
        compare_validate.validate(doc, E_ID)  # T1 names run 1, an Opengrep run
    doc["findings"].pop()
    compare_validate.validate(doc, E_ID)
    assert row("C1", R1)["state"] == "met" and R2
