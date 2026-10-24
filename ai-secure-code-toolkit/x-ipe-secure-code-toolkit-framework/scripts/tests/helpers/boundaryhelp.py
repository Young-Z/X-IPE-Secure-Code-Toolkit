"""Delivered Guard outputs for runs without helpers (FEATURE-002-F byte-identity, DAO-017 condition 2).

`delivered_outputs` drives the delivered 002-A/C commands on a fixed scenario with a frozen clock and
returns normalised texts. The fixtures in `fixtures/pre_002f/` were captured with the delivered code at
the TASK-085 step 0 (before any 002-F change); `test_helper_boundary.py` compares the current outputs
with them. Normalised: verification ids, times, project paths, footer and renderer digests (the
renderer digest changes with any report.py byte, by CR-TASK-086 design).
"""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pre_002f"
FROZEN = "2026-10-24T01:00:00Z"
VID = re.compile(r"gv-\d{8}T\d{6}Z-([0-9a-f]{8})")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
FOOTER = re.compile(r"guard-result-sha256: [0-9a-f]{64}")


def normalise(text: str, root: Path, renderer: str | None = None) -> str:
    for form in {str(root), str(root.resolve())}:
        text = text.replace(form, "<project>")
    for suffix in set(VID.findall(text)):
        text = text.replace(suffix, "<vid8>")
    if renderer:
        text = text.replace(renderer, "<renderer>")
    text = FOOTER.sub("guard-result-sha256: <footer>", text)
    return TIME.sub("<time>", text)


def _dump(result: Any) -> str:
    data = result.to_dict() if hasattr(result, "to_dict") else result
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)


def delivered_outputs(env: dict[str, Any]) -> dict[str, str]:
    """Run the fixed scenario on `env` (test_guard.env layout) and return name → normalised text."""
    import test_guard as tg

    from x_ipe_secure_code.guard import cancel as guard_cancel
    from x_ipe_secure_code.guard import model as guard_model
    from x_ipe_secure_code.guard import report
    from x_ipe_secure_code.guard import service as guard

    root: Path = env["project"]
    project = str(root)
    out: dict[str, str] = {}
    renderer = report.renderer_identity()["renderer_digest"]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(guard_model, "utc_now", lambda: FROZEN)
        patch.setattr(guard, "utc_now", lambda: FROZEN)

        def keep(name: str, value: Any) -> None:
            out[name] = normalise(_dump(value), root, renderer)

        def keep_md(name: str, text: str) -> None:
            out[name] = normalise(text, root, renderer)

        # A: Fail run (confirmed High finding): conclude, show, result JSON and Markdown.
        vid, concluded = tg.full_run(env)
        keep("a-conclude.json", concluded)
        keep("a-show.json", guard.show(project, vid))
        keep("a-result.json", tg.result_json(env, vid))
        keep_md("a-report.md", tg.report_md(env, vid))
        # B: Cannot confirm pass (finding not confirmed by the Reviewer).
        vid_b, concluded_b = tg.full_run(env, confirm=False)
        keep("b-conclude.json", concluded_b)
        keep("b-result.json", tg.result_json(env, vid_b))
        keep_md("b-report.md", tg.report_md(env, vid_b))
        # C: cancel finalize after a recorded plan and evidence.
        vid_c = tg.opened(env)
        assert tg.plan(env, vid_c).ok
        assert tg.record(env, vid_c, evidence=[tg.ev()]).ok
        keep("c-show-open.json", guard.show(project, vid_c))
        keep("c-cancel.json", guard_cancel.cancel(project, vid_c, "user stopped"))
        keep("c-result.json", tg.result_json(env, vid_c))
        keep_md("c-report.md", tg.report_md(env, vid_c))
        # D: plan validation outputs (refused, then accepted, then refused again).
        vid_d = tg.opened(env)
        base = tg.plan_doc()["checks"][0]
        method = {"name": "semantic-review", "kind": "reading", "required": True}
        tool = {"name": "opengrep", "kind": "runtime", "required": True}
        plans = {
            "d-plan-unknown-field": {"checks": [{**base, "colour": "red"}]},
            "d-plan-rule-not-adopted": {"checks": [{**base, "rule": "X/1/Y"}]},
            "d-plan-duplicate-method": {"checks": [{**base, "methods": [method, method]}]},
            "d-plan-choice-missing": {"checks": [{**base, "methods": [method, {**method, "name": "other"}]}]},
            "d-plan-adapter-kind": {"checks": [{**base, "methods": [{**tool, "kind": "reading"}]}]},
            "d-plan-choice-unknown-key": {
                "checks": [
                    {
                        **base,
                        "methods": [method, tool],
                        "method_choice": {
                            "considered": ["x"],
                            "selected": ["opengrep"],
                            "reason": "r",
                            "x": 1,
                        },
                    }
                ]
            },
        }
        for name, over in plans.items():
            keep(f"{name}.json", tg.plan(env, vid_d, **over))
        accepted_check = {
            **base,
            "methods": [method, {"name": "aux-read", "kind": "reading", "required": False}],
            "method_choice": {
                "considered": ["semantic-review", "aux-read"],
                "selected": ["semantic-review"],
                "reason": "cheapest sufficient",
            },
        }
        keep("d-plan-accepted.json", tg.plan(env, vid_d, checks=[accepted_check]))
        keep("d-plan-twice.json", tg.plan(env, vid_d))
        # E: record validation outputs.
        change = {"check": "C1", "change": "supplement", "reason": "r"}
        records = {
            "e-record-tool-id": {"evidence": [tg.ev("opengrep-1-1")]},
            "e-record-tool-method": {"evidence": [tg.ev("E9", method="opengrep", kind="runtime")]},
            "e-record-tool-source": {"evidence": [tg.ev()], "findings": [tg.high_finding(source="trivy")]},
            "e-record-unknown-check": {"ledger": [{"check": "C9", "state": "met", "evidence": []}]},
            "e-record-change-unknown-field": {
                "method_changes": [{**change, "method": {"name": "x", "kind": "reading"}, "colour": 1}]
            },
            "e-record-change-adapter-kind": {
                "method_changes": [{**change, "method": {"name": "trivy", "kind": "reading"}}]
            },
        }
        for name, parts in records.items():
            keep(f"{name}.json", tg.record(env, vid_d, **parts))
        keep(
            "e-record-change-accepted.json",
            tg.record(
                env, vid_d, method_changes=[{**change, "method": {"name": "extra-read", "kind": "reading"}}]
            ),
        )
        keep(
            "e-record-accepted.json",
            tg.record(
                env, vid_d, evidence=[tg.ev()], ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]
            ),
        )
        keep("e-state-plan.json", tg.state_json(env, vid_d)["plan"])
        # F: review validation outputs.
        keep(
            "f-review-unknown-type.json", tg.review(env, vid_d, [{"type": "foo", "id": "C1", "result": "x"}])
        )
        keep("f-review-accepted.json", tg.review(env, vid_d, [tg.na_confirmed()]))
        keep("f-conclude.json", guard.conclude(project, vid_d))
        keep("f-result.json", tg.result_json(env, vid_d))
        keep_md("f-report.md", tg.report_md(env, vid_d))
    return out


def write_fixtures(outputs: dict[str, str]) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (FIXTURES / name).write_text(text + "\n", encoding="utf-8")
