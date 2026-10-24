"""FEATURE-002-F end-to-end flows (AC-002F-05e, 08a, 08b, 08d) through the service functions and the CLI."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

from conftest import run_cli, tree_hashes
from helperhelp import (  # noqa: F401 - fixture reuse
    GUARD,
    Flow,
    env,
    fake,
    flow,
    helper_run,
    henv,
    no_runtime,
    raw_record,
    state_of,
)

from x_ipe_secure_code.cli import build_parser
from x_ipe_secure_code.guard import service as guard

REPORTS = "x-ipe-docs/secure-code/reports/guard"


# ---------- AC-002F-05e
def test_05e_no_runtime_full_flow_gap(henv, no_runtime):
    flow = Flow(henv)
    vid = helper_run(henv)
    out = flow.submit(vid)
    assert (
        out.problems[0].code == "HELPER_CHECK_FAILED"
        and "no container runtime CLI" in out.problems[0].message
    )
    hid = out.data["helper"]
    cli = run_cli(
        ["guard", "helper", "show", "--run", vid, "--project", str(henv["project"]), "--json"],
        henv["trust_dir"],
        env_extra={"PATH": str(no_runtime)},
    )
    shown = json.loads(cli.stdout)
    assert cli.returncode == 0 and shown["data"]["helpers"][0]["state"] == "check_failed"
    assert "runtime_unavailable" in shown["data"]["runtime"]
    concluded = guard.conclude(str(henv["project"]), vid)
    assert concluded.ok and concluded.data["verdict"] == "cannot_confirm_pass"
    result = json.loads((henv["project"] / REPORTS / f"{vid}.json").read_text())
    entry = result["helpers"]["helpers"][0]
    assert entry["id"] == hid and "compile probe unavailable" in entry["gap"]
    assert "## Temporary helper checks" in (henv["project"] / REPORTS / f"{vid}.md").read_text()


# ---------- AC-002F-08a
def test_08a_tree_diff_only_run_folder_reports(flow):
    root = flow.root
    skip = (
        root / GUARD,
        root / REPORTS,
        root / ".x-ipe/private/secure-code/locks",
        root / ".x-ipe/private/secure-code/tmp",
    )

    def snapshot():
        return {k: v for k, v in tree_hashes(root).items() if not any(k.startswith(str(s)) for s in skip)}

    vid = helper_run(flow.env)
    flow.request(vid, None)
    before = snapshot()
    vid, hid = flow.ready(vid)
    assert flow.run(vid, hid, flow.helper_attempt(vid)).ok
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    assert guard.conclude(str(root), vid).ok
    assert snapshot() == before
    assert not any("checks" == p.name for p in root.rglob("checks"))


# ---------- AC-002F-08b
def test_08b_cleanup_keep_release(flow):
    vid, hid, out = flow.executed()
    assert guard.conclude(str(flow.root), vid).ok
    run_dir = flow.root / GUARD / vid
    assert (run_dir / "helpers" / hid / "script.py").is_file()
    assert guard.keep(str(flow.root), vid, "audit").ok
    later = datetime.now(UTC) + timedelta(days=40)
    guard.cleanup(str(flow.root), now=later)
    assert (run_dir / "helpers" / hid / "script.py").is_file()
    assert guard.release(str(flow.root), vid).ok
    out = guard.cleanup(str(flow.root), now=later)
    assert out.ok and not run_dir.exists()
    assert (flow.root / REPORTS / f"{vid}.json").is_file()


# ---------- AC-002F-08d
def test_08d_no_publish_command_no_egress(flow):
    parser = build_parser()

    def choices(action_parser):
        return {
            name: sub
            for a in action_parser._actions
            if getattr(a, "choices", None)
            for name, sub in a.choices.items()
        }

    top = choices(parser)
    helper = choices(choices(top["guard"])["helper"])
    assert set(helper) == {"submit", "show", "grant", "run"}
    tools = choices(top["tools"])
    assert {"register-helper-image", "helper-conformance"} <= set(tools)
    words = ("publish", "export", "upload", "promote")
    names = set(helper) | set(tools) | set(choices(top["guard"]))
    assert not any(w in n for n in names for w in words)
    vid, hid, out = flow.executed()
    assert state_of(flow.env, vid)["egress"] == {"grants": [], "declarations": []}
    log = " ".join(" ".join(r) for r in flow.fake.log())
    assert "--network none" in log and "pull" not in [r[0] for r in flow.fake.log()]
    assert not os.path.exists(flow.root / "checks")
