"""FEATURE-002-F cancellation (AC-002F-04f; review M2): the toolkit stops and removes the containers it
owns, claims termination only when the runtime reports them gone, and commits nothing afterwards."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json
import threading
import time

from helperhelp import GUARD, env, fake, flow, helper_run, henv, state_of  # noqa: F401 - fixture reuse

from x_ipe_secure_code.guard import cancel

REPORTS = "x-ipe-docs/secure-code/reports/guard"


def _cancel_when_running(flow, vid, purpose):
    def worker():
        end = time.time() + 30
        while time.time() < end:
            st = flow.fake.state()
            if any(
                c["State"].get("Running")
                and c["Config"]["Labels"].get("x-ipe.secure-code.purpose") == purpose
                for c in st["containers"].values()
            ):
                out["cancel"] = cancel.cancel(str(flow.root), vid, "user stopped")
                return
            time.sleep(0.1)

    out = {}
    thread = threading.Thread(target=worker)
    thread.start()
    return thread, out


def test_04f_cancel_stops_container_or_not_confirmed(flow):
    vid, hid = flow.ready()
    flow.fake.set(runs={"target": {"mode": "auto", "sleep": 20}})
    a = flow.helper_attempt(vid)
    thread, out = _cancel_when_running(flow, vid, "target")
    result = flow.run(vid, hid, a)
    thread.join(60)
    assert result.problems[0].code == "RUN_CANCELLED"
    assert result.data["termination"] == "confirmed"
    assert out["cancel"].ok, out["cancel"].to_text()
    final = json.loads((flow.root / REPORTS / f"{vid}.json").read_text())
    assert final["cancellation"]["tool_termination"]["tool"] == "confirmed"
    assert final["verdict"] != "pass" and flow.fake.state()["containers"] == {}
    assert [r for r in flow.fake.log() if r[0] == "kill"]
    assert all(x["status"] != "finished" for x in final["attempts"] if x["id"] == a)


def test_04f_not_confirmed_when_removal_fails(flow):
    vid, hid = flow.ready()
    flow.fake.set(runs={"target": {"mode": "auto", "sleep": 20}}, rm_fails="target")
    thread, out = _cancel_when_running(flow, vid, "target")
    result = flow.run(vid, hid, flow.helper_attempt(vid))
    thread.join(60)
    assert result.problems[0].code == "RUN_CANCELLED" and result.data["termination"] == "not_confirmed"
    final = json.loads((flow.root / REPORTS / f"{vid}.json").read_text())
    assert final["cancellation"]["tool_termination"]["tool"] == "not_confirmed"


def test_m2_cancel_during_compile_probe(flow):
    vid = helper_run(flow.env)
    flow.fake.set(
        runs={
            "compile": {
                "mode": "stdout",
                "sleep": 20,
                "stdout": json.dumps({"ok": True, "version": [3, 12, 4], "error": ""}),
            }
        }
    )
    thread, out = _cancel_when_running(flow, vid, "compile")
    result = flow.submit(vid)
    thread.join(60)
    assert result.problems[0].code == "RUN_CANCELLED", result.to_text()
    assert out["cancel"].ok
    state = state_of(flow.env, vid)
    assert "helpers" not in state and not (flow.root / GUARD / vid / "helpers").exists()
    final = json.loads((flow.root / REPORTS / f"{vid}.json").read_text())
    gen = [x for x in final["attempts"] if x["kind"] == "generation"]
    assert gen and gen[0]["status"] == "cancelled"
    assert flow.fake.state()["containers"] == {}
