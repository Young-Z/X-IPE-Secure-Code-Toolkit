"""FEATURE-002-F user grant (AC-002F-04o, 04p, 05g; FR-002F-7; design §7)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

from helperhelp import env, fake, flow, helper_run, henv, mod, state_of  # noqa: F401 - fixture reuse

from x_ipe_secure_code.guard import service as guard

CONSENT_PARTS = (
    "recorded cooperative consent",
    "cannot prove a person gave it",
    "not a security boundary",
    "enforced container limits are the security boundary",
)


# ---------- AC-002F-04o
def test_04o_tty_digests_new_grant_no_egress(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    refused = flow.grant(vid)
    assert refused.problems[0].code == "HELPER_NOT_REVIEWED"
    assert flow.review(vid, hid).ok
    non_tty = flow.grant(vid, interactive=False)
    assert (
        non_tty.problems[0].code == "INTERACTIVE_REQUIRED" and "agents cannot" in non_tty.problems[0].message
    )
    mismatch = flow.grant(vid, typed="gv-wrong")
    assert mismatch.problems[0].code == "CONFIRMATION_MISMATCH"
    assert "helper_grants" not in state_of(flow.env, vid)
    out = flow.grant(vid)
    assert out.ok, out.to_text()
    prompt = flow.prompts[0]
    h = state_of(flow.env, vid)["helpers"][0]
    for part in (
        vid,
        h["check"],
        h["goal"],
        "src/config",
        h["script"]["sha256"],
        h["declaration_sha256"],
        h["samples_sha256"],
    ):
        assert part in prompt, part
    record = state_of(flow.env, vid)["helper_grants"][0]
    assert record["verification"] == vid and record["interactive"] is True
    assert record["helpers"][0]["script_sha256"] == h["script"]["sha256"]
    assert record["helpers"][0]["sample_digests"] == [s["sha256"] for s in h["samples"]]
    assert state_of(flow.env, vid)["egress"] == {"grants": [], "declarations": []}
    again = flow.grant(vid)
    assert again.problems[0].code == "HELPER_NOT_REVIEWED"
    new = flow.submit(vid).data["helper"]
    assert flow.review(vid, new).ok
    assert flow.grant(vid).data["helpers"] == [new]


# ---------- AC-002F-04p (command output)
def test_04p_output_wording(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    assert flow.review(vid, hid).ok
    out = flow.grant(vid)
    text = (out.data["wording"] + " " + flow.prompts[0]).lower()
    for part in CONSENT_PARTS:
        assert part in text, part


# ---------- AC-002F-05g
def test_05g_agent_only_not_granted(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    assert flow.review(vid, hid).ok
    assert flow.grant(vid, interactive=False).problems[0].code == "INTERACTIVE_REQUIRED"
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["reason_code"] == "not_granted" and not flow.fake.creates("target")
    concluded = guard.conclude(str(flow.root), vid)
    part = (
        concluded.ok
        and __import__("json").loads(
            (flow.root / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.json").read_text()
        )["helpers"]
    )
    entry = part["helpers"][0]
    assert entry["gap"] == "not granted" and entry["execution"] == "not executed"
    ledger = {r["check"]: r for r in concluded.data["ledger"]}
    assert ledger["C1"]["state"] == "unconfirmed"
