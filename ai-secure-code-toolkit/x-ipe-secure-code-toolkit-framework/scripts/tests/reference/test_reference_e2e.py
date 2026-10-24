"""FEATURE-001-E end-to-end tests: carrier-verification bootstrap (AC-001E-09a, 09b) on loopback fixtures."""

from __future__ import annotations

import refhelp
from netguard import GUARD, network_guards  # noqa: F401 - autouse guards
from refhelp import (
    CWE79,
    LOCAL,
    RefEnv,
    mod,
    page,
)

clock, renv, server = refhelp.clock, refhelp.renv, refhelp.server  # pytest fixtures


# AC-001E-09a
def test_carrier_verification_bootstrap_e2e(renv, clock):
    renv.standard(CWE79)
    renv.serve("/docs/cwe/79.html", page("cwe-79.html"))
    first = renv.opened(renv.save_scope(LOCAL))  # 1. verification on an available (Local) scope
    renv.grant(first)  # 2. the User grants reference_fetch (terminal)
    fetched = renv.fetch(first)  # 3. one fetch fills the cache
    assert fetched.ok and fetched.data["outcome"] == "fetched", fetched.to_dict()
    assert renv.conclude(first).ok  # 4. conclude
    egress = renv.state(first)["egress"]
    assert len(egress["declarations"]) == 1 and egress["declarations"][0]["used"]
    assert renv.srv.count == 1
    policy = renv.entry(CWE79)  # 5. resolve → cached, with digests
    assert policy["retrieval_status"] == "cached" and policy["knowledge_kind"] == "reference"
    evidence = policy["source_evidence"]
    assert evidence["policy_state_digest"] and evidence["response_digest"]
    scope_id = renv.save_scope(LOCAL, CWE79)  # 6. adopt it and open a new verification
    second = renv.opened(scope_id)
    adopted = {a["rule"]: a["state_digest"] for a in renv.state(second)["scope"]["adopted"]}
    assert adopted[CWE79] == evidence["policy_state_digest"]
    assert renv.srv.count == 1 and renv.state(second)["egress"]["declarations"] == []


# AC-001E-09b
def test_reference_only_library_cannot_bootstrap(project, tmp_path, server, clock):
    env = RefEnv(project, tmp_path, server, local=False)
    env.standard(CWE79)
    env.serve("/docs/cwe/79.html", page("cwe-79.html"))
    proposal = env.resolve(CWE79)
    assert proposal.data["entries"][0]["reason"] == "not_cached"
    decisions = env.req(
        {
            "schema": "ai-secure-code-toolkit/scope-decisions/v1",
            "mode": "clues",
            "considered": [CWE79],
            "proposal_digest": proposal.data["proposal_digest"],
            "clues": "reference only",
            "language_context": [],
            "decisions": [{"ref": CWE79, "decision": "not_adopted", "reason": "content not obtained"}],
            "confirmation_note": "User explicitly confirmed the scope",
        }
    )
    saved = mod("policy.service").save_scope(str(project), decisions, True)
    if saved.ok:
        opened = env.open_guard(saved.data["scope_id"])
        assert not opened.ok, opened.to_dict()
    else:
        assert saved.problems[0].code, saved.to_dict()
    result = env.fetch(None)
    assert result.problems[0].code == "RUN_REQUIRED"
    assert "B16" in result.next_steps[0] and "available scope" in result.next_steps[0]
    assert env.srv.count == 0 and GUARD["connects"] == []
