"""FEATURE-003-B integration tests: single-source generation via the FEATURE-001-A writer (AC-003B-01a…01k).

All runs use the CLI in sandbox target projects beneath the test's tmp_path.
"""

from __future__ import annotations

import json

import pytest
from carhelp import (
    AGENTS,
    BEGIN,
    DEF_REL,
    END,
    ENV,
    GOLDEN_001A_FRAGMENT,
    HOST,
    INSTR,
    KINDS,
    PATHS,
    RECORD_001A_KEYS,
    begin_count,
    canaries,
    canary_needles,
    choices,
    codes,
    edit_statement,
    entry,
    identity_text,
    inner,
    packaged_definition,
    problem,
    routing_region,
    run_copy,
    sandbox,
    toolkit_copy,
    watch_writes,
    written_paths,
)

from x_ipe_secure_code.environments import PROFILES


def _ok(proc, out):
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return out


def _render(box, kind: str, version: str | None = None) -> str:
    from x_ipe_secure_code import __version__, routing

    defn = routing.parse(box.definition_path().read_bytes())
    identity = routing.RoutingIdentity(version or __version__, defn.digest)
    host = HOST if kind == "system-prompt" else None
    return routing.render(defn, identity, PROFILES[box.env], kind, host=host)


def _accept_host_entry(box, old: bytes = b"in-flow", new: bytes = b"in-flow (team wording)") -> bytes:
    data = box.read(AGENTS)
    edited = data.replace(old, new, 1)
    assert edited != data
    box.write(AGENTS, edited)
    assert entry(_ok(*box.carriers()), "host-entry")["state"] == "kept-differs"
    assert entry(_ok(*box.carriers("--accept", "host-entry")), "host-entry")["state"] == "customized"
    return edited


def _copy_runner(copy, box):
    def init(*args):
        return run_copy(copy, box, "init", "--project", str(box.root), "--env", box.env, *args)

    def carriers(*args):
        return run_copy(copy, box, "carriers", "--project", str(box.root), "--env", box.env, *args)

    return init, carriers


def _definition_b(suffix: str = " Definition B.") -> dict:
    obj = packaged_definition()
    edit_statement(obj, suffix)
    return obj


# ---------------------------------------------------------------- AC-003B-01a

def test_01a_all_selected_carriers_at_decided_locations_same_identity(tmp_path):
    from x_ipe_secure_code import __version__, routing

    box = sandbox(tmp_path)
    out = _ok(*box.select_all())
    digest = routing.parse(box.definition_path().read_bytes()).digest
    identity = identity_text(__version__, digest)
    assert out["data"]["routing_identity"] == identity
    expected_state = {"host-entry": "current", "github-instructions": "created", "system-prompt": "created"}
    for kind in KINDS:
        item = entry(out, kind)
        assert item["path"] == PATHS[kind] and item["selection"] == "selected"
        assert item["state"] == expected_state[kind]
        text = box.text(PATHS[kind])
        assert inner(text) == _render(box, kind)
        assert f"Routing identity: {identity}." in text
        assert begin_count(box.read(PATHS[kind])) == 1


# ---------------------------------------------------------------- AC-003B-01b

@pytest.mark.parametrize("change", ["maintainer-edit", "toolkit-source-definition", "new-toolkit-version"])
def test_01b_definition_change_updates_every_unedited_carrier_in_one_run(tmp_path, change):
    box = sandbox(tmp_path)
    identity_a = _ok(*box.select_all())["data"]["routing_identity"]
    runs = []
    if change == "maintainer-edit":
        box.edit_definition()
        out = _ok(*box.carriers())
        assert [entry(out, k)["state"] for k in KINDS] == ["updated"] * 3  # all in the same run
        runs.append(out)
    elif change == "toolkit-source-definition":
        copy = toolkit_copy(tmp_path, definition=_definition_b(), name="toolkit-def-b")
        init = _ok(*box.init(toolkit=copy))
        assert init["data"]["fragment"] == "update" and "FRAGMENT_EDITED" not in codes(init)
        out = _ok(*box.carriers())
        assert [entry(out, k)["state"] for k in KINDS] == ["current", "updated", "updated"]
        runs.append(out)
    else:
        copy = toolkit_copy(tmp_path, version="0.2.0", definition=_definition_b(), name="toolkit-0.2.0")
        init, carriers = _copy_runner(copy, box)
        first = _ok(*carriers())  # an old record, a new running toolkit version: never refused
        assert [entry(first, k)["state"] for k in KINDS] == ["updated"] * 3
        assert first["data"]["routing_identity"] == identity_a.replace(" 0.1.0,", " 0.2.0,")
        runs.append(first)
        installed = _ok(*init())
        assert installed["data"]["fragment"] == "update"
        out = _ok(*carriers())
        assert [entry(out, k)["state"] for k in KINDS] == ["current", "updated", "updated"]
        runs.append(out)
    identity_b = runs[-1]["data"]["routing_identity"]
    assert identity_b != identity_a
    for kind in KINDS:
        text = box.text(PATHS[kind])
        assert f"Routing identity: {identity_b}." in text and identity_a not in text
    for out in runs:
        assert "FRAGMENT_EDITED" not in codes(out)
        assert all(item["state"] != "kept-differs" for item in out["data"]["carriers"])


# ---------------------------------------------------------------- AC-003B-01d

def test_01d_pre_003b_install_two_step_upgrade(tmp_path):
    box = sandbox(tmp_path, init=False)
    era = toolkit_copy(tmp_path, era="001A")
    _ok(*box.init(toolkit=era))  # a real pre-003B install: FEATURE-001-A-era payload
    assert box.text(AGENTS) == GOLDEN_001A_FRAGMENT[ENV]
    record = box.record()
    assert set(record) == RECORD_001A_KEYS and f".github/skills/{DEF_REL}" not in record["files"]
    initialized_at = record["initialized_at"]

    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.carriers()
    assert proc.returncode == 1 and codes(out) == ["ROUTING_DEFINITION_INVALID"]
    assert "routing-definition.json" in out["problems"][0]["message"]
    assert any("secure-code init" in step for step in out["next_steps"])
    assert writes == [] and box.hashes() == before

    out = _ok(*box.init())
    assert f".github/skills/{DEF_REL}" in out["data"]["files"]["created"]
    assert out["data"]["fragment"] == "update" and "FRAGMENT_EDITED" not in codes(out)
    data = box.read(AGENTS)
    assert begin_count(data) == 1 and data.startswith(BEGIN.encode()) and data.rstrip().endswith(END.encode())
    assert box.record()["initialized_at"] == initialized_at

    out = _ok(*box.carriers())
    assert entry(out, "host-entry")["state"] == "current"


# ---------------------------------------------------------------- AC-003B-01e

def test_01e_init_and_carriers_interleaved_single_fragment_same_state(tmp_path):
    box = sandbox(tmp_path)

    def init(expected: str):
        out = _ok(*box.init())
        assert out["data"]["fragment"] == expected, out["data"]["fragment"]
        return out

    def carriers(expected: dict[str, str], *args: str):
        out = _ok(*box.carriers(*args))
        for kind, state in expected.items():
            assert entry(out, kind)["state"] == state, (kind, entry(out, kind))
        return out

    def same_state_checks(out):
        assert "FRAGMENT_EDITED" not in codes(out)
        for rel in (AGENTS, INSTR):
            if box.path(rel).exists():
                assert begin_count(box.read(rel)) <= 1

    for out in (carriers({"host-entry": "current"}), init("current"),
                carriers({"host-entry": "current", "github-instructions": "created"},
                         "--select", "github-instructions"),
                init("current"), carriers({"host-entry": "current", "github-instructions": "current"}),
                init("current")):
        same_state_checks(out)

    box.edit_definition(lambda o: edit_statement(o, " Second wording."))
    for out in (init("update"), carriers({"host-entry": "current", "github-instructions": "updated"})):
        same_state_checks(out)
    box.edit_definition(lambda o: edit_statement(o, " Third wording."))
    for out in (carriers({"host-entry": "updated", "github-instructions": "updated"}), init("current")):
        same_state_checks(out)

    _accept_host_entry(box)
    for out in (init("customized"), carriers({"host-entry": "customized", "github-instructions": "current"}),
                init("customized"), init("customized"), carriers({"host-entry": "customized"})):
        same_state_checks(out)


# ---------------------------------------------------------------- AC-003B-01f

def test_01f_agents_and_instructions_identical_routing_one_declaration(tmp_path):
    box = sandbox(tmp_path)
    out = _ok(*box.carriers("--select", "github-instructions"))
    agents, instructions = box.text(AGENTS), box.text(INSTR)
    assert routing_region(agents) == routing_region(instructions)  # no conflicting or additional trigger
    identity = out["data"]["routing_identity"]
    for text in (agents, instructions):
        assert f"Routing identity: {identity}." in text
        assert ("All toolkit carriers with this routing identity are one integration declaration: "
                "together they start at most one Copilot or Guard flow for the same stage and "
                "effective context.") in text
    declaration = out["data"]["integration_declaration"]
    assert AGENTS in declaration and INSTR in declaration and identity in declaration
    assert "one integration declaration" in declaration
    status = _ok(*box.status())["data"]["host_integration"]
    assert status["routing_identity"] == identity
    assert AGENTS in status["integration_declaration"] and INSTR in status["integration_declaration"]
    assert identity in status["integration_declaration"]


# ---------------------------------------------------------------- AC-003B-01g

@pytest.mark.parametrize("order", ["init-then-carriers", "carriers-then-init"])
def test_01g_accepted_host_entry_customized_in_init_and_carriers_both_orders(tmp_path, order):
    box = sandbox(tmp_path)
    edited = _accept_host_entry(box)
    accepted = box.record()["carriers"]["entries"]["host-entry"]["accepted"]

    def init():
        out = _ok(*box.init())
        data = out["data"]
        assert data["fragment"] == "customized" and data["already_current"] is False
        assert "not synced with the routing definition" in data["fragment_note"]
        assert "FRAGMENT_EDITED" not in codes(out)

    def carriers():
        item = entry(_ok(*box.carriers()), "host-entry")
        assert item["state"] == "customized"
        assert "not synced with the routing definition" in item["next_step"]

    with watch_writes() as writes:
        for run in ((init, carriers) if order == "init-then-carriers" else (carriers, init)):
            run()
    assert box.read(AGENTS) == edited
    agents = box.path(AGENTS).resolve()
    for path in written_paths(writes):
        assert path != agents and not path.name.startswith(".AGENTS.md.tmp"), path
    assert box.record()["carriers"]["entries"]["host-entry"]["accepted"] == accepted


# ---------------------------------------------------------------- AC-003B-01h

def test_01h_edit_after_acceptance_is_fragment_edited(tmp_path):
    box = sandbox(tmp_path)
    _accept_host_entry(box)
    again = box.read(AGENTS).replace(b"team wording", b"team wording, revised")
    box.write(AGENTS, again)
    proc, out = box.init()
    _ok(proc, out)
    assert "FRAGMENT_EDITED" in codes(out) and out["data"]["fragment"] == "edited_kept"
    assert "customized" not in proc.stdout
    assert box.read(AGENTS) == again
    out = _ok(*box.carriers())
    item = entry(out, "host-entry")
    assert item["state"] == "kept-differs" and "FRAGMENT_EDITED" in codes(out)
    difference = out["data"]["differences"][AGENTS]
    assert difference["diff"] and difference["choices"] == choices("host-entry")
    assert box.read(AGENTS) == again


# ---------------------------------------------------------------- AC-003B-01i

def _break_member(name: str):
    def accepted(member):
        return member["entries"]["host-entry"]["accepted"]

    def run(record):
        member = record["carriers"]
        if name == "not-object":
            record["carriers"] = ["host-entry"]
        elif name == "accepted-without-digest":
            del accepted(member)["fragment_sha256"]
        elif name == "malformed-digest":
            accepted(member)["fragment_sha256"] = "not-a-digest"
        elif name == "routing-wrong-type":
            accepted(member)["routing"] = "0.1.0"
        elif name == "unknown-key":
            member["surprise"] = True
        return record

    return run


@pytest.mark.parametrize("replace", [False, True], ids=["plain", "with-replace"])
@pytest.mark.parametrize("name", ["not-object", "accepted-without-digest", "malformed-digest",
                                  "routing-wrong-type", "unknown-key", "truncated-json"])
def test_01i_invalid_member_never_honoured(tmp_path, name, replace):
    box = sandbox(tmp_path)
    _accept_host_entry(box)
    if name == "truncated-json":
        box.save_record(json.dumps(box.record())[:-25])
    else:
        box.save_record(_break_member(name)(box.record()))
    before = box.hashes()
    args = ("--replace", AGENTS) if replace else ()
    with watch_writes() as writes:
        proc, out = box.init(*args)
    assert proc.returncode == 1 and codes(out) == ["RECORD_INVALID"]
    lowered = proc.stdout.lower()
    assert "customized" not in lowered and "synchronized" not in lowered
    assert out["data"].get("fragment") not in ("current", "update", "customized")
    assert box.hashes() == before and writes == []


# ---------------------------------------------------------------- AC-003B-01j

@pytest.mark.parametrize("change", ["maintainer-edit", "toolkit-source-definition", "new-toolkit-version"])
def test_01j_accepted_then_new_routing_identity(tmp_path, change):
    box = sandbox(tmp_path)
    edited = _accept_host_entry(box)
    identity_a = _ok(*box.carriers())["data"]["routing_identity"]
    if change == "maintainer-edit":
        box.edit_definition()
        init, carriers = box.init, box.carriers
    elif change == "toolkit-source-definition":
        copy = toolkit_copy(tmp_path, definition=_definition_b(), name="toolkit-def-b")

        def init():
            return box.init(toolkit=copy)

        carriers = box.carriers
    else:
        copy = toolkit_copy(tmp_path, version="0.2.0", name="toolkit-0.2.0")
        init, carriers = _copy_runner(copy, box)

    proc, out = init()
    _ok(proc, out)
    assert out["data"]["fragment"] == "customized"
    assert box.read(AGENTS) == edited
    changed = problem(out, "CUSTOMIZATION_ROUTING_CHANGED")
    assert identity_a in changed["message"]
    assert "secure-code carriers" in out["next_steps"][0]
    assert "synchronized" not in proc.stdout.lower() and "FRAGMENT_EDITED" not in codes(out)

    out = _ok(*carriers())
    identity_b = out["data"]["routing_identity"]
    assert identity_b != identity_a and identity_b in changed["message"]
    assert entry(out, "host-entry")["state"] == "kept-differs"  # a difference for a decision (05d)
    assert box.read(AGENTS) == edited


# ---------------------------------------------------------------- AC-003B-01k

@pytest.mark.parametrize("mode", ["json", "text"])
def test_01k_accept_then_replace_then_carriers(tmp_path, mode):
    box = sandbox(tmp_path)
    prefix = "# Team rules ü\r\n\r\nKeep this.\r\n\r\n".encode()
    box.write(AGENTS, prefix + box.read(AGENTS).replace(b"\n", b"\r\n"))
    _ok(*box.init())  # CRLF file, fragment unchanged in content
    secrets = "".join(value + "\n" for value in canaries().values()).replace("\n", "\r\n")
    data = box.read(AGENTS)
    at = data.index(END.encode())
    box.write(AGENTS, data[:at] + secrets.encode() + data[at:])
    accepted_bytes = _accept_host_entry(box, b"in-flow", b"in-flow, team")

    proc, out = box.init("--replace", AGENTS, json_out=mode == "json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for needle in canary_needles():
        assert needle not in proc.stdout and needle not in proc.stderr
    if mode == "json":
        assert out["data"]["fragment"] == "replaced"
        replaced = out["data"]["replaced_customization"]
        assert "accepted customization" in replaced["statement"] and "replaced" in replaced["statement"]
        assert replaced["content"].startswith("secret-masked")
        diff = "\n".join(replaced["diff"])
        for kind in canaries():
            assert f"[masked:{kind}]" in diff, kind
    else:
        assert "replaced" in proc.stdout and "accepted customization" in proc.stdout
        assert "[masked:credential." in proc.stdout
    after = box.read(AGENTS)
    assert after.startswith(prefix)  # all bytes outside the fragment identical
    assert inner(after.decode()) == _render(box, "host-entry")
    record = box.record()
    assert "carriers" not in record  # acceptance cleared; nothing else remained in the member

    assert entry(_ok(*box.carriers()), "host-entry")["state"] == "current"
    assert _ok(*box.init())["data"]["fragment"] == "current"

    box.write(AGENTS, accepted_bytes)  # restoring the old text is never honoured again
    out = _ok(*box.init())
    assert out["data"]["fragment"] == "edited_kept" and "FRAGMENT_EDITED" in codes(out)
    assert entry(_ok(*box.carriers()), "host-entry")["state"] == "kept-differs"
