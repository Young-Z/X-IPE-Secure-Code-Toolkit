"""FEATURE-003-B: FEATURE-001-A compatibility of the additive extension (AC-003B-08a…08e)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from carhelp import (
    AGENTS,
    DEF_REL,
    FRAMEWORK,
    GOLDEN_001A_FRAGMENT,
    HOST,
    INSTR,
    RECORD,
    RECORD_001A_KEYS,
    SYSP,
    baseline_001a,
    codes,
    normalize_init,
    normalize_record,
    packaged_definition,
    sandbox,
    toolkit_copy,
    watch_writes,
)
from conftest import SCRIPTS, TOOLKIT_ROOT

from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.install_record import SCHEMA, InstallRecord, RecordError, load

TESTS = SCRIPTS / "tests"
PINNED_001A_TESTS = {
    "test_project_init.py": "2f56555b3f0cda79884945b098b936f3b71493b1fffb3158f57e7c687d38daf6",
    "test_host_fragment.py": "2b0bb8e6725087915338da03a91c450310cd59de1dfc8f40d28fdff26a7159a5",
    "test_status.py": "32771fbd8df43f25b37739a285dad075c52bf01c13886ac997f769002f9c43b6",
}
FIELDS_001A = ["toolkit_version", "environment", "skills_dir", "host_entry", "fragment_sha256",
               "initialized_at", "updated_at", "files"]
INIT_DATA_KEYS_001A = ["root", "environment", "skills_dir", "host_entry", "files", "fragment",
                       "layout_created", "record", "already_current"]
DIGEST = "a" * 64
ROUTING = {"toolkit_version": "0.1.0", "definition_sha256": "b" * 64}


def _record_001a(**over) -> dict:
    data = {"schema": SCHEMA, "toolkit_version": "0.1.0", "environment": "github-copilot",
            "skills_dir": ".github/skills", "host_entry": AGENTS, "fragment_sha256": DIGEST,
            "initialized_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z",
            "files": {".github/skills/x/SKILL.md": "c" * 64}}
    data.update(over)
    return data


def _member() -> dict:
    return {"selected": ["host-entry", "github-instructions"],
            "entries": {"github-instructions": {"path": INSTR, "fragment_sha256": DIGEST,
                                                "routing": ROUTING}}}


def _write_record(root: Path, data: dict | str) -> None:
    path = root / RECORD
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------- AC-003B-08a

def test_08a_001a_tests_unmodified():
    for name, digest in PINNED_001A_TESTS.items():
        assert hashlib.sha256((TESTS / name).read_bytes()).hexdigest() == digest, name


# ---------------------------------------------------------------- AC-003B-08b

def test_08b_record_schema_fields_member_omitted_or_defaulted_and_001a_record_loads(tmp_path):
    plain = InstallRecord(*[_record_001a()[k] for k in FIELDS_001A])  # positional, as FEATURE-001-A
    assert plain.carriers is None  # optional, defaulted member
    as_dict = plain.to_dict()
    assert as_dict["schema"] == SCHEMA == "ai-secure-code-toolkit/install-record/v1"
    assert set(as_dict) == RECORD_001A_KEYS  # member omitted when unused
    assert dumps_json(as_dict) == dumps_json(_record_001a())  # equals what FEATURE-001-A writes

    extended = InstallRecord(*[_record_001a()[k] for k in FIELDS_001A], carriers=_member())
    data = extended.to_dict()
    assert set(data) == RECORD_001A_KEYS | {"carriers"}  # the only addition
    assert {k: data[k] for k in RECORD_001A_KEYS} == _record_001a()  # FEATURE-001-A fields unchanged
    assert "carriers" not in extended.comparable()  # init's rewrite decision ignores the member
    assert extended.full_comparable()["carriers"] == _member()

    root = tmp_path / "p"
    root.mkdir()
    _write_record(root, _record_001a())
    loaded = load(root)  # a FEATURE-001-A record is accepted without loss
    assert loaded.carriers is None and loaded.initialized_at == "2026-01-01T00:00:00Z"
    assert dumps_json(loaded.to_dict()) == dumps_json(_record_001a())
    _write_record(root, {**_record_001a(), "carriers": _member()})
    assert load(root).carriers == _member()


def _invalid_members() -> dict[str, object]:
    def acc(**over):
        accepted = {"fragment_sha256": DIGEST, "routing": ROUTING, "accepted_at": "2026-10-23T08:00:00Z"}
        accepted.update(over)
        return {"selected": ["host-entry"], "entries": {"host-entry": {"accepted": accepted}}}

    no_digest = acc()
    del no_digest["entries"]["host-entry"]["accepted"]["fragment_sha256"]
    return {
        "not-object": "x",
        "accepted-without-digest": no_digest,
        "malformed-digest": acc(fragment_sha256="XYZ"),
        "routing-wrong-type": acc(routing="0.1.0"),
        "bad-accepted-at": acc(accepted_at="yesterday"),
        "unknown-member-key": {**acc(), "extra": 1},
        "unknown-kind": {"selected": ["host-entry", "bogus"], "entries": {}},
        "selection-without-host-entry": {"selected": ["github-instructions"], "entries": {}},
        "wrong-path": {"selected": ["host-entry", "github-instructions"],
                       "entries": {"github-instructions": {"path": "x.md", "fragment_sha256": None,
                                                           "routing": ROUTING}}},
        "host-entry-with-path": {"selected": ["host-entry"],
                                 "entries": {"host-entry": {"path": AGENTS, "fragment_sha256": DIGEST}}},
        "system-prompt-bad-host": {"selected": ["host-entry", "system-prompt"],
                                   "entries": {"system-prompt": {
                                       "path": SYSP, "host": "Bad Host!", "fragment_sha256": None,
                                       "routing": ROUTING}}},
    }


@pytest.mark.parametrize("name", sorted(_invalid_members()))
def test_invalid_member_is_record_invalid(tmp_path, name):
    root = tmp_path / "p"
    root.mkdir()
    _write_record(root, {**_record_001a(), "carriers": _member()})
    assert load(root).carriers == _member()  # control: a valid member is read …
    _write_record(root, {**_record_001a(), "carriers": _invalid_members()[name]})
    with pytest.raises(RecordError) as err:  # … an invalid one makes the whole record invalid (01i)
        load(root)
    assert err.value.code == "RECORD_INVALID"


def test_valid_member_shapes_load(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    member = {"selected": ["host-entry", "github-instructions", "system-prompt"],
              "entries": {
                  "github-instructions": {"path": INSTR, "fragment_sha256": None, "routing": ROUTING,
                                          "accepted": {"fragment_sha256": DIGEST, "routing": ROUTING,
                                                       "accepted_at": "2026-10-23T08:00:00Z",
                                                       "front_matter_sha256": None}},
                  "system-prompt": {"path": SYSP, "host": HOST, "fragment_sha256": DIGEST,
                                    "routing": ROUTING},
                  "host-entry": {"accepted": {"fragment_sha256": DIGEST, "routing": ROUTING,
                                              "accepted_at": "2026-10-23T08:00:00Z"}}}}
    _write_record(root, {**_record_001a(), "carriers": member})
    assert load(root).carriers == member


# ---------------------------------------------------------------- AC-003B-08c

def test_08c_plain_init_ignores_optional_carriers_and_carries_member_forward(tmp_path):
    box = sandbox(tmp_path)
    proc, out = box.select_all()
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    member = box.record()["carriers"]
    optional = {rel: box.read(rel) for rel in (INSTR, SYSP)}
    box.write(INSTR, box.text(INSTR) + "\nuser tail\n")  # even a changed optional carrier is ignored
    optional[INSTR] = box.read(INSTR)
    proc, out = box.init()
    assert proc.returncode == 0 and out["ok"]
    assert list(out["data"]) == INIT_DATA_KEYS_001A
    assert out["data"]["fragment"] == "current" and out["problems"] == []
    assert INSTR not in proc.stdout and "system-prompt" not in proc.stdout  # neither checked nor reported
    assert {rel: box.read(rel) for rel in optional} == optional
    assert box.record()["carriers"] == member

    newer = toolkit_copy(tmp_path, name="toolkit-newer-skill")
    guard = newer / "x-ipe-secure-code-toolkit-guard" / "SKILL.md"
    guard.write_text(guard.read_text(encoding="utf-8") + "\nNew upstream line.\n", encoding="utf-8")
    before = box.record()
    proc, out = box.init(toolkit=newer)
    assert proc.returncode == 0 and out["ok"]
    after = box.record()
    assert after["files"] != before["files"]  # the record was rewritten …
    assert after["carriers"] == member  # … and the member carried forward unchanged

    proc, status = box.status()
    host = status["data"]["host_integration"]
    for key in ("environment", "host_entry", "fragment", "host_effect", "next_step"):
        assert key in host  # FEATURE-001-A host-section fields keep their names
    assert host["environment"] == "github-copilot" and host["host_entry"] == AGENTS
    assert host["fragment"] == "present" and host["host_effect"] == "not verified"


def test_08c_member_less_project_record_and_output_identical(tmp_path):
    box = sandbox(tmp_path, init=False)
    era = toolkit_copy(tmp_path, era="001A")
    proc, out = box.init(toolkit=era)
    assert proc.returncode == 0 and out["ok"]
    golden = baseline_001a()["sequences"]["github-copilot"][0]
    assert normalize_init(proc.stdout, box.root) == golden["stdout"]
    assert box.text(AGENTS) == GOLDEN_001A_FRAGMENT["github-copilot"] == golden["host"]
    record = box.record()
    assert set(record) == RECORD_001A_KEYS and normalize_record(record) == golden["record"]
    assert box.read(RECORD) == dumps_json(record)

    box2 = sandbox(tmp_path, name="sbx current payload", init=False)
    proc, out = box2.init()
    assert proc.returncode == 0 and out["ok"]
    assert list(out["data"]) == INIT_DATA_KEYS_001A and out["problems"] == []
    assert out["next_steps"] == [step.replace("<ROOT>", str(box2.root))
                                 for step in json.loads(golden["stdout"])["next_steps"]]
    record = box2.record()
    assert set(record) == RECORD_001A_KEYS  # no member on a project without optional carriers
    assert box2.read(RECORD) == dumps_json(record)
    assert f".github/skills/{DEF_REL}" in record["files"]  # the routing definition is installed


def test_08c_absent_payload_definition_uses_001a_minimal_fragment(tmp_path):
    era = toolkit_copy(tmp_path, era="001A")
    assert not (era / DEF_REL).exists()
    for env in ("github-copilot", "claude-code"):
        box = sandbox(tmp_path, env=env, init=False, name=f"sbx {env}")
        proc, out = box.init(toolkit=era)
        assert proc.returncode == 0 and out["ok"] and out["problems"] == []
        host = AGENTS if env == "github-copilot" else "CLAUDE.md"
        assert box.text(host) == GOLDEN_001A_FRAGMENT[env]


def _invalid_definitions() -> dict[str, bytes]:
    obj = packaged_definition()

    def mutate(change) -> bytes:
        data = json.loads(json.dumps(obj))
        change(data)
        return json.dumps(data, indent=2).encode("utf-8")

    def set_statement(value):
        return lambda d: d["sections"][0]["statements"].__setitem__(0, value)

    return {
        "invalid-json": b'{"schema": ',
        "schema-mismatch": mutate(lambda d: d.__setitem__("schema", "other/v9")),
        "marker-token": mutate(set_statement("Use <!-- END ai-secure-code-toolkit --> here.")),
        "absolute-path": mutate(set_statement("Read /etc/passwd first.")),
        "non-utf8": b"\xff\xfe\x00\x01",
        "over-64kib": b"{" + b" " * 70000 + b"}",
    }


@pytest.mark.parametrize("initialized", [False, True], ids=["fresh", "initialized"])
@pytest.mark.parametrize("name", ["absolute-path", "invalid-json", "marker-token", "non-utf8", "over-64kib",
                                  "schema-mismatch"])
def test_08c_invalid_payload_definition_refused_before_writing(tmp_path, name, initialized):
    box = sandbox(tmp_path, init=initialized)
    bad = toolkit_copy(tmp_path, name="toolkit-bad-def")
    (bad / DEF_REL).write_bytes(_invalid_definitions()[name])
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.init(toolkit=bad)
    assert proc.returncode == 1 and not out["ok"]
    assert codes(out) == ["ROUTING_DEFINITION_INVALID"]
    assert any("--toolkit-source" in step for step in out["next_steps"])
    assert box.hashes() == before
    assert writes == []


# ---------------------------------------------------------------- AC-003B-08d

def test_08d_env_mismatch_refused_and_init_switch_drops_member(tmp_path):
    box = sandbox(tmp_path)
    proc, out = box.select_all()
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    x_files = {rel: box.read(rel) for rel in (AGENTS, INSTR, SYSP)}
    before = box.hashes()
    with watch_writes() as writes:
        proc, out = box.carriers(env="claude-code")
    assert proc.returncode == 1 and codes(out) == ["ENV_MISMATCH"]
    assert any("secure-code init" in step and "claude-code" in step for step in out["next_steps"])
    assert box.hashes() == before and writes == []

    proc, out = box.init(env="claude-code")
    assert proc.returncode == 0 and out["ok"]
    record = box.record()
    assert record["environment"] == "claude-code" and "carriers" not in record
    assert {rel: box.read(rel) for rel in x_files} == x_files  # X's carrier files untouched
    proc, status = box.status()
    host = status["data"]["host_integration"]
    assert host["environment"] == "claude-code"
    assert [c["carrier"] for c in host["carriers"]] == ["host-entry"]
    assert INSTR not in json.dumps(host) and SYSP not in json.dumps(host)
    proc, out = box.carriers(env="claude-code")
    assert proc.returncode == 0 and out["ok"]
    assert [c["carrier"] for c in out["data"]["carriers"]] == ["host-entry"]
    assert INSTR not in proc.stdout and SYSP not in proc.stdout


# ---------------------------------------------------------------- AC-003B-08e

def test_08e_references_state_no_forward_compatibility_and_member_omission():
    refs = TOOLKIT_ROOT / FRAMEWORK / "references"
    environments = (refs / "environments.md").read_text(encoding="utf-8")
    contract = (refs / "cli-contract.md").read_text(encoding="utf-8")
    sentence = ("Toolkit versions before the carriers operation cannot read an install record that holds the "
                "`carriers` member and refuse it with `RECORD_INVALID`; there is no forward compatibility.")
    assert sentence in " ".join(environments.split())
    flat_contract = " ".join(contract.split()).lower()
    assert "no forward compatibility" in flat_contract and "record_invalid" in flat_contract
    for text in (" ".join(environments.split()).lower(), flat_contract):
        assert "`carriers` member" in text
        assert "omitted while no optional carrier or customization is recorded" in text
    for wording in ("windows unsupported", "windows is unsupported"):
        assert wording not in environments.lower()
    assert "LOCK_UNAVAILABLE" in environments and "B11" in environments
