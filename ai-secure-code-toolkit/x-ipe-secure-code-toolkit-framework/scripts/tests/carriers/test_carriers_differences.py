"""FEATURE-003-B integration tests: Maintainer difference handling and masking (AC-003B-05a…05g)."""

from __future__ import annotations

import re

import pytest
from carhelp import (
    AGENTS,
    END,
    FRONT_MATTER,
    GOLDEN_001A_BODY,
    HOST,
    INSTR,
    KINDS,
    PATHS,
    canaries,
    canary_needles,
    choices,
    codes,
    entry,
    inner,
    problem,
    sandbox,
    sha_text,
    status_entry,
)

from x_ipe_secure_code.environments import PROFILES

ALTERED = '---\napplyTo: "src/**"\n---\n'


def _ok(proc, out):
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return out


def _render(box, kind: str) -> str:
    from x_ipe_secure_code import __version__, routing

    defn = routing.parse(box.definition_path().read_bytes())
    identity = routing.RoutingIdentity(__version__, defn.digest)
    host = HOST if kind == "system-prompt" else None
    return routing.render(defn, identity, PROFILES[box.env], kind, host=host)


def _replace_inner(text: str, body: str) -> str:
    lines = text.splitlines(keepends=True)
    begin = next(i for i, line in enumerate(lines)
                 if line.strip().startswith("<!-- BEGIN ai-secure-code-toolkit"))
    end = next(i for i, line in enumerate(lines) if line.strip() == END)
    return "".join(lines[:begin + 1]) + body + "".join(lines[end:])


def _edit(box, kind: str, new: bytes = b"in-flow and team-specific") -> bytes:
    data = box.read(PATHS[kind])
    edited = data.replace(b"in-flow", new, 1)
    assert edited != data
    box.write(PATHS[kind], edited)
    return edited


def _insert_before_end(text: str, lines: str) -> str:
    at = text.index(END)
    return text[:at] + lines + text[at:]


# ---------------------------------------------------------------- AC-003B-05a

@pytest.mark.parametrize("kind", KINDS)
def test_05a_edited_fragment_kept_with_masked_diff_and_five_choices(tmp_path, kind):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    edited = _edit(box, kind)
    out = _ok(*box.carriers())
    item = entry(out, kind)
    assert item["state"] == "kept-differs" and box.read(PATHS[kind]) == edited
    assert any(PATHS[kind] in p["message"] for p in out["problems"] if p["code"] == "FRAGMENT_EDITED")
    difference = out["data"]["differences"][PATHS[kind]]
    assert difference["content"].startswith("secret-masked")
    assert any(line.startswith("-") and "team-specific" in line for line in difference["diff"])
    assert any(line.startswith("+") and "in-flow security" in line for line in difference["diff"])
    assert difference["choices"] == choices(kind)
    assert f"--regenerate {kind}" in item["next_step"] and f"--accept {kind}" in item["next_step"]
    for other in KINDS:
        if other != kind:
            assert entry(out, other)["state"] == "current"


# ---------------------------------------------------------------- AC-003B-05b

def test_05b_kept_difference_reported_every_run_and_in_status(tmp_path):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    edited = _edit(box, "github-instructions")
    for _ in range(3):
        out = _ok(*box.carriers())
        assert entry(out, "github-instructions")["state"] == "kept-differs"
        assert out["data"]["differences"][INSTR]["diff"]
        status = _ok(*box.status())
        assert status_entry(status, "github-instructions")["fragment"] == "modified"
        assert status["data"]["host_integration"]["differences"][INSTR]["diff"]
    assert box.read(INSTR) == edited  # never silently overwritten, merged or dropped


# ---------------------------------------------------------------- AC-003B-05c

@pytest.mark.parametrize("front", ["unchanged", "missing", "altered", "moved"])
def test_05c_regenerate_replaces_only_that_carrier_and_restores_front_matter(tmp_path, front):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    agents = _edit(box, "host-entry")
    body_edited = box.text(INSTR).replace("in-flow", "in-flow (ours)", 1)
    rest = body_edited[len(FRONT_MATTER):] + "tail ü\n"
    text = {"unchanged": FRONT_MATTER + rest, "missing": rest, "altered": ALTERED + rest,
            "moved": "User intro ü\n\n" + FRONT_MATTER + rest}[front]
    box.write(INSTR, text)
    out = _ok(*box.carriers("--regenerate", "github-instructions"))
    assert entry(out, "github-instructions")["state"] == "replaced"
    assert entry(out, "host-entry")["state"] == "kept-differs" and box.read(AGENTS) == agents
    difference = out["data"]["differences"][INSTR]
    assert difference["replaced"] is True and difference["content"].startswith("secret-masked")
    assert any(line.startswith("-") and "(ours)" in line for line in difference["diff"])
    outside = {"unchanged": text, "missing": FRONT_MATTER + text,
               "altered": FRONT_MATTER + text[len(ALTERED):],
               "moved": FRONT_MATTER + text.replace(FRONT_MATTER, "", 1)}[front]
    result = box.text(INSTR)
    assert result == _replace_inner(outside, _render(box, "github-instructions"))
    assert result.startswith(FRONT_MATTER) and result.count(FRONT_MATTER) == 1
    assert "(ours)" not in result and "tail ü" in result


# ---------------------------------------------------------------- AC-003B-05d

@pytest.mark.parametrize("kind", KINDS)
def test_05d_accept_records_customization_never_synced_and_reopens_on_change(tmp_path, kind):
    from x_ipe_secure_code import __version__

    box = sandbox(tmp_path)
    _ok(*box.select_all())
    _edit(box, kind)
    assert entry(_ok(*box.carriers()), kind)["state"] == "kept-differs"
    out = _ok(*box.carriers("--accept", kind))
    item = entry(out, kind)
    assert item["state"] == "customized"
    assert "not synced with the routing definition" in item["next_step"]
    digest = re.search(r"definition sha256:([0-9a-f]{64})", out["data"]["routing_identity"]).group(1)
    accepted = box.record()["carriers"]["entries"][kind]["accepted"]
    assert accepted["fragment_sha256"] == sha_text(inner(box.text(PATHS[kind])))
    assert accepted["routing"] == {"toolkit_version": __version__, "definition_sha256": digest}
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", accepted["accepted_at"])
    if kind == "github-instructions":
        assert accepted["front_matter_sha256"] is not None
    status = status_entry(_ok(*box.status()), kind)
    assert status["fragment"] == "customized" and "not synced" in status["next_step"]
    # later results show customized, never current
    assert entry(_ok(*box.carriers()), kind)["state"] == "customized"

    _edit(box, kind, b"in-flow again")  # the accepted fragment changes → a difference again
    assert entry(_ok(*box.carriers()), kind)["state"] == "kept-differs"
    assert entry(_ok(*box.carriers("--accept", kind)), kind)["state"] == "customized"
    box.edit_definition()  # the routing definition changes → a difference again
    out = _ok(*box.carriers())
    assert entry(out, kind)["state"] == "kept-differs" and "FRAGMENT_EDITED" in codes(out)


# ---------------------------------------------------------------- AC-003B-05e

@pytest.mark.parametrize("case", ["entry-digest-missing", "foreign-host-digest", "lost-entry"])
def test_05e_missing_or_foreign_digest_never_overwrites(tmp_path, case):
    box = sandbox(tmp_path)
    _ok(*box.select_all())
    record = box.record()
    kind = "host-entry" if case == "foreign-host-digest" else "github-instructions"
    if case == "entry-digest-missing":
        record["carriers"]["entries"]["github-instructions"]["fragment_sha256"] = None
    elif case == "foreign-host-digest":
        record["fragment_sha256"] = sha_text(GOLDEN_001A_BODY["claude-code"])  # from another environment
    else:
        del record["carriers"]["entries"]["github-instructions"]
    box.save_record(record)
    box.edit_definition()  # the fragment now differs from the toolkit rendering
    before = box.read(PATHS[kind])
    out = _ok(*box.carriers())
    assert entry(out, kind)["state"] == "kept-differs" and "FRAGMENT_EDITED" in codes(out)
    assert box.read(PATHS[kind]) == before
    assert out["data"]["differences"][PATHS[kind]]["choices"] == choices(kind)


# ---------------------------------------------------------------- AC-003B-05f / 05g

def _canary_front_matter() -> str:
    c = canaries()
    return ('---\napplyTo: "**"\n'
            f'api_key: "{c["credential.token"]}"\n'
            f'aws: {c["credential.cloud_key"]}\n'
            f'{c["credential.assignment"]}\n'
            f'{c["credential.private_key"]}\n'
            '---\n')


def _seed_canaries(box) -> None:
    _ok(*box.carriers("--select", "github-instructions"))
    lines = "".join(value + "\n" for value in canaries().values())
    box.write(AGENTS, _insert_before_end(box.text(AGENTS), lines))
    instr = box.text(INSTR)
    box.write(INSTR, _canary_front_matter() + instr[len(FRONT_MATTER):])


def _assert_masked(proc, *, labelled: bool = True) -> None:
    for needle in canary_needles():
        assert needle not in proc.stdout and needle not in proc.stderr
    for kind in canaries():
        assert f"[masked:{kind}]" in proc.stdout, kind
    if labelled:
        assert "secret-masked" in proc.stdout


@pytest.mark.parametrize("mode", ["json", "text"])
def test_05f_canaries_masked_in_text_and_json_with_markers(tmp_path, mode):
    box = sandbox(tmp_path)
    _seed_canaries(box)
    json_out = mode == "json"
    proc, out = box.carriers(json_out=json_out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    _assert_masked(proc)
    if json_out:
        assert entry(out, "host-entry")["state"] == "kept-differs"
        assert entry(out, "github-instructions")["front_matter"] == "drift: altered"
        assert problem(out, "FRONT_MATTER_DRIFT")
        assert out["data"]["differences"][INSTR]["front_matter_diff"]
    proc, _ = box.status(json_out=json_out)
    assert proc.returncode == 0
    _assert_masked(proc)


@pytest.mark.parametrize("mode", ["json", "text"])
def test_05g_regenerate_shows_only_masked_replaced_content(tmp_path, mode):
    box = sandbox(tmp_path)
    _seed_canaries(box)
    proc, out = box.carriers("--regenerate", "host-entry", "--regenerate", "github-instructions",
                             json_out=mode == "json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    _assert_masked(proc)
    if mode == "json":
        for rel in (AGENTS, INSTR):
            assert out["data"]["differences"][rel]["replaced"] is True
    assert inner(box.text(AGENTS)) == _render(box, "host-entry")
    assert box.text(INSTR).startswith(FRONT_MATTER)
    for needle in canary_needles():
        assert needle not in box.text(INSTR)
