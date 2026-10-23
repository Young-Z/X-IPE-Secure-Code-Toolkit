"""FEATURE-003-B unit tests: the single routing definition and its rendering (AC-003B-01c, 02a…02g).

Content checks of rendered carrier text only; real host triggering is HO-003B-01 (manual, human).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re

import pytest
from carhelp import DEF_REL, GOLDEN_001A_BODY, KINDS
from conftest import TOOLKIT_ROOT

from x_ipe_secure_code.environments import PROFILES
from x_ipe_secure_code.guard.mask import mask_text
from x_ipe_secure_code.payload import SKILL_NAMES

ABS_PATH = re.compile(r"(^|[\s`(])(/[^\s/]|~/|[A-Za-z]:\\)")
CASES = [(kind, env) for env in PROFILES for kind in KINDS
         if not (env == "claude-code" and kind == "github-instructions")]
SECTION_IDS = {"copilot", "guard", "deduplication", "results", "roles", "handoff"}


def _routing():
    from x_ipe_secure_code import routing

    return routing


def _packaged_bytes() -> bytes:
    return (TOOLKIT_ROOT / DEF_REL).read_bytes()


def _definition():
    return _routing().parse(_packaged_bytes())


def _identity(defn):
    from x_ipe_secure_code import __version__

    return _routing().RoutingIdentity(__version__, defn.digest)


def _render(kind: str, env: str = "github-copilot", host: str | None = None, defn=None) -> str:
    defn = defn or _definition()
    if kind == "system-prompt" and host is None:
        host = "copilot-cli"
    return _routing().render(defn, _identity(defn), PROFILES[env], kind, host=host)


def _section(text: str, heading: str) -> str:
    lines = text.splitlines()
    start = lines.index(f"### {heading}")
    stop = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("### ")), len(lines))
    return "\n".join(lines[start + 1:stop]).lower()


def _all_rendered() -> list[str]:
    return [_render(kind, env) for kind, env in CASES]


# ---------------------------------------------------------------- design-supporting unit tests

def test_packaged_definition_valid():
    raw = json.loads(_packaged_bytes())
    assert set(raw) == {"schema", "title", "declaration", "skills", "sections", "status_command"}
    assert raw["schema"] == "ai-secure-code-toolkit/routing-definition/v1"
    assert sorted(s["name"] for s in raw["skills"]) == sorted(SKILL_NAMES)
    assert {s["id"] for s in raw["sections"]} == SECTION_IDS
    defn = _definition()
    assert defn.obj == raw
    assert _routing().DEFINITION_REL == DEF_REL


def test_render_deterministic_and_identity_is_canonical_digest():
    raw = json.loads(_packaged_bytes())
    canonical = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    defn = _definition()
    assert defn.digest == hashlib.sha256(canonical).hexdigest()
    reindented = json.dumps(raw, indent=7, ensure_ascii=False).encode("utf-8")
    assert _routing().parse(reindented).digest == defn.digest  # whitespace-only edit: same identity
    for kind, env in CASES:
        first, second = _render(kind, env), _render(kind, env)
        assert first == second and "\r" not in first
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", first) is None  # no time inside fragments


def test_pointer_wording_keeps_001a_edit_target():
    text = _render("host-entry")
    assert "in-flow" in text  # the unchanged FEATURE-001-A test edits this word
    golden = GOLDEN_001A_BODY["github-copilot"].splitlines()
    golden_pointers = [line for line in golden if line.startswith("- `")]
    assert len(golden_pointers) == 3
    for line in golden_pointers:
        assert line in text.splitlines()


def _mutations():
    def statement(value):
        def change(obj):
            obj["sections"][0]["statements"][0] = value
        return change

    def drop_section(obj):
        obj["sections"] = obj["sections"][1:]

    def duplicate_skill(obj):
        obj["skills"] = obj["skills"] + [obj["skills"][0]]

    def unknown_key(obj):
        obj["extra"] = "x"

    def schema(obj):
        obj["schema"] = "ai-secure-code-toolkit/routing-definition/v2"

    def empty_statements(obj):
        obj["sections"][0]["statements"] = []

    def many_statements(obj):
        obj["sections"][0]["statements"] = [f"Statement {i}." for i in range(21)]

    def status_command(obj):
        obj["status_command"] = "uvx --from {skills_dir}/x scripts"

    def empty_pointer(obj):
        obj["skills"][0]["pointer"] = ""

    token = "ghp_" + "Ab1" * 12
    return {
        "marker-open": statement("Use <!-- the Copilot skill."),
        "marker-close": statement("Use --> the Copilot skill."),
        "newline": statement("Use the Copilot skill.\nAlways."),
        "front-matter-token": statement("---"),
        "abs-path": statement("Read /etc/passwd before work."),
        "home-path": statement("Read ~/notes first."),
        "windows-path": statement("Read C:\\Users\\x first."),
        "secret": statement(f"Use token {token} for access."),
        "brace": statement("Use {placeholder} here."),
        "too-long": statement("x" * 501),
        "drop-section": drop_section,
        "duplicate-skill": duplicate_skill,
        "unknown-key": unknown_key,
        "schema": schema,
        "empty-statements": empty_statements,
        "too-many-statements": many_statements,
        "status-command": status_command,
        "empty-pointer": empty_pointer,
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_validation_rejects_marker_newline_abs_path_secret(name):
    obj = json.loads(_packaged_bytes())
    _mutations()[name](obj)
    routing = _routing()
    with pytest.raises(routing.RoutingError) as err:
        routing.parse(json.dumps(obj).encode("utf-8"))
    assert err.value.code == "ROUTING_DEFINITION_INVALID"


@pytest.mark.parametrize("data", [b"\xff\xfe not utf-8", b"{not json", b"[]", b"{}" + b" " * 65536],
                         ids=["non-utf8", "not-json", "not-object", "too-large"])
def test_parse_rejects_unreadable_bytes(data):
    routing = _routing()
    with pytest.raises(routing.RoutingError) as err:
        routing.parse(data)
    assert err.value.code == "ROUTING_DEFINITION_INVALID"


def test_valid_maintainer_edit_accepted_with_new_identity():
    obj = json.loads(_packaged_bytes())
    obj["sections"][0]["statements"][0] += " Keep the change small."
    edited = _routing().parse(json.dumps(obj).encode("utf-8"))
    assert edited.digest != _definition().digest
    assert "Keep the change small." in _render("host-entry", defn=edited)


# ---------------------------------------------------------------- AC-003B-01c

@pytest.mark.parametrize("kind,env", CASES)
def test_01c_rendering_holds_only_routing_pointers_and_status(kind, env):
    defn = _definition()
    obj, profile = defn.obj, PROFILES[env]
    text = _render(kind, env, defn=defn)
    identity = f"ai-secure-code-toolkit {_identity(defn).toolkit_version}, definition sha256:{defn.digest}"
    carrier = {
        "host-entry": f"Integration carrier: host entry (`{profile.host_entry}`).",
        "github-instructions": "Integration carrier: GitHub instructions.",
        "system-prompt": 'Integration carrier: system-prompt fragment for host "copilot-cli".',
    }[kind]
    allowed = {
        f"## {obj['title']}",
        f"{carrier} Routing identity: {identity}.",
        obj["declaration"],
        f"This project uses the AI secure-code toolkit skills in `{profile.skills_dir}/`:",
        "Check status: `" + obj["status_command"].replace("{skills_dir}", profile.skills_dir) + "`",
    }
    allowed |= {f"- `{s['name']}`: {s['pointer']}" for s in obj["skills"]}
    for section in obj["sections"]:
        allowed.add(f"### {section['heading']}")
        allowed |= {f"- {statement}" for statement in section["statements"]}
    lines = [line for line in text.splitlines() if line.strip()]
    assert set(lines) == allowed  # only routing statements, the three pointers and the status command
    assert len(lines) == len(allowed)
    assert lines[0] == f"## {obj['title']}" and lines[1].startswith(carrier)
    for line in lines:
        assert ABS_PATH.search(line) is None, line
    assert mask_text(text)[0] == text  # no credential-like content
    lowered = text.lower()
    for forbidden in ("private key", "public key", "passphrase", "signature:", ".pem", "precheck-key",
                      "trusted", "cwe-", "owasp"):
        assert forbidden not in lowered, forbidden
    # no copied skill procedure or knowledge text (environments.md / cli-contract.md document the CLI)
    sources = [TOOLKIT_ROOT / name / "SKILL.md" for name in SKILL_NAMES]
    for name in SKILL_NAMES:
        sources += [path for path in sorted((TOOLKIT_ROOT / name / "references").glob("*.md"))
                    if path.name not in ("environments.md", "cli-contract.md")]
    corpus = {line.strip() for path in sources for line in path.read_text(encoding="utf-8").splitlines()
              if len(line.strip()) >= 30}
    for line in lines:
        assert line.strip() not in corpus or line.startswith("Check status:"), line


# ---------------------------------------------------------------- AC-003B-02a…02g (every carrier)

def test_02a_copilot_proactive_for_design_impl_fix_refactor_not_questions():
    for text in _all_rendered():
        copilot = _section(text, "Copilot")
        assert "use the copilot skill proactively" in copilot
        for task in ("design", "implementation", "bug fix", "refactor", "changes to an existing design"):
            assert task in copilot, task
        assert "do not use the copilot skill for plain questions or read-only knowledge lookups" in copilot


def test_02b_guard_only_explicit_or_authorized_never_on_completion():
    for text in _all_rendered():
        guard = _section(text, "Guard")
        assert "only on an explicit verification request or an authorized upstream verification step" in guard
        assert "never start guard automatically because an artifact was completed" in guard
        assert "never use guard instead of copilot" in guard


def test_02c_one_declaration_no_restart_reevaluate_reviewer_no_merge():
    for text in _all_rendered():
        lowered = text.lower()
        assert "one integration declaration" in lowered
        assert "at most one copilot or guard flow for the same stage and effective context" in lowered
        dedup = _section(text, "One flow per stage and context")
        assert "loading several toolkit carriers never starts a copilot or guard flow more than once" in dedup
        assert "do not start the flow again for the same stage and the same effective context" in dedup
        assert "evaluate again after a relevant change of input or stage" in dedup
        assert "never skip it permanently" in dedup
        assert "a read-only reviewer never starts the copilot or guard flow" in dedup
        assert "do not merge different framework needs within one task" in dedup


def test_02d_failed_old_reports_not_done_no_invented_policies_no_silent_gates():
    for text in _all_rendered():
        results = _section(text, "Reports and gates")
        assert "a failed or old report never counts as done for the current work" in results
        assert "unavailable skill or invalid output as not completed" in results
        assert "the upstream caller decides under its existing gates" in results
        assert "never make up policies from memory" in results
        assert "continuing the work is not passing" in results
        assert "never bypass mandatory gates silently" in results


def test_02e_minimal_handoff_per_skill_and_naming_is_not_handoff():
    for text in _all_rendered():
        handoff = _section(text, "Minimal handoff")
        lines = handoff.splitlines()
        framework = next(line for line in lines if line.startswith("- framework:"))
        copilot = next(line for line in lines if line.startswith("- copilot:"))
        guard = next(line for line in lines if line.startswith("- guard:"))
        for phrase in ("scenario", "rule clues", "information need", "concrete policies", "sources",
                       "unresolved items"):
            assert phrase in framework, phrase
        for phrase in ("task", "current artifact or change", "constraints", "concrete suggestions",
                       "adoption review", "not adopted or not verifiable"):
            assert phrase in copilot, phrase
        for phrase in ("formed artifact", "explicit targets", "rule clues",
                       "execution authorization and budget",
                       "three-state verdict", "findings", "coverage gaps", "execution state"):
            assert phrase in guard, phrase
        assert "only naming a skill is not a completed handoff" in handoff
        assert "the upstream caller acts on the results" in handoff


def _when_to_use(name: str) -> str:
    text = (TOOLKIT_ROOT / name / "SKILL.md").read_text(encoding="utf-8")
    match = re.search(r"^## When to Use\n(.*?)(?=^## )", text, re.S | re.M)
    assert match, name
    return " ".join(match.group(1).split()).lower()


def _description(name: str) -> str:
    text = (TOOLKIT_ROOT / name / "SKILL.md").read_text(encoding="utf-8")
    return re.search(r"^description: (.+)$", text, re.M).group(1).lower()


def test_02f_triggers_consistent_with_skill_when_to_use():
    copilot_wtu = _when_to_use("x-ipe-secure-code-toolkit-copilot")
    guard_wtu = _when_to_use("x-ipe-secure-code-toolkit-guard")
    framework_wtu = _when_to_use("x-ipe-secure-code-toolkit-framework")
    # Test-side trigger map: (phrase in the skill's own "When to Use", phrase the carrier section must carry)
    copilot_triggers = [
        ("design, implementation, bug fix or refactor", "design, implementation, bug fix and refactor"),
        ("changes to an existing design", "changes to an existing design"),
    ]
    copilot_non_use = [
        ("not for plain questions", "plain questions"),
        ("read-only lookups", "read-only knowledge lookups"),
        ("not for verifying already finished artifacts", "not to verify already finished artifacts"),
    ]
    guard_triggers = [
        ("an explicit verification request", "an explicit verification request"),
        ("an authorized upstream verification step", "an authorized upstream verification step"),
    ]
    guard_non_use = [
        ("not for in-flow suggestions", "never use guard instead of copilot for in-flow suggestions"),
    ]
    assert "use when an agent designs, implements, fixes or refactors code" in _description(
        "x-ipe-secure-code-toolkit-copilot")
    assert "use only on an explicit or authorized security verification request" in _description(
        "x-ipe-secure-code-toolkit-guard")
    assert "not for design/implementation advice" in framework_wtu
    for text in _all_rendered():
        copilot, guard = _section(text, "Copilot"), _section(text, "Guard")
        for skill_phrase, carrier_phrase in copilot_triggers + copilot_non_use:
            assert skill_phrase in copilot_wtu, skill_phrase
            assert carrier_phrase in copilot, carrier_phrase
        for skill_phrase, carrier_phrase in guard_triggers + guard_non_use:
            assert skill_phrase in guard_wtu, skill_phrase
            assert carrier_phrase in guard, carrier_phrase
        for sentence in re.split(r"(?<=[.;])\s+|\n", text.lower()):
            # no carrier sentence routes verification to Copilot or in-flow work to Guard
            if "copilot skill" in sentence and "verif" in sentence:
                assert "not to verify" in sentence, sentence
            if "guard" in sentence and "in-flow" in sentence:
                assert "never" in sentence and "instead of copilot" in sentence, sentence


def test_02g_roles_only_from_verification_and_text_grants_nothing():
    for text in _all_rendered():
        roles = _section(text, "Roles")
        assert "roles come only from actual verification" in roles
        assert "the maintainer by the owner-signed authorization" in roles
        assert "agents by real requests or signed pre-authorization" in roles
        assert "this carrier text grants no role, permission or consent" in roles


def test_definition_unchanged_by_rendering():
    defn = _definition()
    before = copy.deepcopy(defn.obj)
    _render("system-prompt", defn=defn)
    assert defn.obj == before
