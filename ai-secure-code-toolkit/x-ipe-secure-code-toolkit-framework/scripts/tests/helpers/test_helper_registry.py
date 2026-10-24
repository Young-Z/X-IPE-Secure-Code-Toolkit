"""FEATURE-002-F image registration and record integrity (AC-002F-11a, 11d, 11e, 08f; DEC-5, DEC-6)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json

import pytest
from conftest import tree_hashes
from helperhelp import (  # noqa: F401 - fixture reuse
    IMAGE_ENV,
    IMAGE_ID,
    env,
    fake,
    henv,
    mod,
    seed_registry,
)

from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust

FORBIDDEN = {
    "pull",
    "build",
    "load",
    "import",
    "login",
    "push",
    "run",
    "system",
    "machine",
    "network",
    "plugin",
}


def register(env, ref=IMAGE_ID, paths=None):
    return mod("registry").register_image(str(env["project"]), ref, trust_paths=paths or env["paths"])


def test_11a_register_success_records_digest_and_version(henv, fake):
    out = register(henv, "python:3.12-slim")
    assert out.ok, out.to_text()
    assert out.data["image"] == IMAGE_ID and out.data["cpython"] == "3.12.4"
    assert out.data["interpreter"] == "/usr/local/bin/python3"
    assert sorted(out.data["env_keys"]) == ["LANG", "PATH", "PYTHON_VERSION"]
    doc = mod("registry").image(henv["project"])
    assert doc["image"] == IMAGE_ID and doc["cpython"] == "3.12.4" and doc["env"] == IMAGE_ENV
    creates = fake.creates("version")
    assert len(creates) == 1 and "--pull=never" in creates[0]
    assert "target=/helper,readonly" in " ".join(creates[0]) and "/input" not in " ".join(creates[0])
    assert not {s.split()[0] for s in fake.subcommands()} & FORBIDDEN


def test_11a_register_rules(henv, fake, tmp_path):
    stranger = resolve_trust(tmp_path / "nobody")
    refused = register(henv, IMAGE_ID, stranger)
    assert refused.problems[0].code == "NOT_AUTHORIZED" and fake.log() == []
    missing = register(henv, "sha256:" + "9" * 64)
    assert missing.problems[0].code == "HELPER_IMAGE_UNAVAILABLE"
    assert "never pulls or builds" in missing.problems[0].message
    for version, impl in (([3, 9, 18], "cpython"), ([3, 14, 0], "cpython"), ([3, 12, 4], "pypy")):
        fake.set(
            runs={
                "version": {
                    "mode": "stdout",
                    "stdout": json.dumps(
                        {"version": version, "implementation": impl, "executable": "/usr/local/bin/python3"}
                    ),
                }
            }
        )
        out = register(henv)
        assert out.problems[0].code == "HELPER_IMAGE_UNSUPPORTED", (version, impl)
    fake.set(runs={})
    ctl = fake.control
    ctl["images"][IMAGE_ID]["Config"]["Volumes"] = {"/data": {}}
    fake.set(images=ctl["images"])
    out = register(henv)
    assert out.problems[0].code == "HELPER_IMAGE_UNSUPPORTED" and "VOLUME" in out.problems[0].message
    assert mod("registry").image(henv["project"]) is None
    assert not {s.split()[0] for s in fake.subcommands()} & FORBIDDEN


def test_dec5_env_keys_shown_credential_refused(henv, fake):
    ctl = fake.control
    secret = "ghp_" + "d" * 36
    ctl["images"][IMAGE_ID]["Config"]["Env"] = [*IMAGE_ENV, f"API_TOKEN={secret}"]
    fake.set(images=ctl["images"])
    out = register(henv)
    assert out.problems[0].code == "HELPER_IMAGE_UNSUPPORTED"
    assert "API_TOKEN" in out.problems[0].message and secret not in out.to_json()
    assert mod("registry").image(henv["project"]) is None


FP1 = "7169605F62C751356D054A26A821E680E5FA6305"
FP2 = "a035c8c19219ba821ecea86b64e628f8d684696d"
FINGERPRINT_LABEL = "public key fingerprint (not a secret)"


def _with_env(fake, *extra):
    ctl = fake.control
    ctl["images"][IMAGE_ID]["Config"]["Env"] = [*IMAGE_ENV, *extra]
    fake.set(images=ctl["images"])


@pytest.mark.parametrize("entry", [f"GPG_KEY={FP1}", f"GPG_KEYS={FP1} {FP2}", f"GPG_KEYS={FP2}"])
def test_dao005_public_fingerprint_registers_labelled(henv, fake, entry):
    """DAO-005 (3): GPG_KEY/GPG_KEYS holding only whole 40-hex fingerprints are not refused (DEC-I4)."""
    _with_env(fake, entry)
    out = register(henv)
    assert out.ok, out.to_text()
    key = entry.split("=", 1)[0]
    assert entry in out.data["env"] and key in out.data["env_keys"]
    assert out.data["env_labels"] == {key: FINGERPRINT_LABEL}
    assert FINGERPRINT_LABEL in out.to_text()
    assert entry in mod("registry").image(henv["project"])["env"]


@pytest.mark.parametrize(
    "entry",
    [
        f"PGP_KEY={FP1}",
        f"GPG_KEY_ID={FP1}",
        f"MY_GPG_KEY={FP1}",
        f"gpg_key={FP1}",
        f"API_KEY={FP1}",
        f"GPG_KEY={FP1[:39]}",
        f"GPG_KEY={FP1}0",
        f"GPG_KEY={FP1[:-1]}G",
        f"GPG_KEY=0x{FP1}",
        f"GPG_KEY={FP1}x",
        f"GPG_KEY={FP1} ",
        f"GPG_KEY= {FP1}",
        f"GPG_KEY={FP1}\n",
        f"GPG_KEYS={FP1}  {FP2}",
        f"GPG_KEYS={FP1},{FP2}",
        f"GPG_KEYS={FP1} {FP2[:39]}",
        "GPG_KEY=ghp_" + "d" * 36,
    ],
)
def test_dao005_fingerprint_near_misses_still_refused(henv, fake, entry):
    _with_env(fake, entry)
    out = register(henv)
    assert not out.ok and out.problems[0].code == "HELPER_IMAGE_UNSUPPORTED"
    assert entry.split("=", 1)[0] in out.problems[0].message
    assert mod("registry").image(henv["project"]) is None


def test_dao005_exemption_does_not_hide_other_credentials(henv, fake):
    _with_env(fake, f"GPG_KEY={FP1}", "API_TOKEN=ghp_" + "d" * 36)
    out = register(henv)
    assert not out.ok and out.problems[0].code == "HELPER_IMAGE_UNSUPPORTED"
    assert "API_TOKEN" in out.problems[0].message and "GPG_KEY" not in out.problems[0].message


def test_dao005_mask_text_untouched():
    from x_ipe_secure_code.guard.mask import mask_text

    assert mask_text(f"GPG_KEY={FP1}")[1]


def test_b1_registration_semantic_verifier_without_record(henv, fake):
    fake.set(deviations={"version": {"HostConfig.NetworkMode": "bridge"}})
    out = register(henv)
    assert out.problems[0].code == "HELPER_CONFIG_MISMATCH" and "network" in out.problems[0].message
    assert not any(r[0] == "start" for r in fake.log())
    assert any(r[:2] == ["rm", "-f"] for r in fake.log())


def test_08f_own_state_002b_002d_unchanged(henv, fake):
    tools = henv["project"] / ".x-ipe/private/secure-code/tools"
    tools.mkdir(parents=True, exist_ok=True)
    (tools / "registry.json").write_text('{"tools": {}}')
    before = tree_hashes(tools)
    assert register(henv).ok
    assert tree_hashes(tools) == before
    helpers = henv["project"] / ".x-ipe/private/secure-code/helpers"
    assert sorted(p.name for p in helpers.iterdir()) == ["image.json", "integrity.key"]
    assert (helpers / "integrity.key").stat().st_mode & 0o777 == 0o600


def test_11e_edited_record_absent(henv, fake):
    seeded = seed_registry(henv)
    registry = mod("registry")
    root = henv["project"]
    assert registry.image(root) is not None
    assert registry.conformance(root, seeded["identity"], IMAGE_ID) is not None
    image_file = root / ".x-ipe/private/secure-code/helpers/image.json"
    doc = json.loads(image_file.read_text())
    doc["cpython"] = "3.12.5"
    image_file.write_text(json.dumps(doc))
    assert registry.image(root) is None
    conf = next((root / ".x-ipe/private/secure-code/helpers/conformance").iterdir())
    doc = json.loads(conf.read_text())
    doc["probes"][0]["detail"] = "edited"
    conf.write_text(json.dumps(doc))
    assert registry.conformance(root, seeded["identity"], IMAGE_ID) is None
    seed_registry(henv)
    (root / ".x-ipe/private/secure-code/helpers/integrity.key").unlink()
    assert registry.image(root) is None
    assert registry.conformance(root, seeded["identity"], IMAGE_ID) is None
