"""Payload location, including the uvx/uv-tool case (code runs from uv's cache)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import TOOLKIT_ROOT

from x_ipe_secure_code import payload


class _FakeDist:
    def __init__(self, text):
        self._text = text

    def read_text(self, name):
        return self._text if name == "direct_url.json" else None


def test_source_tree_layout_found():
    assert payload.framework_dir() == TOOLKIT_ROOT / payload.SKILL_NAMES[0]


def test_installed_origin_used_when_running_from_cache(monkeypatch, tmp_path):
    scripts = TOOLKIT_ROOT / payload.SKILL_NAMES[0] / "scripts"
    fake_file = tmp_path / "cache" / "lib" / "x_ipe_secure_code" / "payload.py"
    fake_file.parent.mkdir(parents=True)
    monkeypatch.setattr(payload, "__file__", str(fake_file))
    monkeypatch.setattr(payload.importlib.metadata, "distribution",
                        lambda name: _FakeDist(json.dumps({"url": scripts.as_uri(), "dir_info": {}})))
    assert payload.framework_dir() == TOOLKIT_ROOT / payload.SKILL_NAMES[0]
    assert payload.locate() == TOOLKIT_ROOT


@pytest.mark.parametrize("text", [None, "not json", json.dumps({"url": "https://example.com/x"})])
def test_installed_origin_ignores_unusable_metadata(monkeypatch, text):
    monkeypatch.setattr(payload.importlib.metadata, "distribution", lambda name: _FakeDist(text))
    assert payload._installed_origin() is None


def test_payload_excludes_dev_artifacts():
    names = payload.files(TOOLKIT_ROOT)
    assert not any("/scripts/tests/" in key or "/.venv/" in key or key.endswith(".pyc")
                   or "/.coverage" in key for key in names)
    assert f"{payload.SKILL_NAMES[0]}/scripts/pyproject.toml" in names


def test_symlink_in_payload_rejected(tmp_path):
    source = tmp_path / "toolkit"
    for name in payload.SKILL_NAMES:
        (source / name).mkdir(parents=True)
        (source / name / "SKILL.md").write_text("x")
    (source / payload.SKILL_NAMES[1] / "link").symlink_to(tmp_path)
    with pytest.raises(payload.PayloadError) as err:
        payload.files(payload.locate(source))
    assert err.value.code == "PAYLOAD_SYMLINK"


@pytest.mark.skipif(shutil.which("uvx") is None, reason="uvx not available")
def test_uvx_end_to_end_init_and_status(tmp_path):
    """The documented invocation: uvx --from <framework>/scripts secure-code …"""
    project = tmp_path / "e2e project"
    project.mkdir()
    scripts = TOOLKIT_ROOT / payload.SKILL_NAMES[0] / "scripts"

    def uvx(*args):
        return subprocess.run(["uvx", "--from", str(scripts), "secure-code", *args],
                              capture_output=True, text=True, timeout=300)

    init = uvx("init", "--project", str(project), "--env", "github-copilot", "--json")
    assert init.returncode == 0, init.stdout + init.stderr
    assert (project / ".github/skills" / payload.SKILL_NAMES[2] / "SKILL.md").is_file()
    installed_scripts = project / ".github/skills" / payload.SKILL_NAMES[0] / "scripts"
    status = subprocess.run(["uvx", "--from", str(installed_scripts), "secure-code", "status",
                             "--project", str(project), "--json"],
                            capture_output=True, text=True, timeout=300)
    assert status.returncode == 0, status.stderr
    data = json.loads(status.stdout)["data"]
    assert data["install"]["state"] == "installed"
    assert not list(Path(project).rglob(".venv"))
