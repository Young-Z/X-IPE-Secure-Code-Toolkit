"""AC-001D-06c Integration: inspect the shipped Framework's user-facing procedure."""

import re

import pytest
from conftest import TOOLKIT_ROOT


@pytest.mark.parametrize("clause", ["preview_show", "real_request", "confirm", "no_repair", "references"])
def test_framework_exit_instructions(clause):
    """Arrange shipped package; Act read Exiting Knowledge; Assert each safety clause."""
    text = (TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework" / "SKILL.md").read_text()
    assert "## Exiting Knowledge" in text
    section = text.split("## Exiting Knowledge", 1)[1].split("\n## ", 1)[0].lower()
    if clause == "preview_show":
        assert "exit-preview" in section
        assert re.search(r"show.{0,100}impact.{0,100}maintainer", section, re.S)
        assert section.index("exit-preview") < section.index("exit-confirm")
    elif clause == "real_request":
        assert "real" in section and "request" in section and "maintainer" in section
        assert "own initiative" in section
    elif clause == "confirm":
        assert "explicit" in section and "confirm" in section and "impact_digest" in section
        assert re.search(r"never.{0,80}confirm.{0,100}behalf", section, re.S)
    elif clause == "no_repair":
        assert re.search(r"never.{0,60}repair.{0,60}automatic", section, re.S)
        assert "knowledge links" in section
        assert "separate" in section and "explicit" in section
    else:
        assert re.search(r"references.{0,20}do not block", section)
