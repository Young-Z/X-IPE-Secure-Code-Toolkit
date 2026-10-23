"""Skill skeleton content checks (AC-001A-04d) and standalone independence (AC-001A-04e)."""

from __future__ import annotations

import re

from conftest import SRC, TOOLKIT_ROOT

from x_ipe_secure_code.payload import SKILL_NAMES


def _skill(name: str) -> str:
    return (TOOLKIT_ROOT / name / "SKILL.md").read_text(encoding="utf-8")


def test_each_skill_has_frontmatter_and_boundary_sections():
    for name in SKILL_NAMES:
        text = _skill(name)
        assert re.match(rf"---\nname: {name}\ndescription: .+\n---\n", text), name
        for heading in ("## Responsibilities", "## Non-Responsibilities", "## When to Use",
                        "## How to Call"):
            assert heading in text, (name, heading)


def test_boundaries_match_o01_to_o06():
    framework, copilot, guard = (_skill(n).lower() for n in SKILL_NAMES)
    assert "adapter" in framework and "does not decide scan strategy" in framework  # O-01, O-06
    assert "design, implementation, bug fix and refactor" in copilot  # O-02
    assert "not a second business writer" in copilot  # O-04
    assert "does not fix" in guard  # O-03
    for text in (framework, copilot, guard):
        assert "reviewers have no extra authority" in text  # O-05


def test_no_xipe_infrastructure_referenced_by_code():
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "x-ipe-docs/planning" not in text and ".x-ipe.yaml" not in text, path
