"""Every source module stays below the 800-line maintainability threshold (FEATURE-002-C design)."""

from __future__ import annotations

from pathlib import Path

import x_ipe_secure_code

LIMIT = 800


def test_every_module_below_limit():
    root = Path(x_ipe_secure_code.__file__).parent
    sizes = {
        p.relative_to(root).as_posix(): len(p.read_text(encoding="utf-8").splitlines())
        for p in root.rglob("*.py")
    }
    assert {k: v for k, v in sizes.items() if v >= LIMIT} == {}
