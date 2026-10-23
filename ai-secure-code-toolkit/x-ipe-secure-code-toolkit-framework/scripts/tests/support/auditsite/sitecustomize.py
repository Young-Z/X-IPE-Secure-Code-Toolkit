"""Test-only: install the write-audit hook in every child Python process of the test suite.

Loaded through PYTHONPATH (set by tests/conftest.py); does nothing unless the suite enabled auditing.
"""

import os
import sys

if os.environ.get("SECURE_CODE_TEST_WRITE_AUDIT"):
    _support = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(_support)
    try:
        import write_audit

        write_audit.install_child()
    finally:
        sys.path.remove(_support)
