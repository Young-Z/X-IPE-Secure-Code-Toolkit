"""Scanner Adapters of this toolkit version (re-export of `adapters`).

Strix is not provided yet.
"""

from __future__ import annotations

from .adapters import ADAPTERS

NOT_PROVIDED = "adapter not provided by this toolkit version"
NOT_PROVIDED_NEXT = ("Use a toolkit version that provides this Adapter; "
                     "no scanner is checked or installed automatically")

__all__ = ["ADAPTERS", "NOT_PROVIDED", "NOT_PROVIDED_NEXT"]
