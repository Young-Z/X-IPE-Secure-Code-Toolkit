"""Terminal interaction for owner commands. Passphrases come only from getpass."""

from __future__ import annotations

import getpass
import sys
from typing import Protocol


class Interaction(Protocol):
    def is_interactive(self) -> bool: ...

    def prompt_secret(self, prompt: str) -> str | None: ...

    def prompt_text(self, prompt: str) -> str | None: ...


class TerminalInteraction:
    """Interactive means both stdin and stdout are terminals.

    A pseudo-terminal also counts as interactive; the passphrase remains the real gate.
    """

    def is_interactive(self) -> bool:
        try:
            return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
        except (ValueError, AttributeError):
            return False

    def prompt_secret(self, prompt: str) -> str | None:
        try:
            return getpass.getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            return None

    def prompt_text(self, prompt: str) -> str | None:
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            return None
