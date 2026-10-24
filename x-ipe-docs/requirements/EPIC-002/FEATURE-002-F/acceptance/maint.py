"""Maintainer seam for the FEATURE-002-F acceptance on the macOS host (TASK-111).

The CLI resolves the trust root from the OS account database only (`auth/trust_store.py`), so a host CLI run
cannot use a disposable trust store, and `auth init` is never run against the macOS account's trust root.
For the two Maintainer commands that need the real local container runtime (which exists only on the host),
this seam calls the SAME public service functions the CLI dispatches to (`cli.py` → `tools_service.
register_helper_image` / `tools_service.helper_conformance`) with an explicit disposable `TrustPaths` under the
session evidence folder — the toolkit's documented library/test-environment form (`trust_store.resolve(app_dir)`:
"Library callers may pass an explicit directory; the CLI never does"), as used by the delivered opt-in
real-runtime tests. Nothing else is done through the library; every agent/user step is CLI.

    uvx --from <frozen>/scripts python maint.py init        <trust-dir>
    uvx --from <frozen>/scripts python maint.py register    <trust-dir> <project> <image-ref>
    uvx --from <frozen>/scripts python maint.py conformance <trust-dir> <project>
    uvx --from <frozen>/scripts python maint.py status      <trust-dir>

Prints the command Result as JSON (the CLI's `--json` form) on stdout; exit 0 when ok, 1 otherwise.
"""

from __future__ import annotations

import sys

from x_ipe_secure_code import tools_service
from x_ipe_secure_code.auth.service import auth_status, initialize_authorization
from x_ipe_secure_code.auth.trust_store import resolve

PASSPHRASE = "acceptance passphrase 42"  # disposable trust store only


class Scripted:
    """Interaction answering the passphrase prompts (disposable trust store only)."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)

    def is_interactive(self) -> bool:
        return True

    def prompt_secret(self, prompt: str) -> str | None:
        return self.answers.pop(0) if self.answers else None

    def prompt_text(self, prompt: str) -> str | None:
        return self.prompt_secret(prompt)


def main(argv: list[str]) -> int:
    op, trust = argv[0], resolve(argv[1])
    if op == "init":
        out = initialize_authorization(paths=trust, interaction=Scripted([PASSPHRASE, PASSPHRASE]))
    elif op == "register":
        out = tools_service.register_helper_image(argv[2], argv[3], trust_paths=trust)
    elif op == "conformance":
        out = tools_service.helper_conformance(argv[2], trust_paths=trust)
    elif op == "status":
        out = auth_status(paths=trust)
    else:
        print(f"unknown op {op}", file=sys.stderr)
        return 2
    print(out.to_json())
    return 0 if out.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
