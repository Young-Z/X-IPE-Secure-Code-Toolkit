"""Test-only CLI launcher (never shipped: scripts/tests/ is excluded from the payload).

Options consumed before the real CLI arguments:
  --test-trust-dir DIR   redirect the trust store for this child process only
  --block-network        make any socket creation fail
  --audit-open FILE      append every opened path (audit event "open") to FILE
  --test-canary-write PATH  write-audit harness canary (FEATURE-003-B AC-003B-07c): write PATH through
                         product code, then exit (no CLI arguments)
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--test-canary-write"]:
        from x_ipe_secure_code.atomic import atomic_write_bytes

        atomic_write_bytes(Path(args[1]), b"canary")
        return 0
    trust_dir = None
    audit_file = None
    while args and args[0] in ("--test-trust-dir", "--block-network", "--audit-open"):
        flag = args.pop(0)
        if flag == "--test-trust-dir":
            trust_dir = Path(args.pop(0))
        elif flag == "--audit-open":
            audit_file = Path(args.pop(0))
        else:
            import socket

            def _blocked(*_a, **_k):
                raise OSError("network blocked by test launcher")

            socket.socket = _blocked  # type: ignore[assignment]
            socket.create_connection = _blocked  # type: ignore[assignment]

    if trust_dir is not None:
        from x_ipe_secure_code.auth import trust_store

        trust_store.default_app_dir = lambda: trust_dir  # test-only monkeypatch

    if audit_file is not None:
        log = open(audit_file, "a", encoding="utf-8")  # noqa: SIM115

        def _hook(event: str, event_args: tuple) -> None:
            if event == "open" and event_args and isinstance(event_args[0], (str, Path)):
                log.write(str(event_args[0]) + "\n")
                log.flush()

        sys.addaudithook(_hook)

    from x_ipe_secure_code.cli import main as cli_main

    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
