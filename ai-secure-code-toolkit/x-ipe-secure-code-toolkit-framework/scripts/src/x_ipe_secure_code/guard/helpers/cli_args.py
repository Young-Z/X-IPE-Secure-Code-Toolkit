"""Argparse registration and dispatch of `secure-code guard helper …` and the helper `tools` commands
(FEATURE-002-F; keeps `cli.py` small). No command promotes, exports, uploads or publishes a helper."""

from __future__ import annotations

import argparse
from typing import Any

TOOLS_COMMANDS = ("register-helper-image", "helper-conformance")


def add_guard_helper(g_commands: Any) -> None:
    helper = g_commands.add_parser("helper", help="Temporary helper scripts for real gaps (FEATURE-002-F)")
    h_commands = helper.add_subparsers(dest="helper_command", required=True)
    submit = h_commands.add_parser("submit", help="Submit a helper script, declaration and samples (agent)")
    submit.add_argument("--run", required=True, metavar="ID")
    submit.add_argument("--request", required=True, metavar="FILE")
    show = h_commands.add_parser("show", help="Show helper states: review, grant, execution (read-only)")
    show.add_argument("--run", required=True, metavar="ID")
    show.add_argument("--helper", metavar="H")
    grant = h_commands.add_parser(
        "grant", help="Grant execution of reviewed helpers (user, interactive only)"
    )
    grant.add_argument("--run", required=True, metavar="ID")
    grant.add_argument("--helper", action="append", default=[], metavar="H")
    run = h_commands.add_parser("run", help="Run a granted helper in a local disposable container (agent)")
    run.add_argument("--run", required=True, metavar="ID")
    run.add_argument("--helper", required=True, metavar="H")
    run.add_argument("--attempt", metavar="A")
    for sub in (submit, show, grant, run):
        sub.add_argument("--project")
        sub.add_argument("--json", action="store_true")


def add_tools_helper(t_commands: Any) -> None:
    register = t_commands.add_parser(
        "register-helper-image", help="Register a locally present helper image by digest (Maintainer)"
    )
    register.add_argument("--image", required=True, metavar="REF")
    conformance = t_commands.add_parser(
        "helper-conformance", help="Run the offline helper runtime conformance suite (Maintainer)"
    )
    for sub in (register, conformance):
        sub.add_argument("--project")
        sub.add_argument("--json", action="store_true")


def run_guard_helper(args: argparse.Namespace) -> Any:
    cmd = args.helper_command
    if cmd == "submit":
        from .submit import submit

        return submit(args.project, args.run, args.request)
    if cmd == "run":
        from .execute import run

        return run(args.project, args.run, args.helper, args.attempt)
    from . import grant

    if cmd == "grant":
        return grant.grant(args.project, args.run, args.helper or None)
    return grant.show(args.project, args.run, args.helper)
