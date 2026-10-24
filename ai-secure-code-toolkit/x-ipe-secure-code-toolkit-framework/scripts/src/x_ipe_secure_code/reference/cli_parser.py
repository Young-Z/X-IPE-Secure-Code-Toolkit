"""`secure-code knowledge reference …` parser (FEATURE-001-E).

The option list is fixed: no option selects a resolver, opener, clock, fixture mode or address allowlist
(AC-001E-08i); argparse refuses unknown options.
"""

from __future__ import annotations

import argparse
from typing import Any

LIMIT_OPTIONS = (
    ("--max-bytes", "max_bytes", int, "Raw body limit in bytes (at most 2 MiB)"),
    ("--max-text", "max_text", int, "Extracted text limit in bytes (at most 256 KiB)"),
    ("--timeout", "timeout", float, "Absolute deadline in seconds (at most 30)"),
    ("--max-fetches", "max_fetches", int, "Reference fetches per verification (at most 20)"),
    ("--cache-capacity", "cache_capacity", int, "Cache capacity in bytes (1 MiB to 64 MiB)"),
)


def _limits(parser: argparse.ArgumentParser, *, fetch: bool) -> None:
    for flag, dest, kind, text in LIMIT_OPTIONS:
        if fetch or dest == "cache_capacity":
            parser.add_argument(flag, dest=dest, type=kind, default=None, help=text)


def add(k_commands: Any) -> None:
    """Register `knowledge reference` and its subcommands on the `knowledge` subparsers."""
    ref = k_commands.add_parser(
        "reference",
        help="Reference knowledge: registered external sources, private "
        "7-day cache, fetching inside a Guard verification",
    )
    r_commands = ref.add_subparsers(dest="reference_command", required=True)
    subs = []
    register = r_commands.add_parser(
        "register", help="Register sources and rules from a batch file (Maintainer)"
    )
    register.add_argument("--batch", required=True, metavar="FILE")
    subs.append(register)
    update = r_commands.add_parser("update", help="Update one source or rule (Maintainer, current digest)")
    target = update.add_mutually_exclusive_group(required=True)
    target.add_argument("--source", metavar="NAMESPACE/VERSION")
    target.add_argument("--rule", metavar="NAMESPACE/VERSION/ID")
    update.add_argument("--registration-digest", required=True, metavar="DIGEST")
    update.add_argument("--domain", action="append", dest="domains", metavar="DOMAIN")
    update.add_argument("--port", metavar="N")
    update.add_argument("--path-prefix", metavar="PATH")
    update.add_argument("--scheme", choices=("http", "https"))
    update.add_argument("--display-name", metavar="TEXT")
    update.add_argument("--title", metavar="TEXT")
    update.add_argument("--entry-url", metavar="URL")
    update.add_argument("--applicability", action="append", metavar="LANGUAGE")
    subs.append(update)
    preview = r_commands.add_parser(
        "remove-preview", help="Impact of removing a rule (Maintainer, read-only)"
    )
    preview.add_argument("--rule", required=True, metavar="NAMESPACE/VERSION/ID")
    preview.add_argument("--reason", required=True)
    subs.append(preview)
    confirm = r_commands.add_parser("remove-confirm", help="Remove a rule after its preview (Maintainer)")
    confirm.add_argument("--rule", required=True, metavar="NAMESPACE/VERSION/ID")
    confirm.add_argument("--reason", required=True)
    confirm.add_argument("--impact-digest", required=True, metavar="DIGEST")
    confirm.add_argument("--registration-digest", required=True, metavar="DIGEST")
    subs.append(confirm)
    source = r_commands.add_parser("remove-source", help="Remove a source without rules (Maintainer)")
    source.add_argument("--source", required=True, metavar="NAMESPACE/VERSION")
    source.add_argument("--registration-digest", required=True, metavar="DIGEST")
    subs.append(source)
    subs.append(
        r_commands.add_parser("list", help="Registered sources and rules with cache state (read-only)")
    )
    show = r_commands.add_parser("show", help="One registration with digests and cache state (read-only)")
    which = show.add_mutually_exclusive_group(required=True)
    which.add_argument("--rule", metavar="NAMESPACE/VERSION/ID")
    which.add_argument("--source", metavar="NAMESPACE/VERSION")
    subs.append(show)
    fetch = r_commands.add_parser("fetch", help="Fetch one Reference rule inside an open Guard verification")
    fetch.add_argument("--run", metavar="VERIFICATION_ID")
    fetch.add_argument("--rule", required=True, metavar="NAMESPACE/VERSION/ID")
    fetch.add_argument("--refresh", action="store_true")
    _limits(fetch, fetch=True)
    subs.append(fetch)
    explore = r_commands.add_parser(
        "explore",
        help="Read one registered-domain page as untrusted text and list its links (never followed)",
    )
    explore.add_argument("--run", metavar="VERIFICATION_ID")
    explore.add_argument("--source", required=True, metavar="NAMESPACE/VERSION")
    explore.add_argument("--url", required=True)
    explore.add_argument("--refresh", action="store_true")
    _limits(explore, fetch=True)
    subs.append(explore)
    clean = r_commands.add_parser("cache-clean", help="Remove expired, invalid and orphaned cache entries")
    _limits(clean, fetch=False)
    subs.append(clean)
    for sub in subs:
        sub.add_argument("--project")
        sub.add_argument("--json", action="store_true")


def changes(args: argparse.Namespace) -> dict[str, Any]:
    """Only the fields the Maintainer named on the command line."""
    names = (
        "domains",
        "port",
        "path_prefix",
        "scheme",
        "display_name",
        "title",
        "entry_url",
        "applicability",
    )
    return {name: getattr(args, name) for name in names if getattr(args, name, None) is not None}


def limits(args: argparse.Namespace) -> dict[str, Any]:
    return {
        dest: getattr(args, dest) for _, dest, _, _ in LIMIT_OPTIONS if getattr(args, dest, None) is not None
    }
