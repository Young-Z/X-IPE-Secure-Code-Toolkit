"""`secure-code` command-line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .auth.service import auth_status, initialize_authorization, revoke_authorization
from .project_init import initialize_project
from .results import Result
from .status import collect


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secure-code",
                                     description="AI secure-code toolkit (Framework)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Initialize a project for an agent environment")
    init.add_argument("--project", help="Explicit project root (required)")
    init.add_argument("--env", help="Agent environment: github-copilot | claude-code (required)")
    init.add_argument("--replace", action="append", default=[], metavar="PATH",
                      help="Project-relative file whose local edits should be replaced")
    init.add_argument("--toolkit-source", metavar="DIR",
                      help="Folder containing the three toolkit skills (default: siblings)")
    init.add_argument("--json", action="store_true", help="Print the structured result")

    carriers = commands.add_parser("carriers", help="Generate, check and decide host integration carriers")
    carriers.add_argument("--project", help="Explicit project root (required)")
    carriers.add_argument("--env", help="Agent environment: github-copilot | claude-code (required)")
    carriers.add_argument("--select", action="append", default=[], metavar="KIND",
                          help="Select carriers (host-entry | github-instructions | system-prompt); replaces "
                               "the stored selection; host-entry is always included")
    carriers.add_argument("--deselect", action="append", default=[], metavar="KIND",
                          help="Stop managing a carrier (its file is left in place)")
    carriers.add_argument("--system-prompt-host", metavar="NAME",
                          help="Host named for the system-prompt fragment")
    carriers.add_argument("--regenerate", action="append", default=[], metavar="KIND",
                          help="Replace that carrier's managed boundaries with the toolkit rendering")
    carriers.add_argument("--accept", action="append", default=[], metavar="KIND",
                          help="Record that carrier's current managed content as an accepted customization")
    carriers.add_argument("--json", action="store_true", help="Print the structured result")

    status = commands.add_parser("status", help="Read-only status of a project")
    status.add_argument("--project", help="Explicit project root (required)")
    status.add_argument("--json", action="store_true")

    knowledge = commands.add_parser("knowledge", help="Local security knowledge (Maintainer writes)")
    k_commands = knowledge.add_subparsers(dest="knowledge_command", required=True)
    k_check = k_commands.add_parser("check", help="Which items/documents are already stored (read-only)")
    k_check.add_argument("--project")
    k_check.add_argument("--input", required=True, metavar="FILE")
    k_import = k_commands.add_parser("import", help="Import a batch of rules (Maintainer)")
    k_import.add_argument("--project")
    k_import.add_argument("--batch", required=True, metavar="FILE")
    k_import.add_argument("--accept-update", action="append", default=[], metavar="RULE@DIGEST")
    k_import.add_argument("--false-positive", action="append", default=[], metavar="RULE:FINGERPRINT")
    k_update = k_commands.add_parser("update", help="Update one rule (Maintainer)")
    k_update.add_argument("--project")
    k_update.add_argument("--rule", required=True)
    k_update.add_argument("--base-state", required=True, metavar="DIGEST")
    k_update.add_argument("--input", required=True, metavar="FILE")
    k_update.add_argument("--false-positive", action="append", default=[], metavar="RULE:FINGERPRINT")
    k_list = k_commands.add_parser("list", help="List stored rules and pending decisions (read-only)")
    k_list.add_argument("--project")
    k_list.add_argument("--namespace")
    k_list.add_argument("--version")
    k_show = k_commands.add_parser("show", help="Show one rule with its changelog (read-only)")
    k_show.add_argument("--project")
    k_show.add_argument("--rule", required=True)
    k_exits = []
    for name, text in (
        ("exit-preview", "Show the impact of deactivate/reactivate/delete/rename first (Maintainer)"),
        ("exit-confirm", "Perform the previewed exit with its impact digest (Maintainer confirmed)"),
    ):
        sub = k_commands.add_parser(name, help=text)
        sub.add_argument("--project")
        sub.add_argument("--rule", required=True)
        sub.add_argument("--action", required=True)
        sub.add_argument("--to", metavar="NAMESPACE/VERSION/NEW_ID")
        sub.add_argument("--reason")
        if name == "exit-confirm":
            sub.add_argument("--impact-digest", metavar="DIGEST")
        k_exits.append(sub)
    k_links = k_commands.add_parser("links", help="Report broken relations and scope references (read-only)")
    k_links.add_argument("--project")
    for sub in (k_check, k_import, k_update, k_list, k_show, *k_exits, k_links):
        sub.add_argument("--json", action="store_true")

    policy = commands.add_parser("policy", help="Resolve formal Local Policies (read-only)")
    p_commands = policy.add_subparsers(dest="policy_command", required=True)
    p_resolve = p_commands.add_parser("resolve", help="Resolve rule references or all Policies")
    p_resolve.add_argument("--project")
    p_resolve.add_argument("--rule", action="append", default=[], metavar="REF",
                           help="NAMESPACE/VERSION/RULE_ID or NAMESPACE/RULE_ID (repeatable)")
    p_resolve.add_argument("--all", action="store_true", help="Apply All proposal (no clues given)")
    p_resolve.add_argument("--language", action="append", default=[], metavar="LANG",
                           help="Artifact language for advisory notes (repeatable)")
    p_resolve.add_argument("--output", metavar="FILE", help="Write the full result to FILE")
    p_resolve.add_argument("--json", action="store_true")

    scope = commands.add_parser("scope", help="Adopted Policy scope records")
    s_commands = scope.add_subparsers(dest="scope_command", required=True)
    s_save = s_commands.add_parser("save", help="Save the scope the user confirmed")
    s_save.add_argument("--project")
    s_save.add_argument("--decisions", required=True, metavar="FILE")
    s_save.add_argument("--confirmed", action="store_true", help="The user confirmed this scope")
    s_save.add_argument("--json", action="store_true")
    s_show = s_commands.add_parser("show", help="Load a scope and check it against current knowledge")
    s_show.add_argument("--project")
    s_show.add_argument("--scope", required=True, metavar="ID")
    s_show.add_argument("--output", metavar="FILE")
    s_show.add_argument("--json", action="store_true")

    preset = commands.add_parser("preset",
                                 help="Reusable Policy scopes of concrete rule references (FEATURE-001-F)")
    pr_commands = preset.add_subparsers(dest="preset_command", required=True)
    pr_list = pr_commands.add_parser("list", help="List Presets in name order (read-only)")
    pr_show = pr_commands.add_parser("show", help="Show one Preset with current availability (read-only)")
    pr_show.add_argument("name")
    pr_save = pr_commands.add_parser("save", help="Save a new Preset the user confirmed")
    pr_save.add_argument("--request", required=True, metavar="FILE")
    pr_save.add_argument("--confirmed", action="store_true", help="The user confirmed this Preset")
    pr_update = pr_commands.add_parser("update", help="Update a Preset (current file digest)")
    pr_update.add_argument("name")
    pr_update.add_argument("--request", required=True, metavar="FILE")
    pr_update.add_argument("--digest", metavar="DIGEST")
    pr_update.add_argument("--confirmed", action="store_true")
    pr_delete = pr_commands.add_parser("delete", help="Delete a Preset (current file digest)")
    pr_delete.add_argument("name")
    pr_delete.add_argument("--digest", metavar="DIGEST")
    pr_delete.add_argument("--confirmed", action="store_true")
    pr_recompute = pr_commands.add_parser("recompute", help="Diff agent-produced candidates (read-only)")
    pr_recompute.add_argument("name")
    pr_recompute.add_argument("--request", required=True, metavar="FILE")
    pr_reconfirm = pr_commands.add_parser("recompute-confirm", help="Apply a confirmed recompute diff")
    pr_reconfirm.add_argument("name")
    pr_reconfirm.add_argument("--request", required=True, metavar="FILE")
    pr_reconfirm.add_argument("--confirmed", action="store_true")
    pr_resolve = pr_commands.add_parser("resolve", help="Propose a Preset (or the default Preset) as scope")
    pr_resolve.add_argument("name", nargs="?")
    pr_resolve.add_argument("--default", action="store_true", help="No clues: propose the default Preset")
    pr_resolve.add_argument("--language", action="append", default=[], metavar="LANG")
    pr_resolve.add_argument("--output", metavar="FILE", help="Write the full result to FILE")
    pr_scope = pr_commands.add_parser("scope-save", help="Save the confirmed Preset-based scope")
    pr_scope.add_argument("name")
    pr_scope.add_argument("--decisions", required=True, metavar="FILE")
    pr_scope.add_argument("--confirmed", action="store_true", help="The user confirmed this scope")

    tag = commands.add_parser("tag",
                              help="Rule classifications (Maintainer writes, open reads; FEATURE-001-F)")
    tg_commands = tag.add_subparsers(dest="tag_command", required=True)
    tg_list = tg_commands.add_parser("list", help="List tags (read-only)")
    tg_show = tg_commands.add_parser("show", help="Show one tag with current availability (read-only)")
    tg_show.add_argument("name")
    tg_save = tg_commands.add_parser("save", help="Save a new tag (Maintainer)")
    tg_save.add_argument("--request", required=True, metavar="FILE")
    tg_save.add_argument("--confirmed", action="store_true")
    tg_update = tg_commands.add_parser("update", help="Replace a tag's members (Maintainer)")
    tg_update.add_argument("name")
    tg_update.add_argument("--request", required=True, metavar="FILE")
    tg_update.add_argument("--digest", metavar="DIGEST")
    tg_update.add_argument("--confirmed", action="store_true")
    tg_delete = tg_commands.add_parser("delete", help="Delete a tag (Maintainer)")
    tg_delete.add_argument("name")
    tg_delete.add_argument("--digest", metavar="DIGEST")
    tg_delete.add_argument("--confirmed", action="store_true")
    for sub in (pr_list, pr_show, pr_save, pr_update, pr_delete, pr_recompute, pr_reconfirm, pr_resolve,
                pr_scope, tg_list, tg_show, tg_save, tg_update, tg_delete):
        sub.add_argument("--project")
        sub.add_argument("--json", action="store_true")
    guard = commands.add_parser("guard", help="Guard verification records and verdict (FEATURE-002-A)")
    g_commands = guard.add_subparsers(dest="guard_command", required=True)
    g_open = g_commands.add_parser("open", help="Open a verification of explicit targets")
    g_open.add_argument("--request", required=True, metavar="FILE")
    g_subs = [g_open]
    for name, text in (("plan", "Record the check plan (once)"),
                       ("record", "Record evidence, findings, ledger states and conflicts"),
                       ("review", "Record one independent Reviewer record"),
                       ("attempt", "Register one unit of work before it starts (budget)"),
                       ("egress", "Declare one outbound call before making it")):
        sub = g_commands.add_parser(name, help=text)
        sub.add_argument("--run", required=True, metavar="ID")
        sub.add_argument("--request", required=True, metavar="FILE")
        g_subs.append(sub)
    for name, text in (("conclude", "Compute the verdict and write the report"),
                       ("show", "Show a concluded verification (read-only)"),
                       ("release", "Remove the keep marker of a verification's evidence"),
                       ("resume", "Resume a paused verification")):
        sub = g_commands.add_parser(name, help=text)
        sub.add_argument("--run", required=True, metavar="ID")
        g_subs.append(sub)
    g_keep = g_commands.add_parser("keep", help="Keep a verification's evidence beyond 30 days")
    g_keep.add_argument("--run", required=True, metavar="ID")
    g_keep.add_argument("--reason", required=True)
    g_accept = g_commands.add_parser("accept-risk", help="Record a User's risk acceptance (interactive only)")
    g_accept.add_argument("--run", required=True, metavar="ID")
    g_accept.add_argument("--finding", required=True)
    g_accept.add_argument("--reason", required=True)
    g_tool = g_commands.add_parser("tool", help="Run an Adapter (e.g. opengrep) for planned checks")
    g_tool.add_argument("--run", required=True, metavar="ID")
    g_tool.add_argument("--request", required=True, metavar="FILE")
    g_subs.append(g_tool)
    g_pause = g_commands.add_parser("pause", help="Pause while waiting for the user (the clock stops)")
    g_pause.add_argument("--run", required=True, metavar="ID")
    g_pause.add_argument("--reason", required=True)
    g_extend = g_commands.add_parser("extend", help="Add time/attempts to a budget (user, interactive only)")
    g_extend.add_argument("--run", required=True, metavar="ID")
    g_extend.add_argument("--minutes", type=int, default=0)
    g_extend.add_argument("--attempts", type=int, default=0)
    g_extend.add_argument("--reason", required=True)
    g_cancel = g_commands.add_parser("cancel", help="Cancel one verification (partial report, never Pass)")
    g_cancel.add_argument("--run", required=True, metavar="ID")
    g_cancel.add_argument("--reason")
    g_allow = g_commands.add_parser("allow-egress", help="Grant one outbound purpose (user, interactive)")
    g_allow.add_argument("--run", required=True, metavar="ID")
    g_allow.add_argument("--purpose", required=True)
    g_allow.add_argument("--recipient", required=True)
    g_allow.add_argument("--data", required=True, help="comma-separated data categories")
    g_allow.add_argument("--scope", required=True, action="append")
    g_allow.add_argument("--reason", required=True)
    g_cleanup = g_commands.add_parser("cleanup", help="Remove expired evidence of finished verifications")
    for sub in (*g_subs, g_keep, g_accept, g_pause, g_extend, g_cancel, g_allow, g_cleanup):
        sub.add_argument("--project")
        sub.add_argument("--json", action="store_true")
    g_compare = g_commands.add_parser(
        "compare", help="Compare two concluded Guard reports (read-only on both runs)"
    )
    g_compare.add_argument("--earlier", action="append", metavar="ID_OR_REPORT")
    g_compare.add_argument("--later", action="append", metavar="ID_OR_REPORT")
    g_compare.add_argument("--project")
    g_compare.add_argument("--json", action="store_true")

    copilot = commands.add_parser("copilot", help="Copilot suggestions and adoption review (FEATURE-003-A)")
    c_commands = copilot.add_subparsers(dest="copilot_command", required=True)
    c_open = c_commands.add_parser("open", help="Open a collaboration on explicit changed artifacts")
    c_open.add_argument("--request", required=True, metavar="FILE")
    c_subs = [c_open]
    for name, text in (("artifacts", "Record added, modified, deleted or renamed artifacts"),
                       ("suggest", "Record one batch of concrete suggestions"),
                       ("review", "Record one independent read-only Reviewer record")):
        sub = c_commands.add_parser(name, help=text)
        sub.add_argument("--id", required=True, metavar="ID")
        sub.add_argument("--request", required=True, metavar="FILE")
        c_subs.append(sub)
    for name, text in (("report", "Publish a new report round when the state changed"),
                       ("show", "Show the current state and stale suggestions (read-only)"),
                       ("close", "Publish a final round if needed and close the collaboration")):
        sub = c_commands.add_parser(name, help=text)
        sub.add_argument("--id", required=True, metavar="ID")
        c_subs.append(sub)
    for sub in c_subs:
        sub.add_argument("--project")
        sub.add_argument("--json", action="store_true")

    tools = commands.add_parser("tools", help="Scanner tools for Adapters (Maintainer registration)")
    t_commands = tools.add_subparsers(dest="tools_command", required=True)
    t_register = t_commands.add_parser("register", help="Register an official tool binary (Maintainer)")
    t_register.add_argument("--project")
    t_register.add_argument("--tool", required=True)
    t_register.add_argument("--path", required=True)
    t_register.add_argument("--json", action="store_true")
    t_prov = t_commands.add_parser(
        "provision",
        help="Provision Trivy components under tool_update grants of an open verification (Maintainer)",
    )
    t_prov.add_argument("--project")
    t_prov.add_argument("--tool", required=True)
    t_prov.add_argument("--run", required=True, metavar="ID")
    t_prov.add_argument("--component", action="append", required=True,
                        help="vulnerability_db, java_db or checks_bundle (repeatable)")
    t_prov.add_argument("--registry", default="mirror.gcr.io", help="mirror.gcr.io (default) or ghcr.io")
    t_prov.add_argument("--time-limit", type=int, default=600, metavar="SECONDS", help="1…3600")
    t_prov.add_argument("--json", action="store_true")
    t_remove = t_commands.add_parser(
        "remove-components", help="Remove provisioned Trivy components (Maintainer)"
    )
    t_remove.add_argument("--project")
    t_remove.add_argument("--tool", required=True)
    t_remove.add_argument("--component", action="append", help="vulnerability_db, java_db or checks_bundle")
    t_remove.add_argument("--all", action="store_true", help="remove every provisioned component")
    t_remove.add_argument("--json", action="store_true")

    auth = commands.add_parser("auth", help="Owner authorization")
    auth_commands = auth.add_subparsers(dest="auth_command", required=True)
    for name, text in (("init", "Initialize or re-authorize (interactive owner only)"),
                       ("revoke", "Revoke the authorization (interactive owner only)"),
                       ("status", "Show the verified role")):
        sub = auth_commands.add_parser(name, help=text)
        sub.add_argument("--json", action="store_true")
    return parser


def run(args: argparse.Namespace) -> Result:
    if args.command == "init":
        return initialize_project(args.project, args.env, args.replace, args.toolkit_source)
    if args.command == "carriers":
        from .carriers import run as run_carriers

        return run_carriers(args.project, args.env, select=args.select, deselect=args.deselect,
                            regenerate=args.regenerate, accept=args.accept, host=args.system_prompt_host)
    if args.command == "status":
        return collect(args.project)
    if args.command == "knowledge":
        return _knowledge(args)
    if args.command in ("policy", "scope"):
        return _policy(args)
    if args.command in ("preset", "tag"):
        return _presets(args)
    if args.command == "guard":
        return _guard(args)
    if args.command == "copilot":
        return _copilot(args)
    if args.command == "tools":
        from . import tools_service

        if args.tools_command == "provision":
            return tools_service.provision(args.project, args.tool, args.run, args.component, args.registry,
                                           args.time_limit)
        if args.tools_command == "remove-components":
            return tools_service.remove_components(args.project, args.tool, args.component, args.all)
        return tools_service.register(args.project, args.tool, args.path)
    if args.auth_command == "init":
        return initialize_authorization()
    if args.auth_command == "revoke":
        return revoke_authorization()
    return auth_status()


def _knowledge(args: argparse.Namespace) -> Result:
    from .knowledge import service

    cmd = args.knowledge_command
    if cmd == "check":
        return service.check(args.project, args.input)
    if cmd == "import":
        return service.import_batch(args.project, args.batch, args.accept_update, args.false_positive)
    if cmd == "update":
        return service.update_rule(args.project, args.rule, args.base_state, args.input,
                                   args.false_positive)
    if cmd == "list":
        return service.list_rules(args.project, args.namespace, args.version)
    if cmd in ("exit-preview", "exit-confirm", "links"):
        from .knowledge import exit as exits

        if cmd == "links":
            return exits.links(args.project)
        if cmd == "exit-preview":
            return exits.preview(args.project, args.rule, args.action, args.to, args.reason)
        return exits.confirm(args.project, args.rule, args.action, args.to, args.reason, args.impact_digest)
    return service.show_rule(args.project, args.rule)


def _policy(args: argparse.Namespace) -> Result:
    from .policy import service

    if args.command == "policy":
        return service.resolve_policies(args.project, args.rule, args.all, args.language, args.output)
    if args.scope_command == "save":
        return service.save_scope(args.project, args.decisions, args.confirmed)
    return service.show_scope(args.project, args.scope, args.output)


def _presets(args: argparse.Namespace) -> Result:
    if args.command == "tag":
        from .knowledge import tags

        cmd = args.tag_command
        if cmd == "list":
            return tags.list_tags(args.project)
        if cmd == "show":
            return tags.show_tag(args.project, args.name)
        if cmd == "save":
            return tags.save_tag(args.project, args.request, args.confirmed)
        if cmd == "update":
            return tags.update_tag(args.project, args.name, args.request, args.digest, args.confirmed)
        return tags.delete_tag(args.project, args.name, args.digest, args.confirmed)
    cmd = args.preset_command
    if cmd in ("resolve", "scope-save"):
        from .policy import preset_scope

        if cmd == "scope-save":
            return preset_scope.save(args.project, args.name, args.decisions, args.confirmed)
        if bool(args.name) == bool(args.default):
            return Result.refused("preset resolve", "REQUEST_INVALID",
                                  "Pass either a Preset NAME or --default",
                                  "Use NAME for a chosen Preset, or --default when the user gave no clues")
        if args.default:
            return preset_scope.resolve_default(args.project, args.language, args.output)
        return preset_scope.resolve_preset(args.project, args.name, args.language, args.output)
    from .knowledge import presets

    if cmd == "list":
        return presets.list_presets(args.project)
    if cmd == "show":
        return presets.show_preset(args.project, args.name)
    if cmd == "save":
        return presets.save_preset(args.project, args.request, args.confirmed)
    if cmd == "update":
        return presets.update_preset(args.project, args.name, args.request, args.digest, args.confirmed)
    if cmd == "delete":
        return presets.delete_preset(args.project, args.name, args.digest, args.confirmed)
    if cmd == "recompute":
        return presets.recompute(args.project, args.name, args.request)
    return presets.recompute_confirm(args.project, args.name, args.request, args.confirmed)


def _guard(args: argparse.Namespace) -> Result:
    from .guard import service

    cmd = args.guard_command
    if cmd == "tool":
        from .guard.toolrun import run_tool

        return run_tool(args.project, args.run, args.request)
    if cmd == "open":
        return service.open_verification(args.project, args.request)
    if cmd in ("allow-egress", "egress"):
        from .guard import egress

        if cmd == "egress":
            return egress.declare(args.project, args.run, args.request)
        data = [d.strip() for d in args.data.split(",") if d.strip()]
        return egress.allow_egress(
            args.project, args.run, args.purpose, args.recipient, data, args.scope, args.reason
        )
    if cmd == "cancel":
        from .guard.cancel import cancel

        return cancel(args.project, args.run, args.reason)
    if cmd in ("attempt", "pause", "resume", "extend"):
        from .guard import control

        if cmd == "attempt":
            return control.attempt(args.project, args.run, args.request)
        if cmd == "pause":
            return control.pause(args.project, args.run, args.reason)
        if cmd == "resume":
            return control.resume(args.project, args.run)
        return control.extend(args.project, args.run, args.minutes, args.attempts, args.reason)
    if cmd in ("plan", "record", "review"):
        functions = {"plan": service.record_plan, "record": service.record, "review": service.record_review}
        function = functions[cmd]
        return function(args.project, args.run, args.request)
    if cmd == "accept-risk":
        return service.accept_risk(args.project, args.run, args.finding, args.reason)
    if cmd == "keep":
        return service.keep(args.project, args.run, args.reason)
    if cmd == "cleanup":
        return service.cleanup(args.project)
    if cmd == "compare":
        from .guard.compare import compare

        return compare(args.project, args.earlier, args.later)
    return {"conclude": service.conclude, "show": service.show, "release": service.release}[cmd](
        args.project, args.run
    )


def _copilot(args: argparse.Namespace) -> Result:
    from .copilot import service

    cmd = args.copilot_command
    if cmd == "open":
        return service.open_collaboration(args.project, args.request)
    if cmd in ("artifacts", "suggest", "review"):
        function = {"artifacts": service.update_artifacts, "suggest": service.suggest,
                    "review": service.review}[cmd]
        return function(args.project, args.id, args.request)
    functions = {"report": service.report, "show": service.show, "close": service.close}
    return functions[cmd](args.project, args.id)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    result = run(args)
    print(result.to_json() if args.json else result.to_text())
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
