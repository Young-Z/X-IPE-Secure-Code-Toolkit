"""`secure-code tools register` (FEATURE-002-B) and the Trivy component commands (FEATURE-002-D)."""

from __future__ import annotations

from .adapters import digests, provided, registry_store
from .atomic import LockHeld
from .auth.service import require_maintainer
from .auth.trust_store import TrustPaths
from .guard.model import utc_now
from .knowledge import store
from .projects import knowledge_root
from .results import Result


def register(project: str | None, tool: str, path: str, trust_paths: TrustPaths | None = None) -> Result:
    """Register the binary of a provided Adapter after checking it against the official digests.

    The binary is hashed, never executed.
    """
    command = "tools register"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    if tool not in provided():
        return Result.refused(
            command,
            "TOOL_UNKNOWN",
            f"No Adapter for {tool!r} in this toolkit version",
            f"Available: {', '.join(provided())}",
        )
    gap = registry_store.platform_gap(tool, digests.host_platform()) if tool == "trivy" else None
    if gap is not None:
        return Result.refused(command, gap.code, gap.reason, gap.next_step)
    decision = require_maintainer("tools.register", paths=trust_paths)
    if not decision.allowed:
        refused = decision.to_result()
        refused.command = command
        return refused
    try:
        outcome = registry_store.register(root, tool, path, utc_now())
    except (store.StoreError, LockHeld) as exc:
        return Result.refused(
            command, getattr(exc, "code", "LOCKED"), str(exc), "Fix the private folder and retry"
        )
    except OSError as exc:
        return Result.refused(command, "IO_ERROR", f"Registration could not be written: {exc}")
    if isinstance(outcome, registry_store.Gap):
        return Result.refused(command, outcome.code, outcome.reason, outcome.next_step)
    data = {
        k: outcome[k]
        for k in ("tool", "version", "asset", "platform", "platform_validated", "path", "digest")
    }
    return Result(command, True, data, [], ["Check it with: secure-code status --project PATH"])


def provision(
    project: str | None,
    tool: str,
    run_id: str,
    components: list[str],
    registry: str = "mirror.gcr.io",
    time_limit: int = 600,
    trust_paths: TrustPaths | None = None,
) -> Result:
    """Maintainer provisioning of Trivy components under `tool_update` grants of an open verification."""
    from .adapters import trivy_provision

    return trivy_provision.provision(project, tool, run_id, components, registry, time_limit, trust_paths)


def remove_components(project: str | None, tool: str, components: list[str] | None = None,
                      remove_all: bool = False, trust_paths: TrustPaths | None = None) -> Result:
    """Maintainer removal of provisioned Trivy components from the project's private cache."""
    from .adapters import trivy_provision

    return trivy_provision.remove_components(project, tool, components, remove_all, trust_paths)


def register_helper_image(project: str | None, image: str, trust_paths: TrustPaths | None = None) -> Result:
    """Maintainer registration of a locally present helper image (FEATURE-002-F; never pulls or builds)."""
    from .guard.helpers import registry

    return registry.register_image(project, image, trust_paths)


def helper_conformance(project: str | None, trust_paths: TrustPaths | None = None) -> Result:
    """Maintainer offline conformance suite of the helper runtime (FEATURE-002-F)."""
    from .guard.helpers import conformance

    return conformance.run(project, trust_paths)
