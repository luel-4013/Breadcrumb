"""Native collection layer (Leadline's collectors, absorbed into Breadcrumb).

Importing this package registers the built-in collectors. Public helpers are
re-exported here so callers do not need to know the module layout.
"""

from .base import (
    Collector,
    CollectorContext,
    CollectorError,
    CollectorResult,
    JobCancelled,
    PhaseOutput,
    adapter_ids,
    adapters_enabled,
    claimable_collector_ids,
    collector_ids,
    get_collector,
    list_adapters,
    list_collectors,
)
from .guard import (
    HARD_BLOCKED_HOSTS,
    HARD_BLOCKED_NETWORKS,
    PRIVATE_NETWORKS,
    PRIVATE_TARGET_WARNING,
    ScopeDecision,
    ScopeDenied,
    ScopeGuard,
)

__all__ = [
    "Collector",
    "CollectorContext",
    "CollectorError",
    "CollectorResult",
    "JobCancelled",
    "PhaseOutput",
    "adapter_ids",
    "adapters_enabled",
    "claimable_collector_ids",
    "collector_ids",
    "get_collector",
    "list_adapters",
    "list_collectors",
    "HARD_BLOCKED_HOSTS",
    "HARD_BLOCKED_NETWORKS",
    "PRIVATE_NETWORKS",
    "PRIVATE_TARGET_WARNING",
    "ScopeDecision",
    "ScopeDenied",
    "ScopeGuard",
]
