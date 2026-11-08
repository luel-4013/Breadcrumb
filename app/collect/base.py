"""Collector contract and registry.

A collector is a native implementation of a Leadline phase. It receives a
small context (target, options, scope guard, cancellation check, event sink)
and returns one or more named phase outputs. The executor turns each output
into a sealed Breadcrumb capture through ``app.ingest``.

Collectors must never open a socket without first calling
``ctx.check_url``/``ctx.check_host``. The guard resolves and pins addresses;
collectors should connect to the returned address, not resolve again.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from ..ingest import IngestResult
from .guard import ScopeDecision, ScopeDenied, ScopeGuard


@dataclass
class PhaseOutput:
    """One named phase's raw output, ready to be sealed as evidence."""

    name: str
    output: str = ""
    stats: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class CollectorResult:
    phases: list[PhaseOutput] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


class CollectorError(RuntimeError):
    """A collector failed in a way that should fail the job."""


def require_no_proxy(ctx) -> None:
    """Native collectors must refuse a proxy, never silently bypass it."""
    if getattr(ctx, "proxy", ""):
        raise CollectorError(
            "native collectors do not support a proxy; clear the header "
            "profile proxy or use an external runner"
        )


class JobCancelled(RuntimeError):
    """Raised when a job's cancel flag is observed."""


@dataclass
class CollectorContext:
    """Everything a collector is allowed to touch."""

    target: str
    options: dict
    guard: ScopeGuard
    job_id: int
    attempt_id: int
    worker_id: str
    cancel_event: threading.Event | None = None
    headers: dict = field(default_factory=dict)
    proxy: str = ""
    rate_limit: float = 0.0
    emit: Callable[[str, str, dict], None] | None = None
    ingest_phase: Callable[[str, str, dict], IngestResult] | None = None

    def emit_event(self, kind: str, message: str, **data) -> None:
        if self.emit is not None:
            self.emit(kind, message, dict(data))

    def cancelled(self) -> bool:
        return bool(self.cancel_event is not None and self.cancel_event.is_set())

    def check_cancel(self) -> None:
        if self.cancelled():
            raise JobCancelled("job cancellation requested")

    def check_url(self, url: str) -> ScopeDecision:
        decision = self.guard.check_url(url)
        self.emit_event(
            "scope",
            f"{url} -> {'allow' if decision.allowed else 'deny'} ({decision.reason})",
            **decision.as_dict(),
        )
        if not decision.allowed:
            raise ScopeDenied(decision)
        return decision

    def check_host(self, host: str, *, port: int | None = None) -> ScopeDecision:
        decision = self.guard.check_host(host, port=port)
        self.emit_event(
            "scope",
            f"{host} -> {'allow' if decision.allowed else 'deny'} ({decision.reason})",
            **decision.as_dict(),
        )
        if not decision.allowed:
            raise ScopeDenied(decision)
        return decision

    def check_network(self, value: str) -> ScopeDecision:
        decision = self.guard.check_network(value)
        self.emit_event(
            "scope",
            f"{value} -> {'allow' if decision.allowed else 'deny'} ({decision.reason})",
            **decision.as_dict(),
        )
        if not decision.allowed:
            raise ScopeDenied(decision)
        return decision

    def sleep(self, seconds: float) -> None:
        """Cancellation-aware sleep for rate limiting and test collectors."""
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            self.check_cancel()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if self.cancel_event is not None:
                if self.cancel_event.wait(min(remaining, 0.2)):
                    self.check_cancel()
            else:
                time.sleep(min(remaining, 0.2))


class Collector:
    """Base class for native collectors."""

    id: str = ""
    label: str = ""
    description: str = ""
    category: str = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        raise NotImplementedError


REGISTRY: dict[str, Collector] = {}
ADAPTER_REGISTRY: dict[str, Collector] = {}


def register(cls):
    collector = cls()
    REGISTRY[collector.id] = collector
    return cls


def register_adapter(cls):
    """Register an opt-in external-tool adapter.

    Adapters share the Collector contract but are kept in a separate registry
    so the durable worker does not silently claim jobs that were queued for an
    external runner. They are claimable by explicit runner id (run-now/CLI) or
    by the worker when ``BREADCRUMB_EXTERNAL_TOOLS=1``.
    """
    collector = cls()
    ADAPTER_REGISTRY[collector.id] = collector
    return cls


def get_collector(collector_id: str) -> Collector | None:
    return REGISTRY.get(collector_id) or ADAPTER_REGISTRY.get(collector_id)


def collector_ids() -> tuple[str, ...]:
    return tuple(sorted(REGISTRY))


def adapter_ids() -> tuple[str, ...]:
    return tuple(sorted(ADAPTER_REGISTRY))


def adapters_enabled() -> bool:
    return os.environ.get("BREADCRUMB_EXTERNAL_TOOLS", "").strip().lower() in (
        "1", "true", "yes", "on"
    )


def claimable_collector_ids() -> tuple[str, ...]:
    ids = set(REGISTRY)
    if adapters_enabled():
        ids.update(ADAPTER_REGISTRY)
    return tuple(sorted(ids))


def list_collectors() -> list[Collector]:
    return [REGISTRY[key] for key in sorted(REGISTRY)]


def list_adapters() -> list[Collector]:
    return [ADAPTER_REGISTRY[key] for key in sorted(ADAPTER_REGISTRY)]


# Import built-in collectors for their registration side effects. Kept at the
# bottom to avoid a circular import while the classes above are defined.
from . import dns as _dns  # noqa: E402,F401
from . import fake as _fake  # noqa: E402,F401
from . import http as _http  # noqa: E402,F401
from . import ports as _ports  # noqa: E402,F401
from . import host_intel as _host_intel  # noqa: E402,F401
from . import js as _js  # noqa: E402,F401
from . import params as _params  # noqa: E402,F401
from . import api as _api  # noqa: E402,F401
from . import vulns as _vulns  # noqa: E402,F401
from . import cve as _cve  # noqa: E402,F401
from . import graph as _graph  # noqa: E402,F401
from . import recon as _recon  # noqa: E402,F401
from . import tools as _tools  # noqa: E402,F401
