"""Deterministic collectors used by the executor tests.

They are registered so tests can insert jobs directly, but their ids never
appear in the runner catalog and the API rejects them. Keeping them in the
same contract exercises the real claim/lease/heartbeat/ingest path without a
network or an external binary.
"""

from __future__ import annotations

import time

from .base import Collector, CollectorContext, CollectorError, CollectorResult, PhaseOutput, register


@register
class EchoCollector(Collector):
    id = "fake-echo"
    label = "Test echo"
    description = "Emits the target as a capture."
    category = "internal"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        ctx.check_cancel()
        ctx.emit_event("progress", "echo collector")
        text = str(ctx.options.get("text") or ctx.target or "") + "\n"
        return CollectorResult([PhaseOutput("echo", text, {"bytes": len(text)})])


@register
class FailCollector(Collector):
    id = "fake-fail"
    label = "Test failure"
    description = "Always raises."
    category = "internal"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        raise CollectorError("synthetic collector failure")


@register
class CancelCollector(Collector):
    id = "fake-cancel"
    label = "Test cancellation"
    description = "Waits until cancellation is requested."
    category = "internal"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        deadline = time.monotonic() + float(ctx.options.get("seconds", 10))
        while time.monotonic() < deadline:
            ctx.check_cancel()
            ctx.sleep(0.05)
        return CollectorResult([PhaseOutput("cancel", "completed without cancellation\n")])


@register
class ScopeCollector(Collector):
    id = "fake-scope"
    label = "Test scope check"
    description = "Checks the target through the scope guard and emits the decision."
    category = "internal"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        decision = ctx.check_host(ctx.target)
        lines = [
            f"allowed={decision.allowed}",
            f"status={decision.status}",
            f"host={decision.host}",
            f"addresses={','.join(decision.addresses)}",
            f"warnings={' | '.join(decision.warnings)}",
        ]
        return CollectorResult([PhaseOutput("scope", "\n".join(lines) + "\n")])
