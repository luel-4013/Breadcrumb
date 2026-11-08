"""Durable execution for native collectors.

External runners keep the original import-first contract. This package adds
the optional native worker: atomic claims, leases, heartbeats, retries,
cancellation, crash recovery, sealed evidence, and phase/attempt history.
"""

from .queue import (
    Claim,
    claim_next,
    finish,
    heartbeat,
    recover_expired,
    request_cancel,
    retry_or_fail,
)
from .worker import (
    DEFAULT_LEASE_SECONDS,
    execute_claimed,
    new_worker_id,
    run_once,
    run_worker,
    start_background_worker,
)

__all__ = [
    "Claim",
    "claim_next",
    "finish",
    "heartbeat",
    "recover_expired",
    "request_cancel",
    "retry_or_fail",
    "DEFAULT_LEASE_SECONDS",
    "execute_claimed",
    "new_worker_id",
    "run_once",
    "run_worker",
    "start_background_worker",
]
