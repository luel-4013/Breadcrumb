from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text, UniqueConstraint
from sqlalchemy.types import JSON
from sqlmodel import Field, SQLModel

from .secrets_store import EncryptedJSON, EncryptedText


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Program(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    platform: Optional[str] = None
    scope_in: Optional[str] = Field(default=None, sa_column=Column(Text))
    scope_out: Optional[str] = Field(default=None, sa_column=Column(Text))
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    ai_summary: Optional[str] = Field(default=None, sa_column=Column(Text))
    ai_model: Optional[str] = None
    ai_at: Optional[datetime] = None
    # Phase B: per-rule severity overrides for imported findings.
    # {"template-id": "critical"}. Applied at ingest, never destructive.
    rule_severities: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    name: str = Field(index=True)
    kind: str = "domain"
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    # Import/provenance metadata. Additive: normal UI targets leave this empty.
    meta: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)


class Paste(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    # Durable-execution provenance. These are deliberately *not* foreign keys:
    # evidence outlives a deleted job, and deleting a job must never be
    # blocked by (or cascade into) the hash-chained capture table.
    job_id: Optional[int] = Field(default=None, index=True)
    attempt_id: Optional[int] = Field(default=None, index=True)
    phase: Optional[str] = Field(default=None, index=True)
    source: str = "manual"
    tool_guess: Optional[str] = None
    parsers: Optional[list] = Field(default_factory=list, sa_column=Column(JSON))
    parse_errors: list = Field(default_factory=list, sa_column=Column(JSON))
    ai_analysis: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    ai_model: Optional[str] = None
    ai_at: Optional[datetime] = None
    raw: str = Field(sa_column=Column(Text))
    # Tamper-evident evidence chain: sha256 of the raw capture + a hash-chain
    # link to the previous capture. Verifiable offline (see /api/v1/verify).
    content_sha256: Optional[str] = Field(default=None, index=True)
    chain_hash: Optional[str] = None
    prev_paste_id: Optional[int] = None
    # Position in the linear evidence chain (1-based) and a stable delivery
    # key used by the worker for idempotent ingest. Both are protected by
    # partial unique indexes in app.db.
    chain_seq: Optional[int] = None
    capture_key: Optional[str] = None
    # Import trust (Phase A). Every capture explains itself: how complete the
    # parse was, which parser versions ran, what was skipped, and how it was
    # produced. The manifest is derived from these fields plus the sealed
    # content, so it can be verified offline.
    completeness: float = 1.0
    skipped_rows: int = 0
    parser_versions: dict = Field(default_factory=dict, sa_column=Column(JSON))
    import_stats: dict = Field(default_factory=dict, sa_column=Column(JSON))
    command: Optional[str] = Field(default=None, sa_column=Column(Text))
    source_meta: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)


class EvidenceChain(SQLModel, table=True):
    """Singleton row (id=1) pointing at the head of the capture hash chain.

    Keeping the head explicit lets the ingest path link a new capture without
    scanning the whole paste table. ``length`` is the number of sealed
    captures currently present; deleting a program records a gap but keeps
    the remaining chain verifiable.
    """

    __tablename__ = "evidencechain"

    id: Optional[int] = Field(default=None, primary_key=True)
    head_paste_id: Optional[int] = None
    length: int = 0
    updated_at: datetime = Field(default_factory=_utcnow)


class Entity(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    paste_id: Optional[int] = Field(default=None, foreign_key="paste.id", index=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    type: str = Field(index=True)
    value: str = Field(index=True)
    normalized: str = ""
    confidence: float = 1.0
    parser: str = ""
    status: str = "new"
    scope_status: str = Field(default="unknown", index=True)
    # Phase B: why the scope engine made this decision. Stable codes such as
    # "in_rule", "out_rule", "status_filter", "no_match", "no_host".
    scope_reason: str = ""
    # HTTP status code observed for this asset, when known. Used by scope
    # status filters and Ledger/diff filters; never guessed from a URL alone.
    status_code: Optional[int] = Field(default=None, index=True)
    ignored: bool = Field(default=False, index=True)
    # Analyst verdict: noise suppression / accuracy (never a parser decision).
    # "none" | "confirmed" | "false-positive" | "needs-review"
    verdict: str = Field(default="none", index=True)
    tags: list = Field(default_factory=list, sa_column=Column(JSON))
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    occurrences: int = 1
    meta: dict = Field(default_factory=dict, sa_column=Column(JSON))
    provenance: list = Field(default_factory=list, sa_column=Column(JSON))
    # Cross-program memory: which OTHER programs have also seen this asset.
    # [{"id": 2, "name": "Acme"}]. The "second brain" other tools lack.
    cross_programs: list = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)


class Relationship(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    paste_id: Optional[int] = Field(default=None, foreign_key="paste.id", index=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    src_value: str
    src_type: str
    dst_value: str
    dst_type: str
    rel_type: str
    src_entity_id: Optional[int] = Field(default=None, index=True)
    dst_entity_id: Optional[int] = Field(default=None, index=True)
    confidence: float = 1.0
    source: str = "parser"
    meta: dict = Field(default_factory=dict, sa_column=Column(JSON))


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    paste_id: Optional[int] = Field(default=None, foreign_key="paste.id", index=True)
    title: str
    severity: str = "info"
    status: str = "open"
    cvss: Optional[str] = None
    description: Optional[str] = Field(default=None, sa_column=Column(Text))
    steps: Optional[str] = Field(default=None, sa_column=Column(Text))
    impact: Optional[str] = Field(default=None, sa_column=Column(Text))
    evidence: Optional[str] = Field(default=None, sa_column=Column(Text))
    remediation: Optional[str] = Field(default=None, sa_column=Column(Text))
    # Free-form analyst metadata: tags for triage + a private note.
    tags: list = Field(default_factory=list, sa_column=Column(JSON))
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    # Stable identity for re-import de-duplication (e.g. nuclei template+URL).
    fingerprint: Optional[str] = Field(default=None, index=True)
    # Parser rule/template identity (nuclei template-id, BBOT finding name).
    # Used for per-rule severity overrides and filtering.
    rule_id: Optional[str] = Field(default=None, index=True)
    source_tool: Optional[str] = None
    # Analyst triage vocabulary shared with Entity: "none" | "confirmed" |
    # "needs-review" | "false-positive". ``status`` stays the workflow state
    # (open/in-progress/resolved/wont-fix); the compatibility layer derives
    # Leadline's triage_status from both fields.
    verdict: str = Field(default="none", index=True)
    # Import/provenance metadata (Leadline IDs, extra_data, original location).
    meta: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: Optional[datetime] = None


class AppState(SQLModel, table=True):
    """Singleton row (id=1) for schema and operational state.

    ``maintenance`` stops native workers from claiming jobs while a backup,
    restore, or migration is in progress. The schema version is written by
    ``init_db`` so an old file can be identified without guessing from columns.
    """

    __tablename__ = "appstate"

    id: Optional[int] = Field(default=None, primary_key=True)
    schema_version: int = 1
    maintenance: bool = False
    maintenance_reason: str = ""
    updated_at: datetime = Field(default_factory=_utcnow)


class ScanJob(SQLModel, table=True):
    """A durable scan request.

    External runners may still claim jobs through the API (the original
    import-first workflow). Native collectors are claimed by ``app.jobs``,
    which adds leases, attempts, cancellation and crash recovery.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    # Optional target attribution resolved before the collector runs. Keeping
    # it on the job lets snapshots and history stay stable even when a target
    # is renamed later.
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    runner: str = Field(index=True)
    target: str = ""
    status: str = Field(default="queued", index=True)
    header_profile_id: Optional[int] = Field(default=None, foreign_key="headerprofile.id")
    # Collector options (ports, paths, subdomains, ...). External runners can
    # use this as a free-form job description too.
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    priority: int = 0
    attempts: int = 0
    max_attempts: int = 3
    next_run_at: Optional[datetime] = None
    lease_owner: Optional[str] = None
    lease_expires_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    cancel_requested: bool = False
    output_paste_id: Optional[int] = None
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    log: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class JobAttempt(SQLModel, table=True):
    """One execution attempt for a job (one worker lease)."""

    __tablename__ = "jobattempt"

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: int = Field(index=True)
    attempt_no: int = 1
    worker_id: str = ""
    status: str = Field(default="running", index=True)
    started_at: datetime = Field(default_factory=_utcnow)
    heartbeat_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    output_paste_id: Optional[int] = None
    stats: dict = Field(default_factory=dict, sa_column=Column(JSON))


class ScanPhase(SQLModel, table=True):
    """One named phase inside an attempt (dns, http, headers, ...)."""

    __tablename__ = "scanphase"

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: int = Field(index=True)
    attempt_id: int = Field(index=True)
    seq: int = 0
    name: str = ""
    status: str = Field(default="running", index=True)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None
    output_paste_id: Optional[int] = None
    stats: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))


class JobEvent(SQLModel, table=True):
    """Append-only progress/audit events for a job."""

    __tablename__ = "jobevent"

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: int = Field(index=True)
    attempt_id: Optional[int] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    kind: str = Field(default="info", index=True)
    message: str = Field(default="", sa_column=Column(Text))
    data: dict = Field(default_factory=dict, sa_column=Column(JSON))


class ScanSnapshot(SQLModel, table=True):
    """Point-in-time target state captured when a job finishes.

    ``data`` is a JSON document (see ``app.history.build_snapshot``) and is
    rebuildable from the sealed captures. A snapshot failure never fails the
    job: the row is stored with ``status="pending"/"failed"`` so it can be
    regenerated later.
    """

    __tablename__ = "scansnapshot"

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: int = Field(index=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    status: str = Field(default="pending", index=True)
    risk_score: int = 0
    risk_level: str = "minimal"
    finding_count: int = 0
    data: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class HeaderProfile(SQLModel, table=True):
    """Reusable HTTP header set: randomized UA + full headers + custom overrides.

    Attach to a scan job so executors send them; or copy as curl flags for
    manual testing.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    family: str = "random"
    user_agent: str = ""
    headers: dict = Field(default_factory=dict, sa_column=Column(EncryptedJSON))
    # Outbound egress for tools using this profile (e.g. http://127.0.0.1:8080
    # or socks5://127.0.0.1:9050). Empty = direct connection.
    proxy: str = Field(default="", sa_column=Column(EncryptedText))
    # Requests-per-second hint for executors (0 = unset).
    rate_limit: float = 0.0
    created_at: datetime = Field(default_factory=_utcnow)


class CustomRunner(SQLModel, table=True):
    """User-defined runner descriptors merged with the built-in registry."""

    id: Optional[int] = Field(default=None, primary_key=True)
    runner_id: str = Field(index=True, unique=True)
    label: str = ""
    description: str = ""
    example: str = ""
    kinds: list = Field(default_factory=lambda: ["domain"], sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)


class RunnerToggle(SQLModel, table=True):
    """Activation state for built-in catalog runners (no row = default)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    runner_id: str = Field(index=True, unique=True)
    enabled: bool = True


class SavedView(SQLModel, table=True):
    """A named, local filter for the Ledger, diff or graph.

    Saved views are deliberately local rows, not share links: Breadcrumb has no
    account model and must keep working offline. ``query`` is the human-editable
    filter string; ``params`` stores structured extras (left/right selectors for
    a diff, graph options) so a view can be reopened exactly.
    """

    __tablename__ = "savedview"
    __table_args__ = (UniqueConstraint("kind", "name", name="ux_savedview_kind_name"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    kind: str = Field(default="ledger", index=True)  # ledger | diff | graph
    query: str = ""
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
