from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text
from sqlalchemy.types import JSON
from sqlmodel import Field, SQLModel


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
    created_at: datetime = Field(default_factory=_utcnow)


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    name: str = Field(index=True)
    kind: str = "domain"
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=_utcnow)


class Paste(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
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
    created_at: datetime = Field(default_factory=_utcnow)


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
    source_tool: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: Optional[datetime] = None


class ScanJob(SQLModel, table=True):
    """Runner seam: a requested scan. No executor runs it yet (see app/runners.py).

    Runners (nmap/subfinder/nuclei wrappers) will claim queued jobs, stream
    output back as pastes, and flip status to running/done/failed.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    program_id: Optional[int] = Field(default=None, foreign_key="program.id", index=True)
    runner: str = Field(index=True)
    target: str = ""
    status: str = Field(default="queued", index=True)
    header_profile_id: Optional[int] = Field(default=None, foreign_key="headerprofile.id")
    log: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class HeaderProfile(SQLModel, table=True):
    """Reusable HTTP header set: randomized UA + full headers + custom overrides.

    Attach to a scan job so executors send them; or copy as curl flags for
    manual testing.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    family: str = "random"
    user_agent: str = ""
    headers: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # Outbound egress for tools using this profile (e.g. http://127.0.0.1:8080
    # or socks5://127.0.0.1:9050). Empty = direct connection.
    proxy: str = ""
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
