import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

DB_PATH = Path(
    os.environ.get("BREADCRUMB_DB_PATH", Path(__file__).resolve().parent.parent / "breadcrumb.db")
)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)

# Columns added after the initial schema, so existing databases keep working.
# SQLModel's create_all() never alters an existing table, so we top it up.
MIGRATIONS = {
    "entity": {
        "scope_status": "TEXT DEFAULT 'unknown'",
        "occurrences": "INTEGER DEFAULT 1",
        "provenance": "TEXT DEFAULT '[]'",
        "ignored": "INTEGER DEFAULT 0",
        "verdict": "TEXT DEFAULT 'none'",
        "tags": "TEXT DEFAULT '[]'",
        "notes": "TEXT",
        "cross_programs": "TEXT DEFAULT '[]'",
    },
    "relationship": {
        "target_id": "INTEGER",
        "src_entity_id": "INTEGER",
        "dst_entity_id": "INTEGER",
        "confidence": "FLOAT DEFAULT 1.0",
        "source": "TEXT DEFAULT 'parser'",
        "meta": "TEXT DEFAULT '{}'",
    },
    "program": {
        "ai_summary": "TEXT",
        "ai_model": "TEXT",
        "ai_at": "DATETIME",
    },
    "paste": {
        "ai_analysis": "TEXT",
        "ai_model": "TEXT",
        "ai_at": "DATETIME",
        "parse_errors": "TEXT DEFAULT '[]'",
        "content_sha256": "TEXT",
        "chain_hash": "TEXT",
        "prev_paste_id": "INTEGER",
    },
    "scanjob": {
        "header_profile_id": "INTEGER",
        "started_at": "DATETIME",
    },
    "finding": {
        "tags": "TEXT DEFAULT '[]'",
        "notes": "TEXT",
        "updated_at": "DATETIME",
        "fingerprint": "TEXT",
        "source_tool": "TEXT",
        "paste_id": "INTEGER",
    },
    "headerprofile": {
        "proxy": "TEXT DEFAULT ''",
        "rate_limit": "FLOAT DEFAULT 0.0",
    },
}

# Indexes for the queries the UI/API run on every page. Created idempotently
# so large datasets (100k+ entities) stay responsive without a rebuild.
INDEXES = [
    ("ix_entity_program_type", "entity (program_id, type)"),
    ("ix_entity_program_ignored", "entity (program_id, ignored)"),
    ("ix_entity_verdict", "entity (verdict)"),
    ("ix_entity_scope_status", "entity (scope_status)"),
    ("ix_entity_type_normalized", "entity (type, normalized)"),
    ("ix_relationship_program", "relationship (program_id)"),
    ("ix_finding_program", "finding (program_id)"),
    ("ix_finding_fingerprint", "finding (fingerprint)"),
    ("ix_paste_program", "paste (program_id)"),
]


def _pending_migrations(inspector) -> list[tuple[str, str, str]]:
    """Return [(table, column, ddl)] that are still missing from the file."""
    tables = set(inspector.get_table_names())
    pending: list[tuple[str, str, str]] = []
    for table, columns in MIGRATIONS.items():
        if table not in tables:
            continue
        existing = {col["name"] for col in inspector.get_columns(table)}
        for name, ddl in columns.items():
            if name not in existing:
                pending.append((table, name, ddl))
    return pending


def _backup_before_migrate() -> Path | None:
    """Copy the DB aside before the first schema change of a run.

    Migration safety (the DefectDojo boot-failure class): never alter a
    user's database without a rollback point. Skippable via
    BREADCRUMB_SKIP_BACKUP=1.
    """
    if os.environ.get("BREADCRUMB_SKIP_BACKUP", "") in ("1", "true", "yes", "on"):
        return None
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = DB_PATH.with_suffix(DB_PATH.suffix + f".pre-migrate-{stamp}.bak")
    try:
        shutil.copy2(DB_PATH, dest)
        return dest
    except OSError:
        return None


def _migrate() -> None:
    inspector = inspect(engine)
    pending = _pending_migrations(inspector)
    if pending:
        _backup_before_migrate()
    tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, name, ddl in pending:
            if table in tables:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        for index_name, target in INDEXES:
            table = target.split(" ")[0]
            if table in tables:
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {target}"))


def init_db() -> None:
    from . import models  # noqa: F401  (ensure models are registered)

    SQLModel.metadata.create_all(engine)
    _migrate()


def get_session():
    with Session(engine) as session:
        yield session
