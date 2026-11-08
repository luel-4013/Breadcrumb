import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import event, inspect, text
from sqlmodel import Session, SQLModel, create_engine

DB_PATH = Path(
    os.environ.get("BREADCRUMB_DB_PATH", Path(__file__).resolve().parent.parent / "breadcrumb.db")
)

# Bump when a migration changes the on-disk contract. The value is recorded in
# appstate so backups/restores and future migrations can be versioned
# explicitly instead of inferred from column presence.
SCHEMA_VERSION = 4

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False, "timeout": 30.0},
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    """Set the SQLite safety/concurrency pragmas on every connection.

    WAL lets readers continue while one writer holds the write lock. The busy
    timeout makes a second writer wait instead of failing immediately. Foreign
    keys are off by default in SQLite, so turn them on explicitly.
    """
    cursor = dbapi_connection.cursor()
    try:
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            # Read-only filesystems and `:memory:` do not support WAL.
            pass
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
        # Zero old cell contents when rows are updated/deleted. The secrets
        # migration rewrites plaintext rows in place; without this SQLite may
        # leave the old text in free pages of the database file.
        cursor.execute("PRAGMA secure_delete=ON")
    finally:
        cursor.close()


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
    "target": {
        "meta": "TEXT DEFAULT '{}'",
    },
    "paste": {
        "ai_analysis": "TEXT",
        "ai_model": "TEXT",
        "ai_at": "DATETIME",
        "parse_errors": "TEXT DEFAULT '[]'",
        "content_sha256": "TEXT",
        "chain_hash": "TEXT",
        "prev_paste_id": "INTEGER",
        "chain_seq": "INTEGER",
        "capture_key": "TEXT",
        "job_id": "INTEGER",
        "attempt_id": "INTEGER",
        "phase": "TEXT",
    },
    "scanjob": {
        "target_id": "INTEGER",
        "header_profile_id": "INTEGER",
        "started_at": "DATETIME",
        "params": "TEXT DEFAULT '{}'",
        "priority": "INTEGER DEFAULT 0",
        "attempts": "INTEGER DEFAULT 0",
        "max_attempts": "INTEGER DEFAULT 3",
        "next_run_at": "DATETIME",
        "lease_owner": "TEXT",
        "lease_expires_at": "DATETIME",
        "heartbeat_at": "DATETIME",
        "cancel_requested": "INTEGER DEFAULT 0",
        "output_paste_id": "INTEGER",
        "error": "TEXT",
    },
    "finding": {
        "tags": "TEXT DEFAULT '[]'",
        "notes": "TEXT",
        "updated_at": "DATETIME",
        "fingerprint": "TEXT",
        "source_tool": "TEXT",
        "paste_id": "INTEGER",
        "verdict": "TEXT DEFAULT 'none'",
        "meta": "TEXT DEFAULT '{}'",
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
    ("ix_paste_job", "paste (job_id)"),
    ("ix_paste_phase", "paste (phase)"),
    ("ix_jobattempt_job", "jobattempt (job_id, attempt_no)"),
    ("ix_scanphase_job", "scanphase (job_id, seq)"),
    ("ix_jobevent_job", "jobevent (job_id, id)"),
    ("ix_finding_verdict", "finding (verdict)"),
    ("ix_scanjob_target", "scanjob (target_id)"),
    ("ix_scansnapshot_job", "scansnapshot (job_id)"),
    ("ix_scansnapshot_target", "scansnapshot (target_id, id)"),
    ("ix_scansnapshot_program", "scansnapshot (program_id, id)"),
]

# A linear hash chain means each capture has at most one successor. These
# partial unique indexes turn a concurrent fork into a database error instead
# of a silently branched chain. `capture_key` is reserved for Phase 1's
# idempotent worker delivery; it is nullable and unused by the current UI.
UNIQUE_INDEXES = [
    ("ux_paste_prev", "paste (prev_paste_id) WHERE prev_paste_id IS NOT NULL"),
    ("ux_paste_chain_seq", "paste (chain_seq) WHERE chain_seq IS NOT NULL"),
    ("ux_paste_capture_key", "paste (capture_key) WHERE capture_key IS NOT NULL"),
    ("ux_scansnapshot_job", "scansnapshot (job_id) WHERE job_id IS NOT NULL"),
]


def _backup_disabled() -> bool:
    return os.environ.get("BREADCRUMB_SKIP_BACKUP", "") in ("1", "true", "yes", "on")


def _sqlite_integrity(conn: sqlite3.Connection) -> None:
    row = conn.execute("PRAGMA integrity_check").fetchone()
    if not row or row[0] != "ok":
        raise sqlite3.DatabaseError(f"SQLite integrity check failed: {row}")


def backup_database(dest: str | Path) -> Path:
    """Write a consistent snapshot of the live DB to ``dest``.

    A raw file copy is unsafe with WAL: the ``-wal`` file may hold committed
    pages that are not in the main file yet. SQLite's online backup API takes
    a transactionally consistent snapshot without stopping readers. The copy
    is integrity-checked and atomically renamed into place.
    """
    dest = Path(dest)
    if not DB_PATH.exists():
        raise FileNotFoundError(f"database does not exist: {DB_PATH}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp-{os.getpid()}")
    try:
        src = sqlite3.connect(str(DB_PATH), timeout=30.0)
        try:
            dst = sqlite3.connect(str(tmp))
            try:
                src.backup(dst)
                _sqlite_integrity(dst)
            finally:
                dst.close()
        finally:
            src.close()
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # noqa: BLE001  (Windows / exotic filesystems)
            pass
        os.replace(tmp, dest)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    return dest


def restore_database(source: str | Path) -> Path | None:
    """Replace the live DB with a validated snapshot.

    The uploaded/selected file is copied into a staging file in the database
    directory, validated, and only then atomically renamed over ``DB_PATH``.
    A safety backup of the current DB is written first (unless disabled).
    Returns the safety-backup path, if one was written.
    """
    source = Path(source)
    staging = DB_PATH.with_name(f".{DB_PATH.name}.restore-{os.getpid()}")
    try:
        src = sqlite3.connect(str(source), timeout=30.0)
        try:
            dst = sqlite3.connect(str(staging))
            try:
                src.backup(dst)
                _sqlite_integrity(dst)
                tables = {
                    row[0]
                    for row in dst.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                if not {"program", "entity", "paste"} <= tables:
                    raise ValueError("Not a Breadcrumb database")
            finally:
                dst.close()
        finally:
            src.close()
        safety = None
        if DB_PATH.exists() and DB_PATH.stat().st_size > 0 and not _backup_disabled():
            safety = _backup_before_migrate()
        engine.dispose()
        os.replace(staging, DB_PATH)
        for suffix in ("-wal", "-shm"):
            Path(f"{DB_PATH}{suffix}").unlink(missing_ok=True)
        init_db()
        return safety
    finally:
        staging.unlink(missing_ok=True)


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


def _chain_needs_backfill(conn) -> bool:
    tables = {
        row[0]
        for row in conn.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if "paste" not in tables:
        return False
    if conn.exec_driver_sql(
        "SELECT 1 FROM paste WHERE chain_hash IS NOT NULL AND chain_seq IS NULL LIMIT 1"
    ).first():
        return True
    if conn.exec_driver_sql(
        "SELECT 1 FROM paste WHERE chain_hash IS NULL AND chain_seq IS NOT NULL LIMIT 1"
    ).first():
        return True
    if "evidencechain" in tables:
        if not conn.exec_driver_sql(
            "SELECT 1 FROM evidencechain WHERE id=1"
        ).first():
            return True
    return False


def _secrets_need_migration(inspector) -> bool:
    """True when header profiles still hold plaintext secrets on disk."""
    if "headerprofile" not in set(inspector.get_table_names()):
        return False
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT 1 FROM headerprofile "
                    "WHERE COALESCE(headers, '') NOT LIKE 'enc:v1:%' "
                    "OR COALESCE(proxy, '') NOT LIKE 'enc:v1:%' LIMIT 1"
                )
            ).first()
        return row is not None
    except Exception as exc:  # noqa: BLE001  (pre-create_all / locked file)
        # A missing table is a fresh database. Any other failure must not be
        # read as "nothing to migrate": return True so init_db() takes a
        # rollback snapshot before touching secrets (and fails if it cannot).
        return "no such table" not in str(exc).lower()


def _upgrade_needed(inspector) -> bool:
    """True when init_db() will change an existing database.

    Used to take exactly one rollback snapshot before the first change of a
    run, rather than copying the file on every boot.
    """
    tables = set(inspector.get_table_names())
    if not tables:
        return False
    if set(SQLModel.metadata.tables) - tables:
        return True
    if _pending_migrations(inspector):
        return True
    if _secrets_need_migration(inspector):
        return True
    with engine.connect() as conn:
        if _chain_needs_backfill(conn):
            return True
    return False


def _backup_before_migrate() -> Path | None:
    """Snapshot the DB before the first schema/data change of a run.

    Migration safety (the DefectDojo boot-failure class): never alter a
    user's database without a rollback point. Skippable via
    BREADCRUMB_SKIP_BACKUP=1, which tests use for disposable databases.
    """
    if _backup_disabled():
        return None
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = DB_PATH.with_suffix(DB_PATH.suffix + f".pre-migrate-{stamp}.bak")
    try:
        return backup_database(dest)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"could not back up database before migration: {exc}") from exc


def _has_duplicates(conn, table: str, column: str) -> bool:
    row = conn.execute(
        text(
            f"SELECT 1 FROM {table} WHERE {column} IS NOT NULL "
            f"GROUP BY {column} HAVING COUNT(*) > 1 LIMIT 1"
        )
    ).first()
    return row is not None


def _backfill_chain() -> None:
    """Give legacy sealed captures a linear sequence and seed the chain head.

    Existing ``chain_hash`` values are never recomputed: the formula and the
    old captures must stay verifiable. Only the ordering column, the chain
    head row, and its length are derived. Unsealed legacy captures stay out of
    the chain.
    """
    with engine.begin() as conn:
        tables = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "paste" not in tables or "evidencechain" not in tables:
            return
        rows = conn.exec_driver_sql(
            "SELECT id, chain_hash, chain_seq FROM paste ORDER BY id"
        ).fetchall()
        sealed = [(row[0], row[2]) for row in rows if row[1]]
        unsealed_with_seq = any(row[2] is not None for row in rows if not row[1])
        needs_seq = any(seq is None for _, seq in sealed) or unsealed_with_seq
        if needs_seq:
            # A partially migrated file may already have the unique index.
            conn.exec_driver_sql("DROP INDEX IF EXISTS ux_paste_chain_seq")
            conn.exec_driver_sql("UPDATE paste SET chain_seq = NULL")
            conn.exec_driver_sql(
                "UPDATE paste SET chain_seq = ? WHERE id = ?",
                [(seq, paste_id) for seq, (paste_id, _) in enumerate(sealed, 1)],
            )
        head_id = sealed[-1][0] if sealed else None
        length = len(sealed)
        has_head = conn.exec_driver_sql(
            "SELECT 1 FROM evidencechain WHERE id=1"
        ).first()
        if needs_seq or not has_head:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            if has_head:
                conn.execute(
                    text(
                        "UPDATE evidencechain SET head_paste_id=:head, "
                        "length=:length, updated_at=:stamp WHERE id=1"
                    ),
                    {"head": head_id, "length": length, "stamp": stamp},
                )
            else:
                conn.execute(
                    text(
                        "INSERT INTO evidencechain (id, head_paste_id, length, updated_at) "
                        "VALUES (1, :head, :length, :stamp)"
                    ),
                    {"head": head_id, "length": length, "stamp": stamp},
                )


def _migrate() -> None:
    inspector = inspect(engine)
    pending = _pending_migrations(inspector)
    tables = set(inspector.get_table_names())
    if pending:
        with engine.begin() as conn:
            for table, name, ddl in pending:
                if table in tables:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
    # Sequence/head backfill must happen before the unique indexes are built.
    _backfill_chain()
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for index_name, target in INDEXES:
            table = target.split(" ")[0]
            if table in tables:
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {target}"))
        for index_name, target in UNIQUE_INDEXES:
            table = target.split(" ")[0]
            if table not in tables:
                continue
            column = target.split("(")[1].split(")")[0].strip()
            if _has_duplicates(conn, table, column):
                print(
                    f"breadcrumb: {index_name} not created: duplicate {column} "
                    "values already exist; run /api/v1/verify and repair the chain",
                    file=sys.stderr,
                )
                continue
            conn.execute(
                text(f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {target}")
            )


def begin_immediate(session: Session) -> None:
    """Start a write transaction that takes SQLite's RESERVED lock now.

    Used by the evidence chain and the job queue. Two writers must not read
    the same head/candidate and then write siblings. ``BEGIN IMMEDIATE`` makes
    the second writer wait (busy timeout) instead of forking.
    """
    if session.in_transaction():
        session.commit()
    session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def ensure_app_state() -> None:
    """Create/update the singleton appstate row after the schema exists."""
    from .models import AppState

    with Session(engine) as session:
        state = session.get(AppState, 1)
        if state is None:
            state = AppState(id=1, schema_version=SCHEMA_VERSION)
        else:
            state.schema_version = SCHEMA_VERSION
        state.updated_at = datetime.now(timezone.utc)
        session.add(state)
        session.commit()


def get_app_state(session: Session | None = None):
    """Return the appstate row, creating it if an old file lacks one."""
    from .models import AppState

    own = session is None
    session = session or Session(engine)
    try:
        state = session.get(AppState, 1)
        if state is None:
            state = AppState(id=1, schema_version=SCHEMA_VERSION)
            session.add(state)
            session.commit()
            session.refresh(state)
        return state
    finally:
        if own:
            session.close()


def set_maintenance(enabled: bool, reason: str = "") -> None:
    """Turn maintenance mode on/off; workers refuse to claim while it is on."""
    from .models import AppState

    init_db()
    with Session(engine) as session:
        state = session.get(AppState, 1)
        if state is None:
            state = AppState(id=1, schema_version=SCHEMA_VERSION)
        state.maintenance = bool(enabled)
        state.maintenance_reason = reason.strip()
        state.updated_at = datetime.now(timezone.utc)
        session.add(state)
        session.commit()


def _compact_after_secret_migration() -> None:
    """Best-effort rewrite/checkpoint so plaintext is not left in free pages.

    ``secure_delete`` covers new writes, but a database that was written
    before WAL/secure-delete was enabled can still hold old plaintext pages in
    the main file or the WAL. VACUUM rewrites the file and truncating the WAL
    removes stale frames. Failures are non-fatal: encryption already succeeded.
    """
    connection = None
    try:
        connection = sqlite3.connect(str(DB_PATH), timeout=30.0)
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("VACUUM")
    except Exception:  # noqa: BLE001  (compaction is best-effort)
        pass
    finally:
        if connection is not None:
            connection.close()


def init_db() -> None:
    from . import models  # noqa: F401  (ensure models are registered)

    backup_path = None
    if DB_PATH.exists() and DB_PATH.stat().st_size > 0:
        inspector = inspect(engine)
        if _upgrade_needed(inspector):
            backup_path = _backup_before_migrate()
    SQLModel.metadata.create_all(engine)
    _migrate()
    ensure_app_state()
    # Header profiles written before encryption existed are still plaintext in
    # the file. Rewrite them in place; safe/idempotent on every startup.
    from .secrets_store import (
        encrypt_legacy_header_profiles,
        encrypt_legacy_header_profiles_in_file,
    )

    migrated = encrypt_legacy_header_profiles()
    scrubbed = 0
    if backup_path is not None:
        # The pre-migration snapshot may still hold plaintext. Scrub it even
        # if another process already encrypted the live rows.
        try:
            scrubbed = encrypt_legacy_header_profiles_in_file(backup_path)
        except Exception as exc:  # noqa: BLE001
            try:
                backup_path.unlink(missing_ok=True)
            except OSError:
                pass
            print(
                f"breadcrumb: removed pre-migration backup {backup_path}: "
                f"could not encrypt its header secrets ({exc})",
                file=sys.stderr,
            )
    if migrated or scrubbed:
        _compact_after_secret_migration()


def get_session():
    with Session(engine) as session:
        yield session
