"""Header-profile secrets: encryption at rest, migration, rotation, redaction."""

import json
import sqlite3
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlmodel import Session, SQLModel, select

from app import cli, secrets_store
from app.models import HeaderProfile


@pytest.fixture()
def secrets_db(tmp_path, monkeypatch):
    """Isolated database + key file, independent of the shared test engine."""
    import app.db as dbmod

    path = tmp_path / "secrets.db"
    engine = create_engine(
        f"sqlite:///{path}", connect_args={"check_same_thread": False}
    )
    monkeypatch.setattr(dbmod, "DB_PATH", path)
    monkeypatch.setattr(dbmod, "engine", engine)
    monkeypatch.setenv("BREADCRUMB_KEY_FILE", str(tmp_path / "secrets.key"))
    monkeypatch.delenv("BREADCRUMB_SECRET_KEY", raising=False)
    monkeypatch.delenv("BREADCRUMB_SECRET_KEYS", raising=False)
    SQLModel.metadata.create_all(engine)
    try:
        yield engine, path, tmp_path / "secrets.key"
    finally:
        engine.dispose()


def _create_profile(engine, secret: str = "") -> int:
    secret = secret or f"Bearer {uuid.uuid4().hex}"
    with Session(engine) as session:
        profile = HeaderProfile(
            name=f"enc-{uuid.uuid4().hex[:8]}",
            family="curl-minimal",
            user_agent="test-agent",
            headers={"Authorization": secret, "X-Test": "yes"},
            proxy="http://user:pass@127.0.0.1:8080",
            rate_limit=1.0,
        )
        session.add(profile)
        session.commit()
        session.refresh(profile)
        assert profile.id is not None
        return profile.id


def test_header_profile_round_trip_is_encrypted_at_rest(secrets_db):
    engine, path, _key_file = secrets_db
    secret = f"Bearer {uuid.uuid4().hex}"
    profile_id = _create_profile(engine, secret)

    with engine.connect() as conn:
        raw = conn.execute(
            text("SELECT headers, proxy FROM headerprofile WHERE id = :id"),
            {"id": profile_id},
        ).one()
    assert raw[0].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert raw[1].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert secret not in raw[0]
    assert b"user:pass" not in path.read_bytes()

    with Session(engine) as session:
        profile = session.get(HeaderProfile, profile_id)
        assert profile.headers["Authorization"] == secret
        assert profile.headers["X-Test"] == "yes"
        assert profile.proxy == "http://user:pass@127.0.0.1:8080"


def test_legacy_plaintext_rows_are_migrated_and_migration_is_idempotent(secrets_db):
    engine, _path, _key_file = secrets_db
    secret = f"legacy-{uuid.uuid4().hex}"
    headers = json.dumps({"Authorization": secret, "X-Legacy": "1"})
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO headerprofile "
                "(name, family, user_agent, headers, proxy, rate_limit, created_at) "
                "VALUES (:name, 'random', 'old-agent', :headers, :proxy, 0, :created)"
            ),
            {
                "name": "legacy-profile",
                "headers": headers,
                "proxy": "socks5://127.0.0.1:9050",
                "created": "2026-01-01 00:00:00",
            },
        )

    assert secrets_store.encrypt_legacy_header_profiles() == 1
    assert secrets_store.encrypt_legacy_header_profiles() == 0

    with engine.connect() as conn:
        raw = conn.execute(
            text(
                "SELECT headers, proxy FROM headerprofile "
                "WHERE name = 'legacy-profile'"
            )
        ).one()
    assert raw[0].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert raw[1].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert secret not in raw[0]

    with Session(engine) as session:
        profile = session.exec(
            select(HeaderProfile).where(HeaderProfile.name == "legacy-profile")
        ).one()
        assert profile.headers["Authorization"] == secret
        assert profile.headers["X-Legacy"] == "1"
        assert profile.proxy == "socks5://127.0.0.1:9050"


def test_missing_key_over_ciphertext_fails_closed(secrets_db):
    engine, _path, key_file = secrets_db
    profile_id = _create_profile(engine)

    key_file.unlink()
    for suffix in (".old", ".new"):
        candidate = key_file.with_name(key_file.name + suffix)
        if candidate.exists():
            candidate.unlink()

    with pytest.raises(secrets_store.SecretsError, match="encrypted header profiles exist"):
        with Session(engine) as session:
            session.get(HeaderProfile, profile_id)


def test_rotation_reencrypts_rows_and_keeps_previous_key(secrets_db):
    engine, _path, key_file = secrets_db
    secret = f"rotate-{uuid.uuid4().hex}"
    profile_id = _create_profile(engine, secret)

    with engine.connect() as conn:
        before = conn.execute(
            text("SELECT headers FROM headerprofile WHERE id = :id"),
            {"id": profile_id},
        ).scalar_one()

    path, old = secrets_store.rotate_key_file()
    assert path == key_file
    assert old.exists()

    with engine.connect() as conn:
        after = conn.execute(
            text("SELECT headers FROM headerprofile WHERE id = :id"),
            {"id": profile_id},
        ).scalar_one()
    assert after != before

    # Removing the previous key proves the rows were actually rewritten with
    # the new primary key, not merely left readable through MultiFernet.
    old.unlink()
    with Session(engine) as session:
        profile = session.get(HeaderProfile, profile_id)
        assert profile.headers["Authorization"] == secret
        assert profile.proxy == "http://user:pass@127.0.0.1:8080"


def test_init_db_backs_up_and_encrypts_legacy_rows(secrets_db, monkeypatch):
    import app.db as dbmod

    engine, path, _key_file = secrets_db
    monkeypatch.delenv("BREADCRUMB_SKIP_BACKUP", raising=False)
    secret = f"startup-{uuid.uuid4().hex}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO headerprofile "
                "(name, family, user_agent, headers, proxy, rate_limit, created_at) "
                "VALUES ('old-row', 'random', 'old-agent', :headers, :proxy, 0, :created)"
            ),
            {
                "headers": json.dumps({"Authorization": secret}),
                "proxy": "http://127.0.0.1:8080",
                "created": "2026-01-01 00:00:00",
            },
        )

    dbmod.init_db()

    backups = list(path.parent.glob("*.pre-migrate-*.bak"))
    assert len(backups) == 1
    backup = backups[0]
    backup_conn = sqlite3.connect(str(backup))
    try:
        backup_raw = backup_conn.execute(
            "SELECT headers, proxy FROM headerprofile WHERE name = 'old-row'"
        ).fetchone()
    finally:
        backup_conn.close()
    assert backup_raw[0].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert backup_raw[1].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert secret.encode() not in backup.read_bytes()
    with engine.connect() as conn:
        raw = conn.execute(
            text("SELECT headers, proxy FROM headerprofile WHERE name = 'old-row'")
        ).one()
    assert raw[0].startswith(secrets_store.ENCRYPTED_PREFIX)
    assert raw[1].startswith(secrets_store.ENCRYPTED_PREFIX)
    with Session(engine) as session:
        profile = session.exec(
            select(HeaderProfile).where(HeaderProfile.name == "old-row")
        ).one()
        assert profile.headers["Authorization"] == secret
        assert profile.proxy == "http://127.0.0.1:8080"


def test_cli_secrets_rotate(secrets_db, capsys):
    engine, _path, key_file = secrets_db
    _create_profile(engine)

    assert cli.main(["secrets", "rotate"]) == 0
    assert key_file.exists()
    assert key_file.with_name(key_file.name + ".old").exists()
    assert "rotated" in capsys.readouterr().out


def test_redaction_helpers_never_return_secret_values():
    headers = {"Authorization": "Bearer very-secret", "Cookie": "session=abc"}
    redacted = secrets_store.redact_headers(headers)
    assert set(redacted) == set(headers)
    assert all(value == "••••••" for value in redacted.values())
    assert secrets_store.redact_text("secret") == "••••••"
    assert secrets_store.redact_text("") == ""
    assert secrets_store.redact_text(None) == ""
