"""Encryption at rest for header-profile secrets.

Header profiles contain reusable request headers (cookies, authorization,
tokens) and an optional proxy URL that may embed credentials. SQLite is a
plain file, so storing those values as text leaks them to every backup, copy,
or accidental commit of ``breadcrumb.db``.

The model columns use the SQLAlchemy types in this module, so the rest of the
application keeps reading and writing ordinary ``dict``/``str`` values. The
database only ever sees ``enc:v1:<fernet-token>``.

Key resolution order:

1. ``BREADCRUMB_SECRET_KEYS`` — comma-separated, newest first (rotation);
2. ``BREADCRUMB_SECRET_KEY`` — one key or passphrase;
3. ``BREADCRUMB_KEY_FILE`` — path to a key file;
4. ``<database path>.key`` — generated on first use with mode ``0600``.

An env value that is not a valid Fernet key is treated as a passphrase and
stretched with SHA-256. Use a high-entropy value; a human password is not a
substitute for a generated key.

If ciphertext exists and the key is missing, decryption raises
``SecretsError`` with a clear message instead of silently returning a broken
value. A key is never regenerated over existing ciphertext.

The local UI/API intentionally still shows the decrypted values (Breadcrumb is
a local, no-auth notebook and the curl-copy workflow depends on it). The
protection here is at rest: database files, backups, and copies of the repo.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import Text
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.types import TypeDecorator

ENCRYPTED_PREFIX = "enc:v1:"
_KEY_DOMAIN = b"breadcrumb-header-secret-v1:"


class SecretsError(RuntimeError):
    """A key is missing/invalid or ciphertext cannot be decrypted."""


class SecretsUnavailable(SecretsError):
    """The optional cryptography dependency is not installed."""


def _db_path() -> Path:
    from .db import DB_PATH

    return DB_PATH


def _key_file_path() -> Path:
    configured = os.environ.get("BREADCRUMB_KEY_FILE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(str(_db_path()) + ".key")


def _env_key_values() -> list[str]:
    multi = os.environ.get("BREADCRUMB_SECRET_KEYS", "").strip()
    if multi:
        return [part.strip() for part in multi.split(",") if part.strip()]
    single = os.environ.get("BREADCRUMB_SECRET_KEY", "").strip()
    return [single] if single else []


def _read_key_file(path: Path) -> list[str]:
    values: list[str] = []
    for candidate in (path, Path(str(path) + ".old")):
        if not candidate.exists():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise SecretsError(f"could not read secret key file {candidate}: {exc}") from exc
        values.extend(
            line.strip()
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        )
    return values


def _write_all(fd: int, payload: bytes) -> None:
    while payload:
        written = os.write(fd, payload)
        if written <= 0:  # pragma: no cover - defensive
            raise OSError("short write while saving the secret key")
        payload = payload[written:]


def _create_key_file(path: Path, key: bytes) -> bool:
    """Create the key file only if nobody else did. Returns True on success."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    except OSError as exc:
        raise SecretsError(
            f"could not create secret key file {path}: {exc}"
        ) from exc
    try:
        _write_all(fd, key + b"\n")
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:  # noqa: BLE001  (Windows / exotic filesystems)
        pass
    return True


def _write_key_lines(path: Path, keys: list[str]) -> None:
    temporary = Path(str(path) + ".new")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    except OSError as exc:
        raise SecretsError(
            f"could not write secret key file {path}: {exc}"
        ) from exc
    try:
        _write_all(fd, ("\n".join(keys) + "\n").encode("utf-8"))
        os.fsync(fd)
    except Exception:
        os.close(fd)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(fd)
    try:
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise SecretsError(
            f"could not replace secret key file {path}: {exc}"
        ) from exc
    try:
        os.chmod(path, 0o600)
    except OSError:  # noqa: BLE001  (Windows / exotic filesystems)
        pass


def _write_key_file(path: Path, key: bytes) -> None:
    _write_key_lines(path, [key.decode("utf-8")])


def _has_ciphertext() -> bool:
    """Return True when the database already contains encrypted secrets.

    A missing table means this is a fresh database and no key is needed yet.
    Any other database error must not be mistaken for "no ciphertext": that
    would generate a new key over encrypted data and strand it.
    """
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError

    from .db import engine

    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT 1 FROM headerprofile "
                    "WHERE headers LIKE :prefix OR proxy LIKE :prefix LIMIT 1"
                ),
                {"prefix": ENCRYPTED_PREFIX + "%"},
            ).first()
            return row is not None
    except OperationalError as exc:
        if "no such table" in str(exc).lower():
            return False
        raise SecretsError(
            "could not inspect header-profile secrets; refusing to generate a "
            "new key while the database is unavailable"
        ) from exc


def _key_values(*, create: bool) -> list[str]:
    values = _env_key_values()
    if values:
        return values
    path = _key_file_path()
    if path.exists():
        values = _read_key_file(path)
        if not values:
            raise SecretsError(f"secret key file {path} is empty")
        return values
    # A rotation interrupted between moving the old key aside and writing the
    # new one must not look like key loss: the previous key still decrypts.
    old = Path(str(path) + ".old")
    if old.exists():
        values = _read_key_file(old)
        if values:
            return values
    if _has_ciphertext():
        raise SecretsError(
            f"encrypted header profiles exist but no secret key was found. "
            f"Set BREADCRUMB_SECRET_KEY or restore {path}."
        )
    if not create:
        raise SecretsError(f"no secret key available (looked for {path})")
    try:
        key = Fernet.generate_key()
    except Exception as exc:  # noqa: BLE001
        raise SecretsUnavailable(
            "the 'cryptography' package is required to encrypt header profiles"
        ) from exc
    if _create_key_file(path, key):
        return [key.decode("utf-8")]
    # Another process won the create race. Read its key rather than
    # overwriting it, or fail clearly if it is still being written.
    deadline = time.monotonic() + 2.0
    while True:
        values = _read_key_file(path)
        if values:
            return values
        if time.monotonic() >= deadline:
            raise SecretsError(
                f"secret key file {path} exists but is empty; remove it and retry"
            )
        time.sleep(0.02)


def _to_fernet(value: str) -> Fernet:
    try:
        return Fernet(value.encode("utf-8"))
    except (ValueError, TypeError, binascii.Error):
        # Treat non-Fernet env values as passphrases. This keeps first-run
        # setup simple without ever storing the passphrase itself.
        digest = hashlib.sha256(_KEY_DOMAIN + value.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def _fernet(*, create: bool = True) -> MultiFernet:
    values = _key_values(create=create)
    if not values:
        raise SecretsError("no secret key configured")
    return MultiFernet([_to_fernet(value) for value in values])


def encrypt_text(value: str) -> str:
    """Encrypt one string."""
    token = _fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return ENCRYPTED_PREFIX + token


def decrypt_text(value: str) -> str:
    """Decrypt one value; legacy plaintext is returned unchanged."""
    if not value.startswith(ENCRYPTED_PREFIX):
        return value
    token = value[len(ENCRYPTED_PREFIX):].encode("ascii")
    try:
        return _fernet(create=False).decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise SecretsError(
            "could not decrypt a header-profile secret: the key is wrong or "
            "the value was modified. Restore the original key file."
        ) from exc


def redact_text(value: str | None) -> str:
    """Placeholder for logs/exports; never returns the original value."""
    return "••••••" if value else ""


def redact_values(text: str | None, values) -> str:
    """Remove known secret values (and common repr/JSON forms) from text.

    Exception messages sometimes embed header values via ``repr`` or JSON
    escaping, so replacing the literal value alone is not enough.
    """
    if not text:
        return text or ""
    variants: set[str] = set()
    for value in values or ():
        raw = str(value)
        if not raw:
            continue
        variants.update(
            variant
            for variant in (
                raw,
                repr(raw),
                json.dumps(raw),
                repr(raw.encode("utf-8")),
            )
            if len(variant) >= 4
        )
        # Multi-line header values are often rendered one line at a time by
        # the exception that rejected them.
        variants.update(
            part.strip()
            for part in re.split(r"[\r\n]+", raw)
            if len(part.strip()) >= 4
        )
    for variant in sorted(variants, key=len, reverse=True):
        text = text.replace(variant, "••••••")
    return text


def redact_headers(headers: dict | None) -> dict:
    """Keep header names, replace every value with a fixed placeholder."""
    return {str(name): "••••••" for name in (headers or {})}


def encrypt_legacy_header_profiles() -> int:
    """Encrypt rows written before the TypeDecorators existed.

    Returns the number of rows rewritten. Safe to call on every startup: only
    rows whose raw database value is still plaintext are touched.
    """
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError
    from sqlmodel import Session, select

    from .db import engine
    from .models import HeaderProfile

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT id, headers, proxy FROM headerprofile")
            ).all()
    except OperationalError as exc:
        if "no such table" in str(exc).lower():
            return 0
        raise SecretsError(
            "could not read header profiles while migrating secrets"
        ) from exc

    legacy_ids = [
        row[0]
        for row in rows
        if not str(row[1] or "").startswith(ENCRYPTED_PREFIX)
        or not str(row[2] or "").startswith(ENCRYPTED_PREFIX)
    ]
    if not legacy_ids:
        return 0

    with Session(engine) as session:
        profiles = session.exec(
            select(HeaderProfile).where(HeaderProfile.id.in_(legacy_ids))
        ).all()
        for profile in profiles:
            # Reading through the decorator gave us plaintext; assigning the
            # same values is a no-op for SQLAlchemy's change tracking, so
            # force the column dirty to rewrite it as ciphertext.
            profile.headers = dict(profile.headers or {})
            profile.proxy = profile.proxy or ""
            flag_modified(profile, "headers")
            flag_modified(profile, "proxy")
            session.add(profile)
        session.commit()
        return len(profiles)


def encrypt_legacy_header_profiles_in_file(path: str | Path) -> int:
    """Encrypt plaintext header secrets inside a standalone SQLite backup.

    ``_backup_before_migrate`` snapshots the database *before* the live rows
    are encrypted. Without this step that snapshot would keep the plaintext
    credentials the migration just removed. The backup is otherwise left
    intact and remains restorable (restoring it re-runs the normal migration).
    """
    import sqlite3

    path = Path(path)
    if not path.exists():
        return 0
    connection = sqlite3.connect(str(path), timeout=30.0)
    changed = 0
    try:
        try:
            rows = connection.execute(
                "SELECT id, headers, proxy FROM headerprofile"
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return 0
            raise
        for profile_id, headers, proxy in rows:
            new_headers = headers
            new_proxy = proxy
            if headers is not None and not str(headers).startswith(ENCRYPTED_PREFIX):
                new_headers = encrypt_text(str(headers))
            if proxy is not None and not str(proxy).startswith(ENCRYPTED_PREFIX):
                new_proxy = encrypt_text(str(proxy))
            if new_headers != headers or new_proxy != proxy:
                connection.execute(
                    "UPDATE headerprofile SET headers = ?, proxy = ? WHERE id = ?",
                    (new_headers, new_proxy, profile_id),
                )
                changed += 1
        connection.commit()
        return changed
    finally:
        connection.close()


def reencrypt_all_header_profiles() -> int:
    """Rewrite every profile with the current primary key (key rotation)."""
    from sqlmodel import Session, select

    from .db import engine
    from .models import HeaderProfile

    with Session(engine) as session:
        profiles = session.exec(select(HeaderProfile)).all()
        for profile in profiles:
            profile.headers = dict(profile.headers or {})
            profile.proxy = profile.proxy or ""
            flag_modified(profile, "headers")
            flag_modified(profile, "proxy")
            session.add(profile)
        session.commit()
        return len(profiles)


def rotate_key_file() -> tuple[Path, Path]:
    """Generate a new primary key, keeping all previous keys for decryption.

    Returns ``(key_file, old_key_file)``. Existing rows are re-encrypted with
    the new primary key before the function returns. Previous keys are merged
    into ``<key_file>.old`` rather than discarded, so a crash part-way through
    re-encryption never strands rows encrypted with an earlier key.
    """
    if _env_key_values():
        raise SecretsError(
            "key rotation is managed by BREADCRUMB_SECRET_KEY(S), not by the key file"
        )
    path = _key_file_path()
    old = Path(str(path) + ".old")
    if not path.exists() and old.exists():
        # Recover an interrupted previous rotation: reuse its primary key.
        recovered = _read_key_file(old)
        if recovered:
            _write_key_file(path, recovered[0].encode("utf-8"))
    if not path.exists():
        raise SecretsError(f"no key file to rotate at {path}")
    current = _read_key_file(path)
    if not current:
        raise SecretsError(f"secret key file {path} is empty")
    previous = _read_key_file(old) if old.exists() else []
    # Deduplicate while preserving newest-first order: current primary, any
    # older keys currently in use, then anything already archived.
    archived = list(dict.fromkeys(current + previous))
    _write_key_lines(old, archived)
    _write_key_file(path, Fernet.generate_key())
    reencrypt_all_header_profiles()
    return path, old


class EncryptedText(TypeDecorator):
    """A text column that is Fernet-encrypted on write and decrypted on read."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        return encrypt_text(str(value))

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        return decrypt_text(str(value))


class EncryptedJSON(TypeDecorator):
    """A JSON-valued column stored as encrypted text."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return encrypt_text(payload)

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        raw = decrypt_text(str(value))
        if raw.strip() in ("", "null"):
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SecretsError("encrypted header profile is not valid JSON") from exc
        return parsed if isinstance(parsed, dict) else {}
