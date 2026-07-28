import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from src.core.exceptions import StorageError


# Bumped whenever the physical schema changes in a backward-incompatible way.
# Section IV extras (KV versioning, Transit key rotation, hash-chained audit log)
# introduced version 2.
SCHEMA_VERSION = 2

DATABASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Feature 1 + section IV "KV versioning".
-- kv_records holds one row per (owner, path) and points at the newest version;
-- every historical write survives as its own row in kv_versions.
CREATE TABLE IF NOT EXISTS kv_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_email TEXT NOT NULL,
    path TEXT NOT NULL,
    latest_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_email, path)
);
CREATE INDEX IF NOT EXISTS idx_kv_owner_email ON kv_records(owner_email);

CREATE TABLE IF NOT EXISTS kv_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    tag_b64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(record_id, version),
    FOREIGN KEY (record_id) REFERENCES kv_records(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_kv_versions_record ON kv_versions(record_id);

-- Feature 2 + section IV "Key rotation for Transit".
-- named_keys holds ownership/usage metadata; key material lives in
-- named_key_versions so old ciphertext stays decryptable after a rotation.
CREATE TABLE IF NOT EXISTS named_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_email TEXT NOT NULL,
    key_name TEXT NOT NULL,
    key_usage TEXT NOT NULL CHECK (key_usage IN ('ENCRYPT_DECRYPT', 'SIGN_VERIFY')),
    signing_algorithm TEXT,
    latest_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_email, key_name)
);
CREATE INDEX IF NOT EXISTS idx_named_keys_owner_email ON named_keys(owner_email);

CREATE TABLE IF NOT EXISTS named_key_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    nonce_b64 TEXT NOT NULL,
    encrypted_key_material_b64 TEXT NOT NULL,
    tag_b64 TEXT NOT NULL,
    public_key_b64 TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(key_id, version),
    FOREIGN KEY (key_id) REFERENCES named_keys(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_named_key_versions_key ON named_key_versions(key_id);

-- Section IV "Tamper-evident audit log": every row carries the hash of the
-- previous row, so deleting or editing history breaks the chain.
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence INTEGER NOT NULL UNIQUE,
    requester_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_identifier TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_requester ON audit_logs(requester_email);
"""

# Tables whose shape changed between schema 1 and 2.
_VERSIONED_TABLES = ("kv_records", "named_keys", "audit_logs")


class LegacySchemaError(StorageError):
    """Raised when the database on disk predates the current schema."""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            self._guard_legacy_schema(connection)
            connection.executescript(DATABASE_SCHEMA)
            connection.execute(
                "INSERT OR REPLACE INTO schema_metadata (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @staticmethod
    def _guard_legacy_schema(connection: sqlite3.Connection) -> None:
        """Refuse to run against a pre-versioning database.

        Silently continuing would leave `CREATE TABLE IF NOT EXISTS` pointing at
        the old column layout, and every query would then fail at a random later
        moment. Failing fast with an actionable message is safer.
        """
        existing = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not existing & set(_VERSIONED_TABLES):
            return
        if "schema_metadata" in existing:
            row = connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is not None and int(row["value"]) >= SCHEMA_VERSION:
                return
        raise LegacySchemaError(
            "The database was created by an older Mini Vault schema. "
            "Run reset_runtime_data_cmd.bat (or delete data/mini_vault.db and "
            "data/vault_config.json) and initialize the Vault again."
        )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def exclusive_connection(self) -> Iterator[sqlite3.Connection]:
        """Serialized transaction, used where read-then-write must be atomic.

        The audit hash chain reads the previous entry_hash and immediately
        writes the next row; two concurrent writers must not observe the same
        predecessor, otherwise the chain forks.
        """
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
