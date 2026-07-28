import sqlite3
from datetime import datetime, timezone
from typing import Callable, Optional

from src.storage.database import Database


# Returns (nonce_b64, ciphertext_b64, tag_b64) for the version number it is given.
EncryptForVersion = Callable[[int], tuple[str, str, str]]


class KvRepository:
    """Storage for Feature 1, extended with version history (section IV).

    `kv_records` is the per-path pointer, `kv_versions` is the append-only
    history. Nothing about the mandatory contract changes: a read without an
    explicit version always resolves to `latest_version`.
    """

    def __init__(self, database: Database) -> None:
        self._database = database

    def append_version(
        self, owner_email: str, path: str, encrypt: EncryptForVersion
    ) -> dict:
        """Allocate the next version and store the ciphertext produced for it.

        The version number is part of the AEAD associated data, so the caller
        cannot encrypt before knowing it. Allocation and insertion therefore run
        inside one serialized transaction with `encrypt` invoked in between:
        two concurrent writes can never be handed the same version number.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._database.exclusive_connection() as conn:
            record = conn.execute(
                "SELECT id, latest_version, created_at FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            ).fetchone()

            if record is None:
                version = 1
                cursor = conn.execute(
                    """
                    INSERT INTO kv_records (
                        owner_email, path, latest_version, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (owner_email, path, version, now, now),
                )
                record_id = int(cursor.lastrowid)
                created_at = now
            else:
                record_id = int(record["id"])
                version = int(record["latest_version"]) + 1
                created_at = record["created_at"]
                conn.execute(
                    "UPDATE kv_records SET latest_version = ?, updated_at = ? WHERE id = ?",
                    (version, now, record_id),
                )

            nonce_b64, ciphertext_b64, tag_b64 = encrypt(version)
            conn.execute(
                """
                INSERT INTO kv_versions (
                    record_id, version, nonce_b64, ciphertext_b64, tag_b64, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (record_id, version, nonce_b64, ciphertext_b64, tag_b64, now),
            )

        return {"created_at": created_at, "updated_at": now, "version": version}

    def get_version(
        self, owner_email: str, path: str, version: Optional[int] = None
    ) -> Optional[sqlite3.Row]:
        """Fetch one version; `None` means the current one."""
        with self._database.connection() as conn:
            if version is None:
                return conn.execute(
                    """
                    SELECT v.*, r.latest_version
                    FROM kv_records r JOIN kv_versions v ON v.record_id = r.id
                    WHERE r.owner_email = ? AND r.path = ? AND v.version = r.latest_version
                    """,
                    (owner_email, path),
                ).fetchone()
            return conn.execute(
                """
                SELECT v.*, r.latest_version
                FROM kv_records r JOIN kv_versions v ON v.record_id = r.id
                WHERE r.owner_email = ? AND r.path = ? AND v.version = ?
                """,
                (owner_email, path, version),
            ).fetchone()

    def list_versions(self, owner_email: str, path: str) -> list[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                """
                SELECT v.version, v.created_at, r.latest_version
                FROM kv_records r JOIN kv_versions v ON v.record_id = r.id
                WHERE r.owner_email = ? AND r.path = ?
                ORDER BY v.version ASC
                """,
                (owner_email, path),
            ).fetchall()

    def delete(self, owner_email: str, path: str) -> bool:
        """Permanently remove the path and its whole history (Feature 1.1.5)."""
        with self._database.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            )
            return cursor.rowcount > 0
