import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.storage.database import Database
from src.transit.exceptions import KeyAlreadyExistsError


class NamedKeyRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        owner_email: str,
        key_name: str,
        key_usage: str,
        signing_algorithm: str | None,
        nonce_b64: str,
        encrypted_key_material_b64: str,
        tag_b64: str,
        public_key_b64: str | None,
    ) -> sqlite3.Row:
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._database.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO named_keys (
                        owner_email, key_name, key_usage, signing_algorithm,
                        nonce_b64, encrypted_key_material_b64, tag_b64,
                        public_key_b64, created_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        owner_email,
                        key_name,
                        key_usage,
                        signing_algorithm,
                        nonce_b64,
                        encrypted_key_material_b64,
                        tag_b64,
                        public_key_b64,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise KeyAlreadyExistsError() from exc
        row = self.get_owned(owner_email, key_name)
        if row is None:
            raise RuntimeError("Created key could not be read")
        return row

    def get_owned(self, owner_email: str, key_name: str) -> Optional[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                "SELECT * FROM named_keys WHERE owner_email = ? AND key_name = ?",
                (owner_email, key_name),
            ).fetchone()

    def list_owned(self, owner_email: str) -> list[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                """
                SELECT key_name, key_usage, signing_algorithm, created_at, revoked_at
                FROM named_keys WHERE owner_email = ? ORDER BY key_name
                """,
                (owner_email,),
            ).fetchall()

    def revoke_owned(self, owner_email: str, key_name: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE named_keys SET revoked_at = ?
                WHERE owner_email = ? AND key_name = ? AND revoked_at IS NULL
                """,
                (now, owner_email, key_name),
            )
            return cursor.rowcount > 0
