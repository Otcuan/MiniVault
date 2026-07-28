import sqlite3
from datetime import datetime, timezone
from typing import Callable, Optional

from src.storage.database import Database
from src.transit.exceptions import KeyAlreadyExistsError


# Returns (nonce_b64, encrypted_key_material_b64, tag_b64, public_key_b64) for
# the version number it is given.
WrapForVersion = Callable[[int], tuple[str, str, str, Optional[str]]]


class NamedKeyRepository:
    """Storage for Feature 2 named keys, extended with rotation (section IV).

    `named_keys` holds ownership and usage metadata; each rotation appends a row
    to `named_key_versions`. Old versions are retained on purpose so ciphertext
    produced before a rotation stays decryptable.
    """

    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        owner_email: str,
        key_name: str,
        key_usage: str,
        signing_algorithm: str | None,
        wrap: WrapForVersion,
    ) -> sqlite3.Row:
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._database.exclusive_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO named_keys (
                        owner_email, key_name, key_usage, signing_algorithm,
                        latest_version, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?, ?)
                    """,
                    (owner_email, key_name, key_usage, signing_algorithm, now, now),
                )
                key_id = int(cursor.lastrowid)
                self._insert_version(conn, key_id, 1, wrap, now)
        except sqlite3.IntegrityError as exc:
            # UNIQUE(owner_email, key_name): the caller already owns this name.
            raise KeyAlreadyExistsError() from exc
        row = self.get_owned(owner_email, key_name)
        if row is None:
            raise RuntimeError("Created key could not be read")
        return row

    def rotate(
        self, owner_email: str, key_name: str, wrap: WrapForVersion
    ) -> Optional[sqlite3.Row]:
        """Append a fresh key version and make it the one used for new writes.

        Allocation and insertion share one serialized transaction because the
        version number is bound into the associated data of the wrapped key.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._database.exclusive_connection() as conn:
            row = conn.execute(
                "SELECT id, latest_version FROM named_keys WHERE owner_email = ? AND key_name = ?",
                (owner_email, key_name),
            ).fetchone()
            if row is None:
                return None
            key_id = int(row["id"])
            version = int(row["latest_version"]) + 1
            self._insert_version(conn, key_id, version, wrap, now)
            conn.execute(
                "UPDATE named_keys SET latest_version = ?, updated_at = ? WHERE id = ?",
                (version, now, key_id),
            )
        return self.get_owned(owner_email, key_name)

    @staticmethod
    def _insert_version(
        conn: sqlite3.Connection,
        key_id: int,
        version: int,
        wrap: WrapForVersion,
        now: str,
    ) -> None:
        nonce_b64, material_b64, tag_b64, public_b64 = wrap(version)
        conn.execute(
            """
            INSERT INTO named_key_versions (
                key_id, version, nonce_b64, encrypted_key_material_b64,
                tag_b64, public_key_b64, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (key_id, version, nonce_b64, material_b64, tag_b64, public_b64, now),
        )

    def get_owned(self, owner_email: str, key_name: str) -> Optional[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                "SELECT * FROM named_keys WHERE owner_email = ? AND key_name = ?",
                (owner_email, key_name),
            ).fetchone()

    def get_version(self, key_id: int, version: int) -> Optional[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                "SELECT * FROM named_key_versions WHERE key_id = ? AND version = ?",
                (key_id, version),
            ).fetchone()

    def list_versions(self, key_id: int) -> list[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                """
                SELECT version, created_at FROM named_key_versions
                WHERE key_id = ? ORDER BY version ASC
                """,
                (key_id,),
            ).fetchall()

    def list_owned(self, owner_email: str) -> list[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                """
                SELECT * FROM named_keys WHERE owner_email = ? ORDER BY key_name
                """,
                (owner_email,),
            ).fetchall()

    def delete_owned(self, owner_email: str, key_name: str) -> bool:
        """Permanently delete a named key and every version of its material.

        Section 2.1 asks revoke_key to permanently delete the key, so this is a
        hard DELETE rather than a status flag: after it runs, no wrapped key
        material for that name is left on disk.
        """
        with self._database.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM named_keys WHERE owner_email = ? AND key_name = ?",
                (owner_email, key_name),
            )
            return cursor.rowcount > 0
