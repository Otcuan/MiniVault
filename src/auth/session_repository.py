import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.storage.database import Database


class SessionRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, user_id: int, token_hash: str, expires_at: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (user_id, token_hash, expires_at, revoked_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
                """,
                (user_id, token_hash, expires_at, now),
            )

    def find_active_by_token_hash(self, token_hash: str) -> Optional[sqlite3.Row]:
        with self._database.connection() as conn:
            return conn.execute(
                """
                SELECT sessions.*, users.email AS user_email
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.revoked_at IS NULL
                """,
                (token_hash,),
            ).fetchone()

    def revoke(self, token_hash: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            cursor = conn.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (now, token_hash),
            )
            return cursor.rowcount > 0
