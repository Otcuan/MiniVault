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
        """Chỉ trả session còn hạn và chưa bị thu hồi; kèm email để dùng cho auth dependency ở bước 3."""
        with self._database.connection() as conn:
            cursor = conn.execute(
                """
                SELECT sessions.*, users.email AS user_email
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.revoked_at IS NULL
                """,
                (token_hash,),
            )
            return cursor.fetchone()