import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.auth.exceptions import DuplicateEmailError
from src.storage.database import Database


class UserRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    @staticmethod
    def normalize_email(email: str) -> str:
        return email.strip().lower()

    def get_by_email(self, email: str) -> Optional[sqlite3.Row]:
        normalized = self.normalize_email(email)
        with self._database.connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE email = ?", (normalized,))
            return cursor.fetchone()

    def create(self, email: str, password_hash: str) -> sqlite3.Row:
        normalized = self.normalize_email(email)
        now = datetime.now(timezone.utc).isoformat()

        try:
            with self._database.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users (email, password_hash, failed_attempts,
                                        locked_until, created_at, updated_at)
                    VALUES (?, ?, 0, NULL, ?, ?)
                    """,
                    (normalized, password_hash, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEmailError(normalized) from exc

        return self.get_by_email(normalized)

    def update_after_failed_login(
        self, user_id: int, failed_attempts: int, locked_until: Optional[str]
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                (failed_attempts, locked_until, now, user_id),
            )

    def reset_login_failures(self, user_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
                (now, user_id),
            )