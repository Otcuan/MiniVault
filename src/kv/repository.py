import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.storage.database import Database


class KvRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def upsert(
        self, owner_email: str, path: str, nonce_b64: str, ciphertext_b64: str, tag_b64: str
    ) -> dict:
        """Ghi mới hoặc ghi đè trực tiếp (không giữ version cũ) — dùng UPSERT
        nguyên tử của SQLite thay vì tự đọc-rồi-ghi, để tránh race condition
        khi 2 request cùng ghi 1 path đồng thời."""
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO kv_records
                    (owner_email, path, nonce_b64, ciphertext_b64, tag_b64, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_email, path) DO UPDATE SET
                    nonce_b64 = excluded.nonce_b64,
                    ciphertext_b64 = excluded.ciphertext_b64,
                    tag_b64 = excluded.tag_b64,
                    updated_at = excluded.updated_at
                """,
                (owner_email, path, nonce_b64, ciphertext_b64, tag_b64, now, now),
            )
            row = conn.execute(
                "SELECT created_at, updated_at FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            ).fetchone()

        return {"created_at": row["created_at"], "updated_at": row["updated_at"]}

    def get(self, owner_email: str, path: str) -> Optional[sqlite3.Row]:
        with self._database.connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            )
            return cursor.fetchone()

    def delete(self, owner_email: str, path: str) -> bool:
        with self._database.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            )
            return cursor.rowcount > 0