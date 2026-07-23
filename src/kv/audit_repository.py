from datetime import datetime, timezone

from src.storage.database import Database


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def log_denied_access(self, requester_email: str, target_type: str, target_identifier: str) -> None:
        """Ghi lại 1 lần truy cập bị từ chối. KHÔNG BAO GIỜ nhận/lưu secret hoặc token
        vào đây — chỉ lưu ai, cố truy cập cái gì, kết quả gì."""
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs
                    (requester_email, action, target_type, target_identifier, result, created_at)
                VALUES (?, 'ACCESS_DENIED', ?, ?, 'DENIED', ?)
                """,
                (requester_email, target_type, target_identifier, now),
            )