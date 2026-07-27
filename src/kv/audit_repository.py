from datetime import datetime, timezone

from src.storage.database import Database


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def log(
        self,
        requester_email: str | None,
        action: str,
        target_type: str,
        target_identifier: str,
        result: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    requester_email, action, target_type,
                    target_identifier, result, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    requester_email,
                    action,
                    target_type,
                    target_identifier,
                    result,
                    now,
                ),
            )

    def log_denied_access(
        self, requester_email: str, target_type: str, target_identifier: str
    ) -> None:
        self.log(
            requester_email,
            "ACCESS_DENIED",
            target_type,
            target_identifier,
            "DENIED",
        )
