import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from src.audit.chain import GENESIS_HASH, compute_entry_hash, verify_chain
from src.storage.database import Database


HEAD_KEY = "audit_chain_head"

# Audit entries only ever carry identifiers (email, KV path, key name) and a
# result. Secrets, passphrases, tokens, DEK and key material are never passed in.
ACCESS_DENIED = "ACCESS_DENIED"


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
        """Append one entry, linked to the current head of the chain.

        Read-then-write runs inside a single BEGIN IMMEDIATE transaction so two
        concurrent requests cannot both read the same predecessor and fork the
        chain.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._database.exclusive_connection() as conn:
            head = conn.execute(
                "SELECT sequence, entry_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if head is None else int(head["sequence"]) + 1
            prev_hash = GENESIS_HASH if head is None else head["entry_hash"]

            entry = {
                "sequence": sequence,
                "requester_email": requester_email,
                "action": action,
                "target_type": target_type,
                "target_identifier": target_identifier,
                "result": result,
                "created_at": now,
            }
            entry_hash = compute_entry_hash(prev_hash, entry)

            conn.execute(
                """
                INSERT INTO audit_logs (
                    sequence, requester_email, action, target_type,
                    target_identifier, result, created_at, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    requester_email,
                    action,
                    target_type,
                    target_identifier,
                    result,
                    now,
                    prev_hash,
                    entry_hash,
                ),
            )
            # Storing the head outside audit_logs is what makes deleting the
            # tail of the log detectable.
            conn.execute(
                "INSERT OR REPLACE INTO schema_metadata (key, value) VALUES (?, ?)",
                (HEAD_KEY, entry_hash),
            )

    def log_denied_access(
        self, requester_email: str, target_type: str, target_identifier: str
    ) -> None:
        self.log(requester_email, ACCESS_DENIED, target_type, target_identifier, "DENIED")

    def list_for_requester(self, requester_email: str, limit: int = 100) -> list[sqlite3.Row]:
        """Entries raised by one caller. Users only ever see their own trail."""
        with self._database.connection() as conn:
            return conn.execute(
                """
                SELECT sequence, action, target_type, target_identifier, result, created_at
                FROM audit_logs WHERE requester_email = ?
                ORDER BY sequence DESC LIMIT ?
                """,
                (requester_email, limit),
            ).fetchall()

    def stored_head(self) -> Optional[str]:
        with self._database.connection() as conn:
            row = conn.execute(
                "SELECT value FROM schema_metadata WHERE key = ?", (HEAD_KEY,)
            ).fetchone()
        return None if row is None else row["value"]

    def verify(self) -> dict[str, Any]:
        """Recompute the whole chain and compare it with the stored head."""
        with self._database.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY sequence ASC"
            ).fetchall()
        stored = self.stored_head()
        # An empty log has no stored head yet; that is a valid initial state.
        expected = stored if rows else None
        return verify_chain(rows, expected)
