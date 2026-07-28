from typing import Optional

from pydantic import BaseModel


class AuditEntry(BaseModel):
    sequence: int
    action: str
    target_type: str
    target_identifier: str
    result: str
    created_at: str


class AuditListResponse(BaseModel):
    entries: list[AuditEntry]


class AuditVerifyResponse(BaseModel):
    """Result of recomputing the hash chain (section IV)."""

    valid: bool
    entry_count: int
    head_hash: str
    # Sequence number of the first entry that failed, when the failure is
    # localized to a row.
    first_invalid_sequence: Optional[int]
    # ENTRY_HASH_MISMATCH | PREV_HASH_MISMATCH | SEQUENCE_GAP | HEAD_MISMATCH
    reason: Optional[str]
