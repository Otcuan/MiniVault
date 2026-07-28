"""Hash chain used by the tamper-evident audit log (section IV).

Every audit entry commits to its predecessor, so the log behaves like a tiny
append-only ledger: an attacker with write access to `data/mini_vault.db` can
still edit rows, but cannot do so without breaking the chain.

Threat model and what each defence covers:

* Editing a field of entry N        -> entry_hash(N) no longer matches -> detected.
* Deleting/reordering a middle entry -> prev_hash of entry N+1 no longer matches -> detected.
* Truncating the tail of the log     -> the recomputed head differs from the head
  hash stored outside the table (schema_metadata) -> detected.

Not covered: an attacker who can also rewrite schema_metadata can recompute a
consistent chain. Defeating that needs an append-only sink outside the database
(remote log shipping, WORM storage, or signing the head with a key held
elsewhere), which is out of scope for this assignment.
"""

import hashlib
import json
from typing import Any, Iterable, Optional


# prev_hash of the very first entry.
GENESIS_HASH = "0" * 64

# Fields committed to by entry_hash, in a fixed order.
HASHED_FIELDS = (
    "sequence",
    "requester_email",
    "action",
    "target_type",
    "target_identifier",
    "result",
    "created_at",
)


def compute_entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """SHA-256 over the previous hash plus a canonical encoding of the entry.

    Canonical JSON (sorted keys, fixed separators, no ASCII escaping) makes the
    encoding unambiguous, so two different field sets can never produce the same
    pre-image.
    """
    payload = {field: entry.get(field) for field in HASHED_FIELDS}
    canonical = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    material = f"{prev_hash}|{canonical}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_chain(
    rows: Iterable[Any],
    expected_head: Optional[str] = None,
) -> dict[str, Any]:
    """Recompute the chain and report the first entry that fails.

    `rows` must be ordered by `sequence` ascending. `expected_head` is the head
    hash persisted outside the table; supplying it is what makes tail truncation
    detectable.
    """
    prev_hash = GENESIS_HASH
    expected_sequence = 1
    count = 0

    for row in rows:
        count += 1
        entry = {field: row[field] for field in HASHED_FIELDS}

        if row["sequence"] != expected_sequence:
            return _failure(count, row["sequence"], "SEQUENCE_GAP", prev_hash)
        if row["prev_hash"] != prev_hash:
            return _failure(count, row["sequence"], "PREV_HASH_MISMATCH", prev_hash)

        recomputed = compute_entry_hash(prev_hash, entry)
        if recomputed != row["entry_hash"]:
            return _failure(count, row["sequence"], "ENTRY_HASH_MISMATCH", prev_hash)

        prev_hash = recomputed
        expected_sequence += 1

    if expected_head is not None and expected_head != prev_hash:
        # The rows that remain are internally consistent, so the log was
        # truncated from the end rather than edited in place.
        return {
            "valid": False,
            "entry_count": count,
            "head_hash": prev_hash,
            "first_invalid_sequence": None,
            "reason": "HEAD_MISMATCH",
        }

    return {
        "valid": True,
        "entry_count": count,
        "head_hash": prev_hash,
        "first_invalid_sequence": None,
        "reason": None,
    }


def _failure(count: int, sequence: Any, reason: str, head: str) -> dict[str, Any]:
    return {
        "valid": False,
        "entry_count": count,
        "head_hash": head,
        "first_invalid_sequence": sequence,
        "reason": reason,
    }
