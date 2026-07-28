"""Section IV extra credit: tamper-evident audit log (+0.3).

The requirement is "hash-chained, detects log tampering", so each test attacks
the log in a different way and asserts the chain notices.
"""

import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from src.audit.chain import GENESIS_HASH, compute_entry_hash, verify_chain
from tests.conftest import ALICE_EMAIL, BOB_EMAIL


PATH = f"secret/{ALICE_EMAIL}/audited"


def provoke_denials(client: TestClient, alice, bob, count: int = 3) -> None:
    """Denied cross-user access is what sections 1.2 and 2.3 require logging."""
    client.post("/v1/kv/entries", json={"path": PATH, "data": {"v": 1}}, headers=alice)
    for index in range(count):
        client.get("/v1/kv/entries", params={"path": PATH}, headers=bob)
        client.post(
            "/v1/transit/encrypt",
            json={"key_name": f"ghost-{index}", "plaintext_b64": "aGk="},
            headers=bob,
        )


def test_chain_verifies_on_an_untouched_log(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    provoke_denials(unlocked_client, alice, bob)
    body = unlocked_client.get("/v1/audit/verify", headers=alice).json()
    assert body["valid"] is True
    assert body["entry_count"] >= 6
    assert body["reason"] is None
    assert len(body["head_hash"]) == 64


def test_empty_log_is_valid(unlocked_client: TestClient, alice_headers) -> None:
    body = unlocked_client.get("/v1/audit/verify", headers=alice_headers).json()
    assert body["valid"] is True
    assert body["entry_count"] == 0
    assert body["head_hash"] == GENESIS_HASH


def test_editing_an_entry_breaks_the_chain(
    unlocked_client: TestClient, alice_bob_headers, vault_paths
) -> None:
    """Rewriting history in place: change who was denied."""
    alice, bob = alice_bob_headers
    provoke_denials(unlocked_client, alice, bob)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        conn.execute(
            "UPDATE audit_logs SET requester_email = ? WHERE sequence = 2",
            ("innocent@example.test",),
        )
        conn.commit()

    body = unlocked_client.get("/v1/audit/verify", headers=alice).json()
    assert body["valid"] is False
    assert body["reason"] == "ENTRY_HASH_MISMATCH"
    assert body["first_invalid_sequence"] == 2


def test_deleting_a_middle_entry_breaks_the_chain(
    unlocked_client: TestClient, alice_bob_headers, vault_paths
) -> None:
    alice, bob = alice_bob_headers
    provoke_denials(unlocked_client, alice, bob)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        conn.execute("DELETE FROM audit_logs WHERE sequence = 2")
        conn.commit()

    body = unlocked_client.get("/v1/audit/verify", headers=alice).json()
    assert body["valid"] is False
    # The gap is caught before any hash is even recomputed.
    assert body["reason"] == "SEQUENCE_GAP"


def test_truncating_the_tail_is_detected_by_the_stored_head(
    unlocked_client: TestClient, alice_bob_headers, vault_paths
) -> None:
    """Deleting the newest entries leaves a chain that is internally consistent.

    That is exactly why the head hash is kept outside audit_logs: without it,
    this attack would pass verification.
    """
    alice, bob = alice_bob_headers
    provoke_denials(unlocked_client, alice, bob)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        highest = conn.execute("SELECT MAX(sequence) FROM audit_logs").fetchone()[0]
        conn.execute("DELETE FROM audit_logs WHERE sequence >= ?", (highest - 1,))
        conn.commit()

    body = unlocked_client.get("/v1/audit/verify", headers=alice).json()
    assert body["valid"] is False
    assert body["reason"] == "HEAD_MISMATCH"


def test_reordering_entries_breaks_the_chain(
    unlocked_client: TestClient, alice_bob_headers, vault_paths
) -> None:
    alice, bob = alice_bob_headers
    provoke_denials(unlocked_client, alice, bob)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        conn.execute("UPDATE audit_logs SET sequence = 999 WHERE sequence = 3")
        conn.execute("UPDATE audit_logs SET sequence = 3 WHERE sequence = 4")
        conn.execute("UPDATE audit_logs SET sequence = 4 WHERE sequence = 999")
        conn.commit()

    assert unlocked_client.get("/v1/audit/verify", headers=alice).json()["valid"] is False


def test_entries_are_scoped_to_the_caller(unlocked_client: TestClient, alice_bob_headers) -> None:
    """One user's log view must not reveal another user's paths or key names."""
    alice, bob = alice_bob_headers
    provoke_denials(unlocked_client, alice, bob)
    body = unlocked_client.get("/v1/audit/entries", headers=bob).json()
    assert body["entries"], "Bob's denied attempts should be recorded"
    assert all(entry["result"] == "DENIED" for entry in body["entries"])
    assert unlocked_client.get("/v1/audit/entries", headers=alice).json()["entries"] == []


def test_audit_endpoints_require_authentication(unlocked_client: TestClient) -> None:
    assert unlocked_client.get("/v1/audit/entries").status_code == 401
    assert unlocked_client.get("/v1/audit/verify").status_code == 401


def test_log_never_stores_secrets(
    unlocked_client: TestClient, alice_bob_headers, vault_paths
) -> None:
    alice, bob = alice_bob_headers
    marker = "must-not-enter-audit"
    unlocked_client.post(
        "/v1/kv/entries", json={"path": PATH, "data": {"secret": marker}}, headers=alice
    )
    unlocked_client.post(
        "/v1/kv/entries", json={"path": PATH, "data": {"secret": marker}}, headers=bob
    )
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        rows = conn.execute("SELECT * FROM audit_logs").fetchall()
    text = " ".join(str(value) for row in rows for value in row)
    assert marker not in text
    assert "Bearer" not in text
    assert BOB_EMAIL in text


def test_hash_is_sensitive_to_every_field() -> None:
    """Unit-level check that no hashed field is silently ignored."""
    base = {
        "sequence": 1,
        "requester_email": "a@example.test",
        "action": "ACCESS_DENIED",
        "target_type": "kv_path",
        "target_identifier": "secret/a@example.test/x",
        "result": "DENIED",
        "created_at": "2026-07-27T00:00:00+00:00",
    }
    reference = compute_entry_hash(GENESIS_HASH, base)
    assert compute_entry_hash("f" * 64, base) != reference
    for field in base:
        mutated = dict(base)
        mutated[field] = 2 if field == "sequence" else f"{base[field]}-changed"
        assert compute_entry_hash(GENESIS_HASH, mutated) != reference


def test_verify_chain_accepts_a_hand_built_chain() -> None:
    entries = []
    prev = GENESIS_HASH
    for sequence in (1, 2):
        entry = {
            "sequence": sequence,
            "requester_email": "a@example.test",
            "action": "ACCESS_DENIED",
            "target_type": "named_key",
            "target_identifier": "k",
            "result": "DENIED",
            "created_at": f"2026-07-27T00:00:0{sequence}+00:00",
        }
        entry_hash = compute_entry_hash(prev, entry)
        entries.append({**entry, "prev_hash": prev, "entry_hash": entry_hash})
        prev = entry_hash

    assert verify_chain(entries, prev)["valid"] is True
    assert verify_chain(entries, "0" * 64)["reason"] == "HEAD_MISMATCH"
