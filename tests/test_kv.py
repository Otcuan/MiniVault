import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from tests.conftest import ALICE_EMAIL, BOB_EMAIL


PATH = f"secret/{ALICE_EMAIL}/database"


def test_write_read_roundtrip(unlocked_client: TestClient, alice_headers) -> None:
    write = unlocked_client.post(
        "/v1/kv/entries",
        json={"path": PATH, "data": {"password": "hunter2", "unicode": "bí mật"}},
        headers=alice_headers,
    )
    assert write.status_code == 200
    read = unlocked_client.get("/v1/kv/entries", params={"path": PATH}, headers=alice_headers)
    assert read.json()["data"] == {"password": "hunter2", "unicode": "bí mật"}


def test_disk_contains_no_plaintext(unlocked_client: TestClient, alice_headers, vault_paths) -> None:
    secret = "very-secret-value-12345"
    unlocked_client.post(
        "/v1/kv/entries",
        json={"path": PATH, "data": {"password": secret}},
        headers=alice_headers,
    )
    raw = vault_paths["database"].read_bytes()
    assert secret.encode() not in raw
    assert b'"password"' not in raw


def test_tampered_record_detected(unlocked_client: TestClient, alice_headers, vault_paths) -> None:
    unlocked_client.post(
        "/v1/kv/entries",
        json={"path": PATH, "data": {"password": "hunter2"}},
        headers=alice_headers,
    )
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        tag = conn.execute("SELECT tag_b64 FROM kv_records WHERE path = ?", (PATH,)).fetchone()[0]
        tampered = ("A" if tag[0] != "A" else "B") + tag[1:]
        conn.execute("UPDATE kv_records SET tag_b64 = ? WHERE path = ?", (tampered, PATH))
        conn.commit()
    response = unlocked_client.get("/v1/kv/entries", params={"path": PATH}, headers=alice_headers)
    assert response.status_code == 409
    assert response.json()["error"] == "TAMPER_DETECTED"


def test_overwrite_keeps_single_record(unlocked_client: TestClient, alice_headers, vault_paths) -> None:
    for value in ("old", "new"):
        unlocked_client.post(
            "/v1/kv/entries", json={"path": PATH, "data": {"value": value}}, headers=alice_headers
        )
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        count = conn.execute("SELECT COUNT(*) FROM kv_records WHERE path = ?", (PATH,)).fetchone()[0]
    assert count == 1
    assert unlocked_client.get("/v1/kv/entries", params={"path": PATH}, headers=alice_headers).json()["data"]["value"] == "new"


def test_not_found_for_owner(unlocked_client: TestClient, alice_headers) -> None:
    response = unlocked_client.get(
        "/v1/kv/entries",
        params={"path": f"secret/{ALICE_EMAIL}/missing"},
        headers=alice_headers,
    )
    assert response.status_code == 404


def test_cross_user_read_write_delete_denied(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    unlocked_client.post("/v1/kv/entries", json={"path": PATH, "data": {"secret": "alice"}}, headers=alice)
    assert unlocked_client.get("/v1/kv/entries", params={"path": PATH}, headers=bob).status_code == 403
    assert unlocked_client.post("/v1/kv/entries", json={"path": PATH, "data": {"secret": "bob"}}, headers=bob).status_code == 403
    assert unlocked_client.delete("/v1/kv/entries", params={"path": PATH}, headers=bob).status_code == 403
    assert unlocked_client.get("/v1/kv/entries", params={"path": PATH}, headers=alice).status_code == 200


def test_malformed_path_is_permission_denied(unlocked_client: TestClient, alice_headers) -> None:
    response = unlocked_client.post(
        "/v1/kv/entries", json={"path": "invalid", "data": {"x": 1}}, headers=alice_headers
    )
    assert response.status_code == 403


def test_authorization_precedes_vault_state(unlocked_client: TestClient, alice_bob_headers) -> None:
    _, bob = alice_bob_headers
    unlocked_client.post("/v1/vault/lock")
    response = unlocked_client.get("/v1/kv/entries", params={"path": PATH}, headers=bob)
    assert response.status_code == 403
    assert response.json()["error"] == "PERMISSION_DENIED"


def test_denied_access_audited_without_secret(unlocked_client: TestClient, alice_bob_headers, vault_paths) -> None:
    alice, bob = alice_bob_headers
    marker = "must-not-enter-audit"
    unlocked_client.post("/v1/kv/entries", json={"path": PATH, "data": {"secret": marker}}, headers=alice)
    unlocked_client.post("/v1/kv/entries", json={"path": PATH, "data": {"secret": marker}}, headers=bob)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        rows = conn.execute("SELECT * FROM audit_logs").fetchall()
    text = " ".join(str(v) for row in rows for v in row)
    assert marker not in text
    assert "Bearer" not in text
    assert BOB_EMAIL in text
