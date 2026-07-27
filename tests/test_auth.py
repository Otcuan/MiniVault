import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import closing

from fastapi.testclient import TestClient

from src.auth.session import hash_token
from tests.conftest import ALICE_EMAIL, ALICE_PASSWORD, login, register


def test_register_normalizes_email(unlocked_client: TestClient) -> None:
    response = unlocked_client.post(
        "/v1/auth/register",
        json={
            "email": "Alice@MiniVault.TEST",
            "passphrase": ALICE_PASSWORD,
            "confirm_passphrase": ALICE_PASSWORD,
        },
    )
    assert response.status_code == 201
    assert response.json()["email"] == ALICE_EMAIL


def test_password_is_argon2_hash(unlocked_client: TestClient, vault_paths) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        stored = conn.execute("SELECT password_hash FROM users WHERE email = ?", (ALICE_EMAIL,)).fetchone()[0]
    assert ALICE_PASSWORD not in stored
    assert stored.startswith("$argon2")


def test_duplicate_registration_rejected(unlocked_client: TestClient) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    response = unlocked_client.post(
        "/v1/auth/register",
        json={"email": ALICE_EMAIL, "passphrase": ALICE_PASSWORD, "confirm_passphrase": ALICE_PASSWORD},
    )
    assert response.status_code == 409


def test_login_returns_token_and_db_stores_only_hash(unlocked_client: TestClient, vault_paths) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    response = unlocked_client.post("/v1/auth/login", json={"email": ALICE_EMAIL, "passphrase": ALICE_PASSWORD})
    token = response.json()["token"]
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        stored = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert token != stored
    assert stored == hash_token(token)


def test_nonexistent_and_wrong_password_use_same_error(unlocked_client: TestClient) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    wrong = unlocked_client.post("/v1/auth/login", json={"email": ALICE_EMAIL, "passphrase": "WrongPassword-123"})
    missing = unlocked_client.post("/v1/auth/login", json={"email": "nobody@example.com", "passphrase": "WrongPassword-123"})
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json()["error"] == missing.json()["error"] == "INVALID_CREDENTIALS"


def test_account_locks_after_five_failures(unlocked_client: TestClient) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    for _ in range(5):
        assert unlocked_client.post("/v1/auth/login", json={"email": ALICE_EMAIL, "passphrase": "WrongPassword-123"}).status_code == 401
    response = unlocked_client.post("/v1/auth/login", json={"email": ALICE_EMAIL, "passphrase": ALICE_PASSWORD})
    assert response.status_code == 423
    assert response.json()["error"] == "ACCOUNT_LOCKED"


def test_expired_lockout_resets_failure_window(unlocked_client: TestClient, vault_paths) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    for _ in range(5):
        unlocked_client.post("/v1/auth/login", json={"email": ALICE_EMAIL, "passphrase": "WrongPassword-123"})
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        conn.execute("UPDATE users SET locked_until = ? WHERE email = ?", (past, ALICE_EMAIL))
        conn.commit()
    response = unlocked_client.post("/v1/auth/login", json={"email": ALICE_EMAIL, "passphrase": "WrongPassword-123"})
    assert response.status_code == 401
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        count, locked_until = conn.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE email = ?", (ALICE_EMAIL,)
        ).fetchone()
    assert count == 1
    assert locked_until is None


def test_missing_and_expired_token_unauthenticated(unlocked_client: TestClient, vault_paths) -> None:
    missing = unlocked_client.get("/v1/kv/entries", params={"path": f"secret/{ALICE_EMAIL}/x"})
    assert missing.status_code == 401
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    headers = login(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    token = headers["Authorization"].split(" ", 1)[1]
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        conn.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?", (past, hash_token(token)))
        conn.commit()
    expired = unlocked_client.get(
        "/v1/kv/entries", params={"path": f"secret/{ALICE_EMAIL}/x"}, headers=headers
    )
    assert expired.status_code == 401
    assert expired.json()["error"] == "UNAUTHENTICATED"


def test_logout_revokes_token(unlocked_client: TestClient) -> None:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    headers = login(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    assert unlocked_client.post("/v1/auth/logout", headers=headers).status_code == 204
    response = unlocked_client.get(
        "/v1/kv/entries", params={"path": f"secret/{ALICE_EMAIL}/x"}, headers=headers
    )
    assert response.status_code == 401
