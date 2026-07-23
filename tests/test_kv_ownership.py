import sqlite3
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app

MASTER_PASSPHRASE = "MiniVault-Master-2026!"
PASSPHRASE = "MySecurePass123"
ALICE_EMAIL = "alice@example.com"
BOB_EMAIL = "bob@example.com"


@contextmanager
def create_unlocked_client(tmp_path: Path):
    app = create_app(
        config_path=tmp_path / "vault_config.json",
        database_path=tmp_path / "mini_vault.db",
    )
    with TestClient(app) as client:
        client.post("/v1/vault/init", json={"master_passphrase": MASTER_PASSPHRASE})
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER_PASSPHRASE})
        yield client


def register_and_login(client: TestClient, email: str) -> dict:
    client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": PASSPHRASE, "confirm_passphrase": PASSPHRASE},
    )
    login_response = client.post("/v1/auth/login", json={"email": email, "passphrase": PASSPHRASE})
    token = login_response.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_cross_user_read_is_denied(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "alice-secret"}}, headers=alice_headers)

        response = client.get("/v1/kv/entries", params={"path": alice_path}, headers=bob_headers)
        assert response.status_code == 403
        assert response.json()["error"] == "PERMISSION_DENIED"


def test_cross_user_write_is_denied(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        response = client.post(
            "/v1/kv/entries", json={"path": alice_path, "data": {"password": "hacked"}}, headers=bob_headers
        )
        assert response.status_code == 403
        assert response.json()["error"] == "PERMISSION_DENIED"


def test_cross_user_delete_is_denied(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "alice-secret"}}, headers=alice_headers)

        response = client.delete("/v1/kv/entries", params={"path": alice_path}, headers=bob_headers)
        assert response.status_code == 403

        still_there = client.get("/v1/kv/entries", params={"path": alice_path}, headers=alice_headers)
        assert still_there.status_code == 200  # record của Alice không bị xóa nhầm


def test_malformed_path_is_denied_not_leaked_as_400(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)

        response = client.post(
            "/v1/kv/entries", json={"path": "not-a-valid-path", "data": {"password": "x"}}, headers=alice_headers
        )
        assert response.status_code == 403
        assert response.json()["error"] == "PERMISSION_DENIED"


def test_own_path_still_works(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        response = client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "ok"}}, headers=alice_headers)
        assert response.status_code == 200


def test_denied_access_is_audited(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "alice-secret"}}, headers=alice_headers)
        client.get("/v1/kv/entries", params={"path": alice_path}, headers=bob_headers)

    conn = sqlite3.connect(database_path)
    row = conn.execute(
        "SELECT requester_email, target_identifier, result FROM audit_logs WHERE requester_email = ?",
        (BOB_EMAIL,),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == BOB_EMAIL
    assert row[1] == alice_path
    assert row[2] == "DENIED"


def test_audit_log_never_contains_secret_or_token(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "top-secret-value"}}, headers=alice_headers)
        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "attacker-attempt"}}, headers=bob_headers)

    conn = sqlite3.connect(database_path)
    rows = conn.execute("SELECT * FROM audit_logs").fetchall()
    conn.close()

    for row in rows:
        row_text = " ".join(str(value) for value in row)
        assert "top-secret-value" not in row_text
        assert "attacker-attempt" not in row_text
        assert "Bearer" not in row_text