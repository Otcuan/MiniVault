import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app

VALID_PASSPHRASE = "MySecurePass123"


def create_test_client(temporary_directory: Path) -> TestClient:
    app = create_app(
        config_path=temporary_directory / "vault_config.json",
        database_path=temporary_directory / "mini_vault.db",
    )
    return TestClient(app)


def test_register_success(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "alice@example.com",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": VALID_PASSPHRASE,
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "alice@example.com"
        assert "created_at" in body
        assert "password_hash" not in body
        assert "passphrase" not in body


def test_register_normalizes_email_case(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "Alice@Example.COM",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": VALID_PASSPHRASE,
            },
        )
        assert response.status_code == 201
        assert response.json()["email"] == "alice@example.com"


def test_register_rejects_duplicate_email(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        payload = {
            "email": "bob@example.com",
            "passphrase": VALID_PASSPHRASE,
            "confirm_passphrase": VALID_PASSPHRASE,
        }
        assert client.post("/v1/auth/register", json=payload).status_code == 201

        second = client.post("/v1/auth/register", json=payload)
        assert second.status_code == 409
        assert second.json()["error"] == "EMAIL_ALREADY_REGISTERED"


def test_register_rejects_mismatched_confirm_passphrase(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "carol@example.com",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": "DifferentPass123",
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "PASSPHRASE_MISMATCH"


def test_register_rejects_weak_passphrase(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "dave@example.com",
                "passphrase": "short1",
                "confirm_passphrase": "short1",
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "WEAK_PASSPHRASE"


def test_password_is_not_stored_in_plaintext(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/auth/register",
            json={
                "email": "erin@example.com",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": VALID_PASSPHRASE,
            },
        )

    conn = sqlite3.connect(database_path)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE email = ?", ("erin@example.com",)
    ).fetchone()
    conn.close()

    assert row is not None
    stored_hash = row[0]
    assert VALID_PASSPHRASE not in stored_hash
    assert stored_hash.startswith("$argon2")