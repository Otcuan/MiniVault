import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app

VALID_PASSPHRASE = "MySecurePass123"
WRONG_PASSPHRASE = "WrongPass456"
EMAIL = "alice@example.com"


def create_test_client(temporary_directory: Path) -> TestClient:
    app = create_app(
        config_path=temporary_directory / "vault_config.json",
        database_path=temporary_directory / "mini_vault.db",
    )
    return TestClient(app)


def register(client, email=EMAIL):
    return client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": VALID_PASSPHRASE, "confirm_passphrase": VALID_PASSPHRASE},
    )


def login(client, email=EMAIL, passphrase=VALID_PASSPHRASE):
    return client.post("/v1/auth/login", json={"email": email, "passphrase": passphrase})


def test_login_success_returns_token_and_expiry(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        register(client)
        response = login(client)
        assert response.status_code == 200
        body = response.json()
        assert "token" in body and len(body["token"]) > 20
        assert "expires_at" in body


def test_login_rejects_wrong_password(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        register(client)
        response = login(client, passphrase=WRONG_PASSPHRASE)
        assert response.status_code == 401
        assert response.json()["error"] == "INVALID_CREDENTIALS"


def test_login_rejects_nonexistent_email(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = login(client, email="nobody@example.com")
        assert response.status_code == 401
        assert response.json()["error"] == "INVALID_CREDENTIALS"  # không lộ email có tồn tại hay không


def test_account_locks_after_five_failed_attempts(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        register(client)

        for _ in range(5):
            response = login(client, passphrase=WRONG_PASSPHRASE)
            assert response.status_code == 401

        # Lần thứ 6, dù nhập ĐÚNG password, vẫn phải bị từ chối vì đang khóa
        response = login(client, passphrase=VALID_PASSPHRASE)
        assert response.status_code == 423
        assert response.json()["error"] == "ACCOUNT_LOCKED"


def test_login_success_resets_failed_attempts_counter(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_test_client(tmp_path) as client:
        register(client)
        login(client, passphrase=WRONG_PASSPHRASE)
        login(client, passphrase=WRONG_PASSPHRASE)
        response = login(client, passphrase=VALID_PASSPHRASE)
        assert response.status_code == 200

    conn = sqlite3.connect(database_path)
    row = conn.execute("SELECT failed_attempts FROM users WHERE email = ?", (EMAIL,)).fetchone()
    conn.close()
    assert row[0] == 0


def test_lock_expires_after_five_minutes(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_test_client(tmp_path) as client:
        register(client)
        for _ in range(5):
            login(client, passphrase=WRONG_PASSPHRASE)

        # Mô phỏng đã qua 5 phút: chỉnh locked_until về quá khứ
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        conn = sqlite3.connect(database_path)
        conn.execute("UPDATE users SET locked_until = ? WHERE email = ?", (past, EMAIL))
        conn.commit()
        conn.close()

        response = login(client, passphrase=VALID_PASSPHRASE)
        assert response.status_code == 200


def test_login_rejects_malformed_email(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/login", json={"email": "not-an-email", "passphrase": VALID_PASSPHRASE}
        )
        assert response.status_code == 422  # Pydantic validation error, không tới được service