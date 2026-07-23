import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient
from contextlib import contextmanager
from main import create_app

MASTER_PASSPHRASE = "MiniVault-Master-2026!"
PASSPHRASE = "MySecurePass123"
EMAIL = "alice@example.com"
PATH = "secret/alice@example.com/db"


@contextmanager
def create_ready_client(tmp_path: Path):
    """Context manager: vault đã init+unlock, user đã register+login (token gắn sẵn header)."""
    app = create_app(
        config_path=tmp_path / "vault_config.json",
        database_path=tmp_path / "mini_vault.db",
    )
    with TestClient(app) as client:
        client.post("/v1/vault/init", json={"master_passphrase": MASTER_PASSPHRASE})
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER_PASSPHRASE})
        client.post(
            "/v1/auth/register",
            json={"email": EMAIL, "passphrase": PASSPHRASE, "confirm_passphrase": PASSPHRASE},
        )
        login_response = client.post("/v1/auth/login", json={"email": EMAIL, "passphrase": PASSPHRASE})
        token = login_response.json()["token"]
        client.headers.update({"Authorization": f"Bearer {token}"})
        yield client


def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        write_response = client.post(
            "/v1/kv/entries", json={"path": PATH, "data": {"password": "hunter2"}}
        )
        assert write_response.status_code == 200
        assert "created_at" in write_response.json()

        read_response = client.get("/v1/kv/entries", params={"path": PATH})
        assert read_response.status_code == 200
        assert read_response.json()["data"] == {"password": "hunter2"}


def test_overwrite_does_not_keep_version_history(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "old"}})
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "new"}})

        read_response = client.get("/v1/kv/entries", params={"path": PATH})
        assert read_response.json()["data"] == {"password": "new"}  # chỉ còn bản mới nhất


def test_read_nonexistent_path_returns_not_found(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        response = client.get("/v1/kv/entries", params={"path": "secret/alice@example.com/ghost"})
        assert response.status_code == 404
        assert response.json()["error"] == "NOT_FOUND"


def test_delete_removes_record(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "hunter2"}})

        delete_response = client.delete("/v1/kv/entries", params={"path": PATH})
        assert delete_response.status_code == 204

        read_response = client.get("/v1/kv/entries", params={"path": PATH})
        assert read_response.status_code == 404


def test_delete_nonexistent_path_returns_not_found(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        response = client.delete("/v1/kv/entries", params={"path": "secret/alice@example.com/ghost"})
        assert response.status_code == 404


def test_disk_never_contains_plaintext_secret(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_ready_client(tmp_path) as client:
        client.post(
            "/v1/kv/entries",
            json={"path": PATH, "data": {"password": "very-secret-value-12345"}},
        )

    conn = sqlite3.connect(database_path)
    row = conn.execute(
        "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM kv_records WHERE path = ?", (PATH,)
    ).fetchone()
    conn.close()

    assert row is not None
    for column_value in row:
        assert "very-secret-value-12345" not in column_value
        assert "password" not in column_value


def test_tampered_tag_is_rejected_on_read(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"
    config_path = tmp_path / "vault_config.json"

    with create_ready_client(tmp_path) as client:
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "hunter2"}})

    # Sửa tay 1 byte trong tag_b64 trên đĩa, mô phỏng dữ liệu bị tamper
    conn = sqlite3.connect(database_path)
    row = conn.execute("SELECT tag_b64 FROM kv_records WHERE path = ?", (PATH,)).fetchone()
    original_tag = row[0]
    tampered_tag = ("Y" if original_tag[0] != "Y" else "Z") + original_tag[1:]
    conn.execute("UPDATE kv_records SET tag_b64 = ? WHERE path = ?", (tampered_tag, PATH))
    conn.commit()
    conn.close()

    # Mở app mới trên CÙNG config + database (đã bị tamper), unlock lại, rồi thử đọc
    app = create_app(config_path=config_path, database_path=database_path)
    with TestClient(app) as client:
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER_PASSPHRASE})
        login_response = client.post("/v1/auth/login", json={"email": EMAIL, "passphrase": PASSPHRASE})
        token = login_response.json()["token"]
        client.headers.update({"Authorization": f"Bearer {token}"})

        response = client.get("/v1/kv/entries", params={"path": PATH})
        assert response.status_code == 409
        assert response.json()["error"] == "TAMPER_DETECTED"