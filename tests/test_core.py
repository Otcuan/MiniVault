import json
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app


MASTER_PASSPHRASE = "MiniVault-Master-2026!"


def create_test_client(temporary_directory: Path) -> TestClient:
    app = create_app(
        config_path=temporary_directory / "vault_config.json",
        database_path=temporary_directory / "mini_vault.db",
    )
    return TestClient(app)


def test_first_status_is_not_initialized(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.get("/v1/vault/status")
        assert response.status_code == 200
        assert response.json() == {
            "initialized": False,
            "status": "not_initialized",
        }


def test_initialize_creates_locked_vault(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert response.status_code == 201
        assert response.json() == {"initialized": True, "status": "locked"}


def test_config_does_not_store_passphrase_or_plaintext_dek(tmp_path: Path) -> None:
    config_path = tmp_path / "vault_config.json"

    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )

    raw_config = config_path.read_text(encoding="utf-8")
    assert MASTER_PASSPHRASE not in raw_config

    config = json.loads(raw_config)
    assert "encrypted_dek_b64" in config
    assert "dek_nonce_b64" in config
    assert "dek_tag_b64" in config
    assert "dek" not in config
    assert "plaintext_dek" not in config


def test_wrong_passphrase_does_not_unlock(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        response = client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": "This-is-the-wrong-passphrase"},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "UNLOCK_FAILED"
        assert client.get("/v1/vault/status").json()["status"] == "locked"


def test_correct_passphrase_unlocks(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        response = client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "unlocked"


def test_restart_returns_to_locked_state(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert client.get("/v1/vault/status").json()["status"] == "unlocked"

    # TestClient mới mô phỏng process/server restart, dùng lại cùng file config.
    with create_test_client(tmp_path) as restarted_client:
        assert restarted_client.get("/v1/vault/status").json() == {
            "initialized": True,
            "status": "locked",
        }


def test_tampered_wrapped_dek_cannot_unlock(tmp_path: Path) -> None:
    config_path = tmp_path / "vault_config.json"

    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    original = config["encrypted_dek_b64"]
    replacement = "A" if original[0] != "A" else "B"
    config["encrypted_dek_b64"] = replacement + original[1:]
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "UNLOCK_FAILED"
        assert client.get("/v1/vault/status").json()["status"] == "locked"
