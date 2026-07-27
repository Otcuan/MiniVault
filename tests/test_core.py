import json
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app
from tests.conftest import MASTER


def test_first_status_is_not_initialized(client: TestClient) -> None:
    assert client.get("/v1/vault/status").json() == {
        "initialized": False,
        "status": "not_initialized",
    }


def test_initialize_creates_locked_vault(client: TestClient) -> None:
    response = client.post("/v1/vault/init", json={"master_passphrase": MASTER})
    assert response.status_code == 201
    assert response.json() == {"initialized": True, "status": "locked"}


def test_config_has_no_plaintext_passphrase_or_dek(client: TestClient, vault_paths) -> None:
    client.post("/v1/vault/init", json={"master_passphrase": MASTER})
    raw = vault_paths["config"].read_text(encoding="utf-8")
    assert MASTER not in raw
    config = json.loads(raw)
    assert "encrypted_dek_b64" in config
    assert "dek" not in config
    assert "plaintext_dek" not in config


def test_wrong_passphrase_keeps_vault_locked(client: TestClient) -> None:
    client.post("/v1/vault/init", json={"master_passphrase": MASTER})
    response = client.post("/v1/vault/unlock", json={"master_passphrase": "Wrong-passphrase-123"})
    assert response.status_code == 401
    assert response.json()["error"] == "UNLOCK_FAILED"
    assert client.get("/v1/vault/status").json()["status"] == "locked"


def test_correct_passphrase_unlocks(client: TestClient) -> None:
    client.post("/v1/vault/init", json={"master_passphrase": MASTER})
    assert client.post("/v1/vault/unlock", json={"master_passphrase": MASTER}).json()["status"] == "unlocked"


def test_restart_defaults_to_locked(vault_paths) -> None:
    app = create_app(vault_paths["config"], vault_paths["database"])
    with TestClient(app) as client:
        client.post("/v1/vault/init", json={"master_passphrase": MASTER})
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER})
        assert client.get("/v1/vault/status").json()["status"] == "unlocked"
    with TestClient(create_app(vault_paths["config"], vault_paths["database"])) as restarted:
        assert restarted.get("/v1/vault/status").json()["status"] == "locked"


def test_tampered_wrapped_dek_rejected(client: TestClient, vault_paths) -> None:
    client.post("/v1/vault/init", json={"master_passphrase": MASTER})
    config = json.loads(vault_paths["config"].read_text(encoding="utf-8"))
    original = config["encrypted_dek_b64"]
    config["encrypted_dek_b64"] = ("A" if original[0] != "A" else "B") + original[1:]
    vault_paths["config"].write_text(json.dumps(config), encoding="utf-8")
    response = client.post("/v1/vault/unlock", json={"master_passphrase": MASTER})
    assert response.status_code == 401
