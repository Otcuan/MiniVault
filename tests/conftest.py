import base64
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from main import create_app


MASTER = "MiniVault-Master-2026!"
ALICE_EMAIL = "alice@minivault.test"
ALICE_PASSWORD = "Alice-Strong-Passw0rd!"
BOB_EMAIL = "bob@minivault.test"
BOB_PASSWORD = "Bob-Strong-Passw0rd!"


def b64(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.b64encode(value).decode("ascii")


@pytest.fixture
def vault_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "config": tmp_path / "vault_config.json",
        "database": tmp_path / "mini_vault.db",
    }


@pytest.fixture
def client(vault_paths: dict[str, Path]) -> Iterator[TestClient]:
    app = create_app(vault_paths["config"], vault_paths["database"])
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def unlocked_client(client: TestClient) -> TestClient:
    assert client.post("/v1/vault/init", json={"master_passphrase": MASTER}).status_code == 201
    assert client.post("/v1/vault/unlock", json={"master_passphrase": MASTER}).status_code == 200
    return client


def register(client: TestClient, email: str, password: str) -> None:
    response = client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": password, "confirm_passphrase": password},
    )
    assert response.status_code == 201, response.text


def login(client: TestClient, email: str, password: str) -> dict[str, str]:
    response = client.post(
        "/v1/auth/login",
        json={"email": email, "passphrase": password},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture
def alice_headers(unlocked_client: TestClient) -> dict[str, str]:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    return login(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)


@pytest.fixture
def alice_bob_headers(unlocked_client: TestClient) -> tuple[dict[str, str], dict[str, str]]:
    register(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD)
    register(unlocked_client, BOB_EMAIL, BOB_PASSWORD)
    return (
        login(unlocked_client, ALICE_EMAIL, ALICE_PASSWORD),
        login(unlocked_client, BOB_EMAIL, BOB_PASSWORD),
    )
