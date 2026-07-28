import base64
import os

# Argon2id is deliberately expensive. Every test initializes and unlocks a Vault
# and registers users, so production cost parameters would make the suite take
# minutes of pure key stretching. These overrides must be set before anything
# imports the application, because settings are read from the environment.
#
# This only changes the COST, never the algorithm: the tests still exercise real
# Argon2id, real AES-256-GCM and real ED25519.
os.environ.setdefault("MINIVAULT_KDF_TIME_COST", "1")
os.environ.setdefault("MINIVAULT_KDF_MEMORY_COST", "1024")
os.environ.setdefault("MINIVAULT_KDF_PARALLELISM", "1")
os.environ.setdefault("MINIVAULT_PASSWORD_TIME_COST", "1")
os.environ.setdefault("MINIVAULT_PASSWORD_MEMORY_COST", "1024")
os.environ.setdefault("MINIVAULT_PASSWORD_PARALLELISM", "1")

from pathlib import Path  # noqa: E402
from typing import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import create_app  # noqa: E402


# Must satisfy src/core/passphrase.py: >=12 characters, >=3 character classes,
# no long repeated run, and no blocklisted word (the product name is one).
MASTER = "Tr0ng-Master-Key-2026!"
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
    """Each test gets its own Vault config and database."""
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
