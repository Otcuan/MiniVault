"""Shared pytest fixtures cho toàn bộ test suite (THO-01).

Mọi test module (Core, Auth, KV, Transit, Sign/Verify) nên dùng các fixture
ở đây thay vì tự dựng TestClient/DB riêng, để đảm bảo:
- Mỗi test chạy trên database + vault config sạch (tmp_path của pytest).
- Alice và Bob dùng chung định danh cho mọi test cross-user.
- Không test nào phụ thuộc state để lại bởi test khác.
"""

from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from main import create_app


VAULT_MASTER_PASSPHRASE = "MiniVault-Master-2026!"

ALICE_EMAIL = "alice@minivault.test"
ALICE_PASSWORD = "Alice-Strong-Passw0rd!"

BOB_EMAIL = "bob@minivault.test"
BOB_PASSWORD = "Bob-Strong-Passw0rd!"


@pytest.fixture
def vault_paths(tmp_path: Path) -> dict[str, Path]:
    """Đường dẫn config/database riêng cho từng test, tự động dọn theo tmp_path."""
    return {
        "config_path": tmp_path / "vault_config.json",
        "database_path": tmp_path / "mini_vault.db",
    }


@pytest.fixture
def client(vault_paths: dict[str, Path]) -> Iterator[TestClient]:
    """TestClient dùng app + database sạch, độc lập với mọi test khác."""
    app = create_app(
        config_path=vault_paths["config_path"],
        database_path=vault_paths["database_path"],
    )
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def unlocked_client(client: TestClient) -> TestClient:
    """Client với vault đã init + unlock, dùng cho test không thuộc phần Core."""
    client.post(
        "/v1/vault/init",
        json={"master_passphrase": VAULT_MASTER_PASSPHRASE},
    )
    client.post(
        "/v1/vault/unlock",
        json={"master_passphrase": VAULT_MASTER_PASSPHRASE},
    )
    return client


@pytest.fixture
def alice() -> dict[str, str]:
    return {"email": ALICE_EMAIL, "password": ALICE_PASSWORD}


@pytest.fixture
def bob() -> dict[str, str]:
    return {"email": BOB_EMAIL, "password": BOB_PASSWORD}
