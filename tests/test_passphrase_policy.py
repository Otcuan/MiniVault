"""Sections 0.1 and 0.2 both require a strength check, not just a length check."""

import pytest
from fastapi.testclient import TestClient

from src.core.passphrase import evaluate, is_strong
from tests.conftest import MASTER


WEAK = {
    "TOO_SHORT": "Ab3!x",
    "TOO_FEW_CHARACTER_CLASSES": "aaabbbcccdddeee",
    "REPEATED_CHARACTERS": "Abcdeeee1234!",
    "COMMON_PATTERN": "MyPassword-2026!",
    "SURROUNDING_WHITESPACE": "  Abcdef-123!  ",
}


@pytest.mark.parametrize("code,passphrase", sorted(WEAK.items()))
def test_policy_flags_each_weakness(code: str, passphrase: str) -> None:
    issue = evaluate(passphrase)
    assert issue is not None and issue.code == code


@pytest.mark.parametrize(
    "passphrase",
    ["Tr0ng-Master-Key-2026!", "correct horse Battery 9 staple", "Zx9#kLmQ2*vB"],
)
def test_policy_accepts_strong_passphrases(passphrase: str) -> None:
    assert is_strong(passphrase)


def test_non_string_input_is_rejected() -> None:
    assert evaluate(None) is not None
    assert evaluate(12345678901234) is not None


def test_register_rejects_a_weak_passphrase(unlocked_client: TestClient) -> None:
    weak = "aaabbbcccdddeee"
    response = unlocked_client.post(
        "/v1/auth/register",
        json={
            "email": "weak@minivault.test",
            "passphrase": weak,
            "confirm_passphrase": weak,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "WEAK_PASSPHRASE"
    # The rejection must not echo the passphrase back to the caller.
    assert weak not in response.text


def test_init_rejects_a_weak_master_passphrase(client: TestClient) -> None:
    response = client.post("/v1/vault/init", json={"master_passphrase": "aaabbbcccdddeee"})
    assert response.status_code == 400
    assert response.json()["error"] == "WEAK_MASTER_PASSPHRASE"
    assert client.get("/v1/vault/status").json()["status"] == "not_initialized"


def test_unlock_does_not_re_apply_the_policy(client: TestClient) -> None:
    """Tightening the policy later must never lock an existing Vault out."""
    assert client.post("/v1/vault/init", json={"master_passphrase": MASTER}).status_code == 201
    assert client.post("/v1/vault/unlock", json={"master_passphrase": MASTER}).status_code == 200
