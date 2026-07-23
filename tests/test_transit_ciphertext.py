import pytest

from src.core.crypto import EncryptedBlob
from src.transit.ciphertext import format_ciphertext, parse_ciphertext
from src.transit.exceptions import MalformedCiphertextError


def make_blob(ciphertext: bytes = b"hello-cipher") -> EncryptedBlob:
    return EncryptedBlob(nonce=b"\x01" * 12, ciphertext=ciphertext, tag=b"\x02" * 16)


def test_round_trip_preserves_key_name_and_blob() -> None:
    blob = make_blob()
    token = format_ciphertext("my-key", blob)
    parsed = parse_ciphertext(token)

    assert parsed.key_name == "my-key"
    assert parsed.blob == blob


def test_format_uses_vault_prefix() -> None:
    token = format_ciphertext("my-key", make_blob())
    prefix, key_name, _ = token.split(":", 2)

    assert prefix == "vault"
    assert key_name == "my-key"


def test_round_trip_with_empty_ciphertext() -> None:
    blob = make_blob(ciphertext=b"")
    token = format_ciphertext("my-key", blob)

    assert parse_ciphertext(token).blob == blob


@pytest.mark.parametrize(
    "token",
    [
        "not-a-vault-ciphertext",
        "vault:only-two-parts",
        "vault::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "vaultx:my-key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "vault:my-key:not-valid-base64!!!",
    ],
)
def test_malformed_ciphertext_rejected(token: str) -> None:
    with pytest.raises(MalformedCiphertextError):
        parse_ciphertext(token)


def test_truncated_payload_rejected() -> None:
    token = format_ciphertext("my-key", make_blob())
    prefix, key_name, payload_b64 = token.split(":", 2)
    truncated_token = f"{prefix}:{key_name}:{payload_b64[: len(payload_b64) // 2]}"

    with pytest.raises(MalformedCiphertextError):
        parse_ciphertext(truncated_token)


def test_tampered_base64_produces_different_blob() -> None:
    """Đổi 1 ký tự vẫn parse được (đúng format) nhưng ra blob khác bản gốc.

    Phát hiện tampering thật sự (GCM tag mismatch) là việc của decrypt ở
    THO-03, không phải của parser này.
    """
    blob = make_blob()
    token = format_ciphertext("my-key", blob)
    prefix, key_name, payload_b64 = token.split(":", 2)
    middle_index = len(payload_b64) // 2
    flipped_char = "B" if payload_b64[middle_index] != "B" else "C"
    tampered_payload = payload_b64[:middle_index] + flipped_char + payload_b64[middle_index + 1 :]
    tampered_token = f"{prefix}:{key_name}:{tampered_payload}"

    parsed = parse_ciphertext(tampered_token)

    assert parsed.blob != blob
