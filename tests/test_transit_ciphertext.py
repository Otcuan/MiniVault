import pytest

from src.core.crypto import EncryptedBlob
from src.transit.ciphertext import format_ciphertext, parse_ciphertext
from src.transit.exceptions import MalformedCiphertextError


def test_ciphertext_framing_roundtrip() -> None:
    blob = EncryptedBlob(nonce=b"1" * 12, ciphertext=b"cipher", tag=b"2" * 16)
    token = format_ciphertext("key", blob)
    parsed = parse_ciphertext(token)
    assert parsed.key_name == "key"
    assert parsed.blob == blob


@pytest.mark.parametrize("token", ["bad", "vault::AAAA", "other:key:AAAA", "vault:key:not-base64!"])
def test_ciphertext_parser_rejects_malformed(token: str) -> None:
    with pytest.raises(MalformedCiphertextError):
        parse_ciphertext(token)
