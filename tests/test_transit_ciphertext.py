import pytest

from src.core.crypto import EncryptedBlob
from src.transit.ciphertext import format_ciphertext, parse_ciphertext
from src.transit.exceptions import MalformedCiphertextError


BLOB = EncryptedBlob(nonce=b"1" * 12, ciphertext=b"cipher", tag=b"2" * 16)


def test_version_one_uses_the_mandatory_framing() -> None:
    """Un-rotated keys emit exactly the shape section 2.2 asks for."""
    token = format_ciphertext("key", 1, BLOB)
    assert token.startswith("vault:key:")
    parsed = parse_ciphertext(token)
    assert (parsed.key_name, parsed.key_version, parsed.blob) == ("key", 1, BLOB)


def test_rotated_key_adds_a_version_segment() -> None:
    token = format_ciphertext("key", 3, BLOB)
    assert token.startswith("vault:v3:key:")
    parsed = parse_ciphertext(token)
    assert (parsed.key_name, parsed.key_version, parsed.blob) == ("key", 3, BLOB)


@pytest.mark.parametrize(
    "token",
    [
        "bad",
        "vault::AAAA",
        "other:key:AAAA",
        "vault:key:not-base64!",
        "vault:v0:key:AAAA",
        "vault:vX:key:AAAA",
        "vault:v1:bad key:AAAA",
    ],
)
def test_ciphertext_parser_rejects_malformed(token: str) -> None:
    with pytest.raises(MalformedCiphertextError):
        parse_ciphertext(token)


def test_truncated_payload_rejected() -> None:
    """A payload shorter than nonce+tag cannot be authentic, so it is refused
    before any key is unwrapped."""
    with pytest.raises(MalformedCiphertextError):
        parse_ciphertext("vault:key:AAAAAAAA")
