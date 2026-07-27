from dataclasses import dataclass
import re

from src.core.crypto import EncryptedBlob, GCM_NONCE_LENGTH, GCM_TAG_LENGTH
from src.core.encoding import decode_b64, encode_b64
from src.transit.exceptions import MalformedCiphertextError


CIPHERTEXT_PREFIX = "vault"
KEY_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class TransitCiphertext:
    key_name: str
    blob: EncryptedBlob


def format_ciphertext(key_name: str, blob: EncryptedBlob) -> str:
    if not isinstance(key_name, str) or not KEY_NAME_PATTERN.fullmatch(key_name):
        raise ValueError("Invalid key name")
    payload = blob.nonce + blob.ciphertext + blob.tag
    return f"{CIPHERTEXT_PREFIX}:{key_name}:{encode_b64(payload)}"


def parse_ciphertext(token: str) -> TransitCiphertext:
    if not isinstance(token, str):
        raise MalformedCiphertextError()
    parts = token.split(":", 2)
    if len(parts) != 3:
        raise MalformedCiphertextError()
    prefix, key_name, payload_b64 = parts
    if prefix != CIPHERTEXT_PREFIX or not KEY_NAME_PATTERN.fullmatch(key_name):
        raise MalformedCiphertextError()
    try:
        payload = decode_b64(payload_b64)
    except (ValueError, UnicodeEncodeError) as exc:
        raise MalformedCiphertextError() from exc
    minimum = GCM_NONCE_LENGTH + GCM_TAG_LENGTH
    if len(payload) < minimum:
        raise MalformedCiphertextError()
    return TransitCiphertext(
        key_name=key_name,
        blob=EncryptedBlob(
            nonce=payload[:GCM_NONCE_LENGTH],
            ciphertext=payload[GCM_NONCE_LENGTH:-GCM_TAG_LENGTH],
            tag=payload[-GCM_TAG_LENGTH:],
        ),
    )
