"""Self-describing Transit ciphertext framing (2.2) with key versions (IV).

Two accepted shapes:

* ``vault:<key_name>:<base64(nonce||ct||tag)>``      -- the exact form required by
  section 2.2 of the assignment. Emitted whenever the named key has never been
  rotated, and always accepted on input, where it means key version 1.
* ``vault:v<N>:<key_name>:<base64(nonce||ct||tag)>`` -- emitted once a key has
  been rotated, mirroring HashiCorp Vault's ``vault:vN:`` prefix. The version
  segment is what lets old ciphertext keep decrypting after a rotation.

The client still never has to remember which key or which version was used.
"""

from dataclasses import dataclass
import re

from src.core.crypto import EncryptedBlob, GCM_NONCE_LENGTH, GCM_TAG_LENGTH
from src.core.encoding import decode_b64, encode_b64
from src.transit.exceptions import MalformedCiphertextError


CIPHERTEXT_PREFIX = "vault"
KEY_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VERSION_PATTERN = re.compile(r"^v([1-9][0-9]{0,8})$")
DEFAULT_KEY_VERSION = 1


@dataclass(frozen=True)
class TransitCiphertext:
    key_name: str
    key_version: int
    blob: EncryptedBlob


def format_ciphertext(key_name: str, key_version: int, blob: EncryptedBlob) -> str:
    if not isinstance(key_name, str) or not KEY_NAME_PATTERN.fullmatch(key_name):
        raise ValueError("Invalid key name")
    if not isinstance(key_version, int) or key_version < 1:
        raise ValueError("Invalid key version")
    payload = encode_b64(blob.nonce + blob.ciphertext + blob.tag)
    if key_version == DEFAULT_KEY_VERSION:
        # Keep the assignment's mandatory framing for un-rotated keys.
        return f"{CIPHERTEXT_PREFIX}:{key_name}:{payload}"
    return f"{CIPHERTEXT_PREFIX}:v{key_version}:{key_name}:{payload}"


def parse_ciphertext(token: str) -> TransitCiphertext:
    if not isinstance(token, str):
        raise MalformedCiphertextError()

    parts = token.split(":", 3)
    if len(parts) == 3:
        prefix, key_name, payload_b64 = parts
        key_version = DEFAULT_KEY_VERSION
    elif len(parts) == 4:
        prefix, version_segment, key_name, payload_b64 = parts
        match = VERSION_PATTERN.fullmatch(version_segment)
        if match is None:
            raise MalformedCiphertextError()
        key_version = int(match.group(1))
    else:
        raise MalformedCiphertextError()

    if prefix != CIPHERTEXT_PREFIX or not KEY_NAME_PATTERN.fullmatch(key_name):
        raise MalformedCiphertextError()
    try:
        payload = decode_b64(payload_b64)
    except (ValueError, UnicodeEncodeError) as exc:
        raise MalformedCiphertextError() from exc

    # A payload must hold at least a nonce and a tag; anything shorter has been
    # truncated and is rejected before any key is unwrapped.
    if len(payload) < GCM_NONCE_LENGTH + GCM_TAG_LENGTH:
        raise MalformedCiphertextError()

    return TransitCiphertext(
        key_name=key_name,
        key_version=key_version,
        blob=EncryptedBlob(
            nonce=payload[:GCM_NONCE_LENGTH],
            ciphertext=payload[GCM_NONCE_LENGTH:-GCM_TAG_LENGTH],
            tag=payload[-GCM_TAG_LENGTH:],
        ),
    )
