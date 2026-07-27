import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_256_KEY_LENGTH = 32
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16


@dataclass(frozen=True)
class EncryptedBlob:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def generate_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes) -> EncryptedBlob:
    if len(key) != AES_256_KEY_LENGTH:
        raise ValueError("AES-256 key must contain exactly 32 bytes")
    nonce = secrets.token_bytes(GCM_NONCE_LENGTH)
    encrypted = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return EncryptedBlob(
        nonce=nonce,
        ciphertext=encrypted[:-GCM_TAG_LENGTH],
        tag=encrypted[-GCM_TAG_LENGTH:],
    )


def decrypt_aes_gcm(key: bytes, blob: EncryptedBlob, associated_data: bytes) -> bytes:
    if len(key) != AES_256_KEY_LENGTH:
        raise ValueError("AES-256 key must contain exactly 32 bytes")
    if len(blob.nonce) != GCM_NONCE_LENGTH:
        raise ValueError("AES-GCM nonce must contain exactly 12 bytes")
    if len(blob.tag) != GCM_TAG_LENGTH:
        raise ValueError("AES-GCM tag must contain exactly 16 bytes")
    return AESGCM(key).decrypt(
        blob.nonce,
        blob.ciphertext + blob.tag,
        associated_data,
    )
