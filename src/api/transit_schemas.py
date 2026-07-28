from typing import Literal, Optional

from pydantic import BaseModel, Field


class CreateKeyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)


class CreateSigningKeyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    signing_algorithm: str = "ED25519"


class KeyMetadata(BaseModel):
    """Everything an owner may learn about a key.

    There is deliberately no field here that could carry key material: the AES
    key, the ED25519 private key and even the public key are absent by design.
    """

    key_name: str
    key_usage: Literal["ENCRYPT_DECRYPT", "SIGN_VERIFY"]
    signing_algorithm: str | None
    latest_version: int
    versions: list[int]
    created_at: str
    updated_at: str


class KeyListResponse(BaseModel):
    keys: list[KeyMetadata]


class DeleteKeyResponse(BaseModel):
    key_name: str
    deleted: bool


class EncryptRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    plaintext_b64: str


class EncryptResponse(BaseModel):
    key_name: str
    key_version: int
    ciphertext: str


class DecryptRequest(BaseModel):
    ciphertext: str


class DecryptResponse(BaseModel):
    key_name: str
    key_version: int
    plaintext_b64: str


class SignRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    message_b64: str
    message_type: str = "RAW"
    signing_algorithm: str = "ED25519"


class SignResponse(BaseModel):
    key_name: str
    key_version: int
    signing_algorithm: str
    signature_b64: str


class VerifyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    message_b64: str
    message_type: str = "RAW"
    signature_b64: str
    signing_algorithm: str = "ED25519"
    # Optional: pin verification to one key version. Left empty, every version
    # of the key is tried (newest first).
    key_version: Optional[int] = Field(default=None, ge=1)


class VerifyResponse(BaseModel):
    key_name: str
    # Version that produced a valid signature, or null when none did.
    key_version: Optional[int]
    signing_algorithm: str
    signature_valid: bool
