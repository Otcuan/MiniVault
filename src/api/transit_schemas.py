from typing import Literal

from pydantic import BaseModel, Field


class CreateKeyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)


class CreateSigningKeyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    signing_algorithm: str = "ED25519"


class KeyMetadata(BaseModel):
    key_name: str
    key_usage: Literal["ENCRYPT_DECRYPT", "SIGN_VERIFY"]
    signing_algorithm: str | None
    created_at: str
    revoked: bool


class KeyListResponse(BaseModel):
    keys: list[KeyMetadata]


class EncryptRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    plaintext_b64: str


class EncryptResponse(BaseModel):
    key_name: str
    ciphertext: str


class DecryptRequest(BaseModel):
    ciphertext: str


class DecryptResponse(BaseModel):
    key_name: str
    plaintext_b64: str


class SignRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    message_b64: str
    message_type: str = "RAW"
    signing_algorithm: str = "ED25519"


class SignResponse(BaseModel):
    key_name: str
    signing_algorithm: str
    signature_b64: str


class VerifyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=64)
    message_b64: str
    message_type: str = "RAW"
    signature_b64: str
    signing_algorithm: str = "ED25519"


class VerifyResponse(BaseModel):
    key_name: str
    signing_algorithm: str
    signature_valid: bool
