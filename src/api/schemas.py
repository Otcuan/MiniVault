from typing import Literal

from pydantic import BaseModel, Field


class VaultInitRequest(BaseModel):
    master_passphrase: str = Field(min_length=12, max_length=1024)


class VaultUnlockRequest(BaseModel):
    master_passphrase: str = Field(min_length=1, max_length=1024)


class VaultStatusResponse(BaseModel):
    initialized: bool
    status: Literal["not_initialized", "locked", "unlocked"]


class ErrorResponse(BaseModel):
    error: str
    message: str
