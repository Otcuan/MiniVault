from typing import Any

from pydantic import BaseModel, Field


class KvWriteRequest(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    data: dict[str, Any]


class KvWriteResponse(BaseModel):
    created_at: str
    updated_at: str
    # Section IV (KV versioning): version assigned to this write.
    version: int


class KvReadResponse(BaseModel):
    data: dict[str, Any]
    version: int
    latest_version: int
    created_at: str


class KvVersionInfo(BaseModel):
    version: int
    created_at: str


class KvVersionsResponse(BaseModel):
    path: str
    latest_version: int
    versions: list[KvVersionInfo]
