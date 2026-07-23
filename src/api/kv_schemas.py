from typing import Any

from pydantic import BaseModel, Field


class KvWriteRequest(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    data: dict[str, Any]


class KvWriteResponse(BaseModel):
    created_at: str
    updated_at: str


class KvReadResponse(BaseModel):
    data: dict[str, Any]