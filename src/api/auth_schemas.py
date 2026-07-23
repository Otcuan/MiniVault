import re

from pydantic import BaseModel, Field, field_validator

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    passphrase: str = Field(min_length=1, max_length=1024)
    confirm_passphrase: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        if not EMAIL_PATTERN.match(value.strip()):
            raise ValueError("Invalid email format")
        return value


class RegisterResponse(BaseModel):
    email: str
    created_at: str

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    passphrase: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        if not EMAIL_PATTERN.match(value.strip()):
            raise ValueError("Invalid email format")
        return value


class LoginResponse(BaseModel):
    token: str
    expires_at: str