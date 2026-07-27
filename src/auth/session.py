import hashlib
import secrets
from datetime import datetime, timedelta, timezone


SESSION_TOKEN_BYTES = 32
LOCKOUT_MINUTES = 5
SESSION_TTL_MINUTES = 30


def generate_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def compute_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL_MINUTES)


def is_expired(expires_at: datetime) -> bool:
    return datetime.now(timezone.utc) >= expires_at


def compute_lockout_until() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
