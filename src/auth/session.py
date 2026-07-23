import hashlib
import secrets
from datetime import datetime, timedelta, timezone

SESSION_TOKEN_BYTES = 32
LOCKOUT_MINUTES = 5
SESSION_TTL_MINUTES = 30


def generate_session_token() -> str:
    """Sinh session token ngẫu nhiên bằng CSPRNG, dạng URL-safe base64."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Hash token trước khi lưu DB, để nếu database bị lộ, token thật vẫn không dùng được.

    Dùng SHA-256 (không phải Argon2) vì token đã có entropy cực cao (256 bit
    ngẫu nhiên từ CSPRNG) — khác hoàn toàn với password do người dùng tự chọn
    (entropy thấp, dễ đoán). Argon2/bcrypt được thiết kế để CHẬM, chống brute-force
    password yếu; áp dụng cho token ngẫu nhiên là lãng phí tài nguyên không cần thiết,
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def compute_expiry() -> datetime:
    """Thời điểm hết hạn = hiện tại (UTC) + 30 phút."""
    return datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL_MINUTES)


def is_expired(expires_at: datetime) -> bool:
    return datetime.now(timezone.utc) >= expires_at


def compute_lockout_until() -> datetime:
    """Thời điểm mở khóa lại = hiện tại (UTC) + 5 phút."""
    return datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)