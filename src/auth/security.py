from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash mật khẩu bằng Argon2id; salt và tham số được nhúng sẵn trong chuỗi trả về."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """So khớp mật khẩu với hash đã lưu. Không bao giờ raise ra ngoài khi sai/hỏng."""
    try:
        _password_hasher.verify(password_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False