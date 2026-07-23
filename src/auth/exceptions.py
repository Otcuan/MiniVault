class AuthError(Exception):
    """Lớp cha cho mọi lỗi liên quan đến Authentication."""


class DuplicateEmailError(AuthError):
    """Email đã được đăng ký bởi tài khoản khác."""


class PassphraseMismatchError(AuthError):
    """Passphrase và confirm passphrase không khớp."""


class WeakPassphraseError(AuthError):
    """Passphrase không đạt độ dài tối thiểu theo chính sách."""


class InvalidCredentialsError(AuthError):
    """Email hoặc passphrase không đúng."""


class AccountLockedError(AuthError):
    """Tài khoản đang bị khóa tạm thời do đăng nhập sai nhiều lần liên tiếp."""

class UnauthenticatedError(AuthError):
    """Token thiếu, sai định dạng, không tồn tại, hoặc đã hết hạn."""