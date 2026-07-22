class VaultError(Exception):
    """Lớp cha cho mọi lỗi liên quan đến Vault."""


class VaultAlreadyInitializedError(VaultError):
    """Vault đã được khởi tạo trước đó."""


class VaultNotInitializedError(VaultError):
    """Vault chưa được khởi tạo."""


class VaultLockedError(VaultError):
    """Một chức năng yêu cầu Vault mở khóa nhưng Vault đang khóa."""


class InvalidMasterPassphraseError(VaultError):
    """Master Passphrase sai hoặc wrapped DEK không thể xác thực."""


class InvalidMasterPassphrasePolicyError(VaultError):
    """Master Passphrase không đạt chính sách tối thiểu."""


class VaultConfigCorruptedError(VaultError):
    """File cấu hình thiếu trường, sai Base64 hoặc bị sửa/hỏng."""


class StorageError(VaultError):
    """Không thể đọc hoặc ghi dữ liệu xuống đĩa."""
