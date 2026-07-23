from src.core.exceptions import VaultError


class MalformedCiphertextError(VaultError):
    """Ciphertext không đúng dạng `vault:<key_name>:<base64>` hoặc bị cắt/sửa."""
