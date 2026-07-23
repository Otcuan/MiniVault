"""Đóng gói / phân tích ciphertext dạng `vault:<key_name>:<base64(nonce+ct+tag)>`.

Tách riêng khỏi encrypt/decrypt (THO-03) và khỏi tra cứu owner/DB (THO-04) nên
có thể viết và test ngay bây giờ, không cần chờ Auth (AN-02) cung cấp session
token. THO-03 sẽ gọi `format_ciphertext` sau khi mã hóa và `parse_ciphertext`
trước khi giải mã.
"""

from dataclasses import dataclass

from src.core.crypto import EncryptedBlob, GCM_NONCE_LENGTH, GCM_TAG_LENGTH
from src.core.encoding import decode_b64, encode_b64
from src.transit.exceptions import MalformedCiphertextError


CIPHERTEXT_PREFIX = "vault"
CIPHERTEXT_SEPARATOR = ":"
CIPHERTEXT_PART_COUNT = 3


@dataclass(frozen=True)
class TransitCiphertext:
    key_name: str
    blob: EncryptedBlob


def format_ciphertext(key_name: str, blob: EncryptedBlob) -> str:
    """Ghép nonce+ciphertext+tag thành một chuỗi tự mô tả để trả cho client."""
    if not key_name:
        raise ValueError("key_name không được rỗng")

    payload = blob.nonce + blob.ciphertext + blob.tag
    return CIPHERTEXT_SEPARATOR.join([CIPHERTEXT_PREFIX, key_name, encode_b64(payload)])


def parse_ciphertext(token: str) -> TransitCiphertext:
    """Tách `vault:<key_name>:<base64>` thành key_name + EncryptedBlob.

    Mọi input sai định dạng (thiếu phần, sai prefix, base64 hỏng, payload bị
    cắt ngắn) đều ném cùng một `MalformedCiphertextError`, không phân biệt lý
    do cụ thể để không tiết lộ chi tiết nội bộ cho client.
    """
    if not isinstance(token, str):
        raise MalformedCiphertextError()

    parts = token.split(CIPHERTEXT_SEPARATOR, CIPHERTEXT_PART_COUNT - 1)
    if len(parts) != CIPHERTEXT_PART_COUNT:
        raise MalformedCiphertextError()

    prefix, key_name, payload_b64 = parts
    if prefix != CIPHERTEXT_PREFIX or not key_name:
        raise MalformedCiphertextError()

    try:
        payload = decode_b64(payload_b64)
    except ValueError as exc:
        raise MalformedCiphertextError() from exc

    minimum_length = GCM_NONCE_LENGTH + GCM_TAG_LENGTH
    if len(payload) < minimum_length:
        raise MalformedCiphertextError()

    nonce = payload[:GCM_NONCE_LENGTH]
    tag = payload[len(payload) - GCM_TAG_LENGTH :]
    ciphertext = payload[GCM_NONCE_LENGTH : len(payload) - GCM_TAG_LENGTH]

    return TransitCiphertext(
        key_name=key_name,
        blob=EncryptedBlob(nonce=nonce, ciphertext=ciphertext, tag=tag),
    )
