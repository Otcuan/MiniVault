import base64


def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_b64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Base64 value must be a string")
    return base64.b64decode(value.encode("ascii"), validate=True)
