from threading import RLock

from src.core.exceptions import VaultLockedError


class VaultState:
    """Trạng thái runtime: DEK chỉ tồn tại trong bộ nhớ khi Vault đã unlock."""

    def __init__(self) -> None:
        self._dek: bytearray | None = None
        self._lock = RLock()

    @property
    def is_unlocked(self) -> bool:
        with self._lock:
            return self._dek is not None

    def set_dek(self, dek: bytes) -> None:
        if len(dek) != 32:
            raise ValueError("DEK must contain exactly 32 bytes")

        with self._lock:
            self._clear_dek_without_lock()
            self._dek = bytearray(dek)

    def get_dek(self) -> bytes:
        with self._lock:
            if self._dek is None:
                raise VaultLockedError()
            return bytes(self._dek)

    def lock(self) -> None:
        with self._lock:
            self._clear_dek_without_lock()

    def _clear_dek_without_lock(self) -> None:
        if self._dek is not None:
            for index in range(len(self._dek)):
                self._dek[index] = 0
            self._dek = None
