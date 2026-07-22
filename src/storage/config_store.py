import json
import os
from pathlib import Path
from typing import Any

from src.core.exceptions import StorageError, VaultConfigCorruptedError


class JsonConfigStore:
    """Đọc/ghi vault_config.json bằng chiến lược ghi file tạm rồi replace."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> dict[str, Any]:
        if not self.exists():
            raise FileNotFoundError(self.path)

        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as exc:
            raise VaultConfigCorruptedError() from exc
        except OSError as exc:
            raise StorageError("Cannot read Vault config") from exc

        if not isinstance(data, dict):
            raise VaultConfigCorruptedError()
        return data

    def save_atomic(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_suffix(self.path.suffix + ".tmp")

        try:
            with temporary_path.open("w", encoding="utf-8") as file:
                json.dump(data, file, ensure_ascii=False, indent=2, sort_keys=True)
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self.path)
        except OSError as exc:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise StorageError("Cannot write Vault config") from exc
