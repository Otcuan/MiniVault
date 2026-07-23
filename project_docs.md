# Project Documentation

## Directory Tree

```text
MiniVault-main
├── .gitignore
├── .pytest_cache
│   ├── .gitignore
│   ├── CACHEDIR.TAG
│   ├── README.md
│   └── v
│       └── cache
│           ├── lastfailed
│           └── nodeids
├── CMD_STEPS.txt
├── CODE_EXPLANATION.md
├── README.md
├── data
│   ├── mini_vault.db
│   └── vault_config.json
├── main.py
├── read.py
├── requirements.txt
├── reset_runtime_data_cmd.bat
├── run_server_cmd.bat
├── setup_cmd.bat
├── src
│   ├── __init__.py
│   ├── api
│   │   ├── __init__.py
│   │   ├── auth_routes.py
│   │   ├── auth_schemas.py
│   │   ├── core_routes.py
│   │   ├── kv_routes.py
│   │   ├── kv_schemas.py
│   │   └── schemas.py
│   ├── auth
│   │   ├── __init__.py
│   │   ├── dependencies.py
│   │   ├── exceptions.py
│   │   ├── repository.py
│   │   ├── security.py
│   │   ├── service.py
│   │   ├── session.py
│   │   └── session_repository.py
│   ├── core
│   │   ├── __init__.py
│   │   ├── crypto.py
│   │   ├── encoding.py
│   │   ├── exceptions.py
│   │   ├── kdf.py
│   │   ├── state.py
│   │   └── vault.py
│   ├── kv
│   │   ├── __init__.py
│   │   ├── audit_repository.py
│   │   ├── exceptions.py
│   │   ├── paths.py
│   │   ├── repository.py
│   │   └── service.py
│   ├── storage
│   │   ├── __init__.py
│   │   ├── config_store.py
│   │   └── database.py
│   └── transit
│       └── __init__.py
└── tests
    ├── __init__.py
    ├── test_auth.py
    ├── test_auth_login.py
    ├── test_core.py
    ├── test_kv.py
    └── test_kv_ownership.py
```

# Files

---

## .gitignore

```
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.coverage
htmlcov/
.vscode/
.idea/
.env
data/*.db
data/*.db-shm
data/*.db-wal
data/vault_config.json
data/*.tmp
data/logs/*.log
data/logs/*.jsonl
.DS_Store
Thumbs.db

```

---

## CMD_STEPS.txt

```txt
MINI VAULT - CAC LENH CHAY TREN WINDOWS CMD

1. Mo CMD, di den thu muc vua giai nen:
   cd /d D:\duong-dan\MiniVault_CongTuan_Starter

2. Kiem tra Python:
   py --version

3. Cach nhanh: chay file setup:
   setup_cmd.bat

4. Hoac chay tung lenh:
   py -m venv .venv
   .venv\Scripts\activate.bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   pytest -q

5. Chay server:
   run_server_cmd.bat

   Hoac:
   .venv\Scripts\activate.bat
   uvicorn main:app --reload

6. Mo Swagger tren trinh duyet:
   http://127.0.0.1:8000/docs

7. Sua code bang Notepad tu CMD:
   notepad src\core\vault.py
   notepad src\core\crypto.py
   notepad src\storage\database.py
   notepad main.py

8. Xem file config sau khi init:
   type data\vault_config.json

9. Xem cau truc thu muc:
   tree /F

10. Xoa du lieu runtime de test init lai:
    reset_runtime_data_cmd.bat

```

---

## CODE_EXPLANATION.md

```md
# Giải thích code phần Lê Công Tuấn

## 1. Luồng Init

1. Kiểm tra Vault chưa được init.
2. Sinh salt 16 byte.
3. Dùng Argon2id dẫn xuất wrapping key 32 byte từ Master Passphrase.
4. Sinh DEK ngẫu nhiên 32 byte.
5. Dùng AES-256-GCM mã hóa DEK với AAD `mini-vault:dek-wrap:v1`.
6. Lưu salt, tham số KDF, nonce, ciphertext, tag vào JSON.
7. Không giữ DEK trong runtime sau init; trạng thái vẫn locked.

## 2. Luồng Unlock

1. Xóa DEK runtime cũ để bảo đảm failed unlock không giữ trạng thái mở.
2. Đọc salt và tham số KDF từ config.
3. Dẫn xuất lại wrapping key từ passphrase nhập vào.
4. Dùng wrapping key giải mã wrapped DEK.
5. Sai passphrase hoặc dữ liệu bị sửa đều dẫn tới `InvalidTag` và trả lỗi chung `UNLOCK_FAILED`.
6. Nếu thành công, đưa DEK vào `VaultState` trong RAM.

## 3. File quan trọng

- `src/core/kdf.py`: Argon2id.
- `src/core/crypto.py`: AES-GCM, nonce, tag.
- `src/core/state.py`: DEK trong bộ nhớ và lock/unlock runtime.
- `src/core/vault.py`: điều phối init/unlock.
- `src/storage/config_store.py`: ghi JSON atomic.
- `src/storage/database.py`: schema dùng chung cho cả nhóm.
- `src/api/core_routes.py`: REST API.
- `main.py`: tạo FastAPI app, lifespan và error handlers.
- `tests/test_core.py`: acceptance tests phần 0.1.

## 4. Quy tắc handoff

An và Thọ chỉ dùng interface công khai:

```python
vault_service.require_unlocked()
dek = vault_service.get_dek()
```

Không truy cập `vault_state._dek`, không đọc trực tiếp file config và không trả DEK qua API.

```

---

## README.md

```md
# Mini Vault - phần Core của Lê Công Tuấn

Starter code triển khai phần foundation, storage schema, Vault Init/Unlock, AES-256-GCM wrapped DEK, FastAPI routes và automated tests.

## Chạy nhanh trên Windows CMD

```cmd
cd /d D:\duong-dan\MiniVault_CongTuan_Starter
setup_cmd.bat
run_server_cmd.bat
```

Swagger: `http://127.0.0.1:8000/docs`

## API hiện có

- `GET /health`
- `GET /v1/vault/status`
- `POST /v1/vault/init`
- `POST /v1/vault/unlock`
- `POST /v1/vault/lock`

## Handoff cho An và Thọ

- Dùng `request.app.state.vault_service` để gọi `require_unlocked()` và `get_dek()`.
- Dùng `request.app.state.database` để lấy `Database` dùng chung.
- Không đọc trực tiếp `data/vault_config.json`.
- Không trả DEK, named AES key hoặc private key qua API.

```

---

## main.py

```py
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.core_routes import router as core_router
from src.core.exceptions import (
    InvalidMasterPassphraseError,
    InvalidMasterPassphrasePolicyError,
    StorageError,
    VaultAlreadyInitializedError,
    VaultConfigCorruptedError,
    VaultLockedError,
    VaultNotInitializedError,
)
from src.core.state import VaultState
from src.core.vault import VaultService
from src.storage.config_store import JsonConfigStore
from src.storage.database import Database

from src.api.auth_routes import router as auth_router
from src.auth.exceptions import (
    AccountLockedError,
    DuplicateEmailError,
    InvalidCredentialsError,
    PassphraseMismatchError,
    UnauthenticatedError,
    WeakPassphraseError,
)
from src.auth.session_repository import SessionRepository
from src.auth.repository import UserRepository                       
from src.auth.service import AuthService

from src.api.kv_routes import router as kv_router
from src.kv.exceptions import RecordNotFoundError, RecordTamperedError
from src.kv.repository import KvRepository
from src.kv.service import KvService

from src.kv.audit_repository import AuditRepository
from src.kv.exceptions import PermissionDeniedError


def create_app(
    config_path: Path = Path("data/vault_config.json"),
    database_path: Path = Path("data/mini_vault.db"),
) -> FastAPI:
    vault_state = VaultState()
    config_store = JsonConfigStore(config_path)
    vault_service = VaultService(config_store=config_store, state=vault_state)
    database = Database(database_path)
    user_repository = UserRepository(database)
    session_repository = SessionRepository(database)
    auth_service = AuthService(user_repository, session_repository)
    kv_repository = KvRepository(database)                        
    audit_repository = AuditRepository(database)                              
    kv_service = KvService(vault_service, kv_repository, audit_repository)     

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        vault_service.lock()  # Mỗi process mới đều bắt đầu ở trạng thái locked.
        app.state.vault_service = vault_service
        app.state.database = database
        app.state.auth_service = auth_service
        app.state.session_repository = session_repository
        app.state.kv_service = kv_service                      
        yield
        vault_service.lock()

    app = FastAPI(title="Mini Vault", version="1.0.0", lifespan=lifespan)
    app.include_router(core_router)
    app.include_router(auth_router)
    app.include_router(kv_router)  
    register_error_handlers(app)

    @app.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    return app


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(VaultAlreadyInitializedError)
    async def handle_already_initialized(
        request: Request, exception: VaultAlreadyInitializedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "error": "VAULT_ALREADY_INITIALIZED",
                "message": "Vault has already been initialized",
            },
        )

    @app.exception_handler(VaultNotInitializedError)
    async def handle_not_initialized(
        request: Request, exception: VaultNotInitializedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "error": "VAULT_NOT_INITIALIZED",
                "message": "Vault has not been initialized",
            },
        )

    @app.exception_handler(InvalidMasterPassphrasePolicyError)
    async def handle_invalid_policy(
        request: Request, exception: InvalidMasterPassphrasePolicyError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": "WEAK_MASTER_PASSPHRASE",
                "message": "Master Passphrase does not meet the minimum policy",
            },
        )

    @app.exception_handler(InvalidMasterPassphraseError)
    async def handle_invalid_passphrase(
        request: Request, exception: InvalidMasterPassphraseError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"error": "UNLOCK_FAILED", "message": "Unable to unlock Vault"},
        )

    @app.exception_handler(VaultLockedError)
    async def handle_locked(
        request: Request, exception: VaultLockedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=423,
            content={"error": "VAULT_LOCKED", "message": "Vault is locked"},
        )

    @app.exception_handler(VaultConfigCorruptedError)
    async def handle_corrupted_config(
        request: Request, exception: VaultConfigCorruptedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": "VAULT_CONFIG_INVALID",
                "message": "Vault configuration is invalid",
            },
        )

    @app.exception_handler(StorageError)
    async def handle_storage_error(
        request: Request, exception: StorageError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error": "STORAGE_ERROR", "message": "A storage operation failed"},
        )

    @app.exception_handler(DuplicateEmailError)
    async def handle_duplicate_email(
            request: Request, exception: DuplicateEmailError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"error": "EMAIL_ALREADY_REGISTERED", "message": "Email already registered"},
        )

    @app.exception_handler(PassphraseMismatchError)
    async def handle_passphrase_mismatch(
            request: Request, exception: PassphraseMismatchError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"error": "PASSPHRASE_MISMATCH", "message": "Passphrase confirmation does not match"},
        )

    @app.exception_handler(WeakPassphraseError)
    async def handle_weak_passphrase(
            request: Request, exception: WeakPassphraseError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"error": "WEAK_PASSPHRASE", "message": "Passphrase does not meet the minimum policy"},
        )

    @app.exception_handler(InvalidCredentialsError)
    async def handle_invalid_credentials(
        request: Request, exception: InvalidCredentialsError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"error": "INVALID_CREDENTIALS", "message": "Invalid email or passphrase"},
        )

    @app.exception_handler(AccountLockedError)
    async def handle_account_locked(
        request: Request, exception: AccountLockedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=423,
            content={"error": "ACCOUNT_LOCKED", "message": "Account is temporarily locked"},
        )

    @app.exception_handler(UnauthenticatedError)
    async def handle_unauthenticated(
        request: Request, exception: UnauthenticatedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"error": "UNAUTHENTICATED", "message": "Missing, invalid, or expired session token"},
        )

    @app.exception_handler(RecordNotFoundError)
    async def handle_record_not_found(
        request: Request, exception: RecordNotFoundError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"error": "NOT_FOUND", "message": "Record not found"},
        )

    @app.exception_handler(RecordTamperedError)
    async def handle_record_tampered(
        request: Request, exception: RecordTamperedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"error": "TAMPER_DETECTED", "message": "Stored record failed integrity verification"},
        )

    @app.exception_handler(PermissionDeniedError)
    async def handle_permission_denied(
        request: Request, exception: PermissionDeniedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"error": "PERMISSION_DENIED", "message": "You do not have access to this resource"},
        )


app = create_app()

```

---

## read.py

```py
import os
import sys
from pathlib import Path

# ===== Cấu hình =====
OUTPUT_FILE = "project_docs.md"

IGNORE_DIRS = {
    ".git", ".idea", ".vscode", "__pycache__",
    "venv", ".venv", "env", "node_modules",
    "dist", "build",
}

IGNORE_FILES = {OUTPUT_FILE, ".DS_Store"}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".java", ".cpp", ".c", ".h",
    ".cs", ".go", ".rs",
    ".html", ".css", ".scss",
    ".json", ".yaml", ".yml",
    ".xml", ".toml", ".ini",
    ".md", ".txt",
    ".sql", ".sh", ".bat",
    ".dockerfile", ".env",
}
# ====================


def is_text_file(path: Path):
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        with open(path, "r", encoding="utf-8") as f:
            f.read(1024)
        return True
    except Exception:
        return False


def build_tree(root):
    lines = [Path(root).resolve().name]

    def walk(directory, prefix=""):
        try:
            entries = sorted(
                e for e in os.listdir(directory)
                if e not in IGNORE_DIRS and e not in IGNORE_FILES
            )
        except PermissionError:
            return

        for i, name in enumerate(entries):
            path = os.path.join(directory, name)
            connector = "└── " if i == len(entries) - 1 else "├── "
            lines.append(prefix + connector + name)
            if os.path.isdir(path):
                extension = "    " if i == len(entries) - 1 else "│   "
                walk(path, prefix + extension)

    walk(root)
    return "\n".join(lines)


def main():
    project_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("# Project Documentation\n\n")
        out.write("## Directory Tree\n\n```text\n")
        out.write(build_tree(project_dir))
        out.write("\n```\n\n# Files\n\n")

        # os.walk đi qua TẤT CẢ các folder con lồng nhau (đệ quy tự động)
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            files.sort()

            for file in files:
                if file in IGNORE_FILES:
                    continue

                path = Path(root) / file
                if not is_text_file(path):
                    continue

                relative = path.relative_to(project_dir)
                out.write("---\n\n")
                out.write(f"## {relative}\n\n")

                lang = path.suffix.lstrip(".")
                out.write(f"```{lang}\n")

                try:
                    with open(path, "r", encoding="utf-8") as f:
                        out.write(f.read())
                except UnicodeDecodeError:
                    try:
                        with open(path, "r", encoding="latin-1") as f:
                            out.write(f.read())
                    except Exception:
                        out.write("[Không thể đọc file]")
                except Exception as e:
                    out.write(f"[Lỗi: {e}]")

                out.write("\n```\n\n")

    print(f"Đã tạo: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
```

---

## requirements.txt

```txt
fastapi>=0.115,<1.0
uvicorn[standard]>=0.30,<1.0
cryptography>=46,<50
argon2-cffi>=23,<26
pytest>=8,<10
httpx>=0.27,<1.0

```

---

## reset_runtime_data_cmd.bat

```bat
@echo off
setlocal
cd /d "%~dp0"
echo CANH BAO: lenh nay xoa vault_config.json va database runtime.
choice /C YN /M "Tiep tuc"
if errorlevel 2 exit /b 0
if exist data\vault_config.json del /Q data\vault_config.json
if exist data\mini_vault.db del /Q data\mini_vault.db
if exist data\mini_vault.db-shm del /Q data\mini_vault.db-shm
if exist data\mini_vault.db-wal del /Q data\mini_vault.db-wal
echo Da xoa runtime data.
endlocal

```

---

## run_server_cmd.bat

```bat
@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat (
  echo Chua co .venv. Hay chay setup_cmd.bat truoc.
  exit /b 1
)
call .venv\Scripts\activate.bat
uvicorn main:app --reload
endlocal

```

---

## setup_cmd.bat

```bat
@echo off
setlocal
cd /d "%~dp0"
py -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest -q
endlocal

```

---

## .pytest_cache\.gitignore

```
# Created by pytest automatically.
*

```

---

## .pytest_cache\CACHEDIR.TAG

```TAG
Signature: 8a477f597d28d172789f06886806bc55
# This file is a cache directory tag created by pytest.
# For information about cache directory tags, see:
#	https://bford.info/cachedir/spec.html

```

---

## .pytest_cache\README.md

```md
# pytest cache directory #

This directory contains data from the pytest's cache plugin,
which provides the `--lf` and `--ff` options, as well as the `cache` fixture.

**Do not** commit this to version control.

See [the docs](https://docs.pytest.org/en/stable/how-to/cache.html) for more information.

```

---

## .pytest_cache\v\cache\lastfailed

```
{
  "tests/test_kv_ownership.py::TestClient": true
}
```

---

## .pytest_cache\v\cache\nodeids

```
[
  "tests/test_auth.py::test_password_is_not_stored_in_plaintext",
  "tests/test_auth.py::test_register_normalizes_email_case",
  "tests/test_auth.py::test_register_rejects_duplicate_email",
  "tests/test_auth.py::test_register_rejects_mismatched_confirm_passphrase",
  "tests/test_auth.py::test_register_rejects_weak_passphrase",
  "tests/test_auth.py::test_register_success",
  "tests/test_auth_login.py::test_account_locks_after_five_failed_attempts",
  "tests/test_auth_login.py::test_lock_expires_after_five_minutes",
  "tests/test_auth_login.py::test_login_rejects_malformed_email",
  "tests/test_auth_login.py::test_login_rejects_nonexistent_email",
  "tests/test_auth_login.py::test_login_rejects_wrong_password",
  "tests/test_auth_login.py::test_login_success_resets_failed_attempts_counter",
  "tests/test_auth_login.py::test_login_success_returns_token_and_expiry",
  "tests/test_core.py::test_config_does_not_store_passphrase_or_plaintext_dek",
  "tests/test_core.py::test_correct_passphrase_unlocks",
  "tests/test_core.py::test_first_status_is_not_initialized",
  "tests/test_core.py::test_initialize_creates_locked_vault",
  "tests/test_core.py::test_restart_returns_to_locked_state",
  "tests/test_core.py::test_tampered_wrapped_dek_cannot_unlock",
  "tests/test_core.py::test_wrong_passphrase_does_not_unlock",
  "tests/test_kv.py::test_delete_nonexistent_path_returns_not_found",
  "tests/test_kv.py::test_delete_removes_record",
  "tests/test_kv.py::test_disk_never_contains_plaintext_secret",
  "tests/test_kv.py::test_overwrite_does_not_keep_version_history",
  "tests/test_kv.py::test_read_nonexistent_path_returns_not_found",
  "tests/test_kv.py::test_tampered_tag_is_rejected_on_read",
  "tests/test_kv.py::test_write_then_read_roundtrip",
  "tests/test_kv_ownership.py::test_audit_log_never_contains_secret_or_token",
  "tests/test_kv_ownership.py::test_cross_user_delete_is_denied",
  "tests/test_kv_ownership.py::test_cross_user_read_is_denied",
  "tests/test_kv_ownership.py::test_cross_user_write_is_denied",
  "tests/test_kv_ownership.py::test_denied_access_is_audited",
  "tests/test_kv_ownership.py::test_malformed_path_is_denied_not_leaked_as_400",
  "tests/test_kv_ownership.py::test_own_path_still_works"
]
```

---

## data\vault_config.json

```json
{
  "dek_nonce_b64": "a0DhpePjN3CwNw7/",
  "dek_tag_b64": "i7hm3X6q3SPyk0qOm+Hz1w==",
  "encrypted_dek_b64": "cFWdyPiKDT8KiBOaGJ53VqGLpXgsGyxrNeEzrwQuBbI=",
  "kdf": "argon2id",
  "kdf_parameters": {
    "hash_len": 32,
    "memory_cost": 65536,
    "parallelism": 4,
    "time_cost": 3
  },
  "kdf_salt_b64": "6QVEvYJ7BnH7qQW0PGd83A==",
  "status": "locked",
  "version": 1
}
```

---

## src\__init__.py

```py

```

---

## src\api\__init__.py

```py

```

---

## src\api\auth_routes.py

```py
from fastapi import APIRouter, Depends, Request, status

from src.api.auth_schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from src.auth.service import AuthService

router = APIRouter(prefix="/v1/auth", tags=["Authentication"])


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    payload: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    return service.register(
        email=payload.email,
        passphrase=payload.passphrase,
        confirm_passphrase=payload.confirm_passphrase,
    )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def login_user(
    payload: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    return service.login(email=payload.email, passphrase=payload.passphrase)
```

---

## src\api\auth_schemas.py

```py
import re

from pydantic import BaseModel, Field, field_validator

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    passphrase: str = Field(min_length=1, max_length=1024)
    confirm_passphrase: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        if not EMAIL_PATTERN.match(value.strip()):
            raise ValueError("Invalid email format")
        return value


class RegisterResponse(BaseModel):
    email: str
    created_at: str

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    passphrase: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        if not EMAIL_PATTERN.match(value.strip()):
            raise ValueError("Invalid email format")
        return value


class LoginResponse(BaseModel):
    token: str
    expires_at: str
```

---

## src\api\core_routes.py

```py
from fastapi import APIRouter, Depends, Request, status

from src.api.schemas import VaultInitRequest, VaultStatusResponse, VaultUnlockRequest
from src.core.vault import VaultService


router = APIRouter(prefix="/v1/vault", tags=["Vault Core"])


def get_vault_service(request: Request) -> VaultService:
    return request.app.state.vault_service


@router.get("/status", response_model=VaultStatusResponse)
def get_vault_status(
    service: VaultService = Depends(get_vault_service),
) -> dict:
    return service.status()


@router.post(
    "/init",
    response_model=VaultStatusResponse,
    status_code=status.HTTP_201_CREATED,
)
def initialize_vault(
    payload: VaultInitRequest,
    service: VaultService = Depends(get_vault_service),
) -> dict:
    return service.initialize(payload.master_passphrase)


@router.post("/unlock", response_model=VaultStatusResponse)
def unlock_vault(
    payload: VaultUnlockRequest,
    service: VaultService = Depends(get_vault_service),
) -> dict:
    return service.unlock(payload.master_passphrase)


@router.post("/lock", response_model=VaultStatusResponse)
def lock_vault(
    service: VaultService = Depends(get_vault_service),
) -> dict:
    return service.lock()

```

---

## src\api\kv_routes.py

```py
from fastapi import APIRouter, Depends, Query, Request, status

from src.api.kv_schemas import KvReadResponse, KvWriteRequest, KvWriteResponse
from src.auth.dependencies import AuthenticatedUser, get_current_user
from src.kv.service import KvService

router = APIRouter(prefix="/v1/kv", tags=["KV Engine"])


def get_kv_service(request: Request) -> KvService:
    return request.app.state.kv_service


@router.post("/entries", response_model=KvWriteResponse, status_code=status.HTTP_200_OK)
def write_entry(
    payload: KvWriteRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> dict:
    # owner_email LUÔN lấy từ token đã xác thực, KHÔNG BAO GIỜ lấy từ payload
    return service.write(owner_email=current_user.email, path=payload.path, data=payload.data)


@router.get("/entries", response_model=KvReadResponse, status_code=status.HTTP_200_OK)
def read_entry(
    path: str = Query(..., min_length=1, max_length=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> dict:
    data = service.read(owner_email=current_user.email, path=path)
    return {"data": data}


@router.delete("/entries", status_code=status.HTTP_204_NO_CONTENT)
def delete_entry(
    path: str = Query(..., min_length=1, max_length=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> None:
    service.delete(owner_email=current_user.email, path=path)
```

---

## src\api\kv_schemas.py

```py
from typing import Any

from pydantic import BaseModel, Field


class KvWriteRequest(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    data: dict[str, Any]


class KvWriteResponse(BaseModel):
    created_at: str
    updated_at: str


class KvReadResponse(BaseModel):
    data: dict[str, Any]
```

---

## src\api\schemas.py

```py
from typing import Literal

from pydantic import BaseModel, Field


class VaultInitRequest(BaseModel):
    master_passphrase: str = Field(min_length=12, max_length=1024)


class VaultUnlockRequest(BaseModel):
    master_passphrase: str = Field(min_length=1, max_length=1024)


class VaultStatusResponse(BaseModel):
    initialized: bool
    status: Literal["not_initialized", "locked", "unlocked"]


class ErrorResponse(BaseModel):
    error: str
    message: str

```

---

## src\auth\__init__.py

```py

```

---

## src\auth\dependencies.py

```py
from datetime import datetime
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.exceptions import UnauthenticatedError
from src.auth.session import hash_token, is_expired
from src.auth.session_repository import SessionRepository

bearer_scheme = HTTPBearer(auto_error=False)  # auto_error=False -> tự raise lỗi của mình, không để FastAPI raise 403 mặc định


class AuthenticatedUser:
    def __init__(self, user_id: int, email: str) -> None:
        self.user_id = user_id
        self.email = email


def get_session_repository(request: Request) -> SessionRepository:
    return request.app.state.session_repository


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> AuthenticatedUser:
    if credentials is None or not credentials.credentials:
        raise UnauthenticatedError()

    token = credentials.credentials.strip()
    if not token:
        raise UnauthenticatedError()

    session_repository = get_session_repository(request)
    session = session_repository.find_active_by_token_hash(hash_token(token))

    if session is None:
        raise UnauthenticatedError()

    expires_at = datetime.fromisoformat(session["expires_at"])
    if is_expired(expires_at):
        raise UnauthenticatedError()

    return AuthenticatedUser(user_id=session["user_id"], email=session["user_email"])
```

---

## src\auth\exceptions.py

```py
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
```

---

## src\auth\repository.py

```py
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.auth.exceptions import DuplicateEmailError
from src.storage.database import Database


class UserRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    @staticmethod
    def normalize_email(email: str) -> str:
        return email.strip().lower()

    def get_by_email(self, email: str) -> Optional[sqlite3.Row]:
        normalized = self.normalize_email(email)
        with self._database.connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE email = ?", (normalized,))
            return cursor.fetchone()

    def create(self, email: str, password_hash: str) -> sqlite3.Row:
        normalized = self.normalize_email(email)
        now = datetime.now(timezone.utc).isoformat()

        try:
            with self._database.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users (email, password_hash, failed_attempts,
                                        locked_until, created_at, updated_at)
                    VALUES (?, ?, 0, NULL, ?, ?)
                    """,
                    (normalized, password_hash, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEmailError(normalized) from exc

        return self.get_by_email(normalized)

    def update_after_failed_login(
        self, user_id: int, failed_attempts: int, locked_until: Optional[str]
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                (failed_attempts, locked_until, now, user_id),
            )

    def reset_login_failures(self, user_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
                (now, user_id),
            )
```

---

## src\auth\security.py

```py
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
```

---

## src\auth\service.py

```py
from datetime import datetime, timezone

from src.auth.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    PassphraseMismatchError,
    WeakPassphraseError,
)
from src.auth.repository import UserRepository
from src.auth.security import hash_password, verify_password
from src.auth.session import compute_expiry, compute_lockout_until, generate_session_token, hash_token
from src.auth.session_repository import SessionRepository

MIN_PASSPHRASE_LENGTH = 12
MAX_FAILED_ATTEMPTS = 5

# Hash "giả" tính sẵn 1 lần khi module load, dùng khi email không tồn tại,
# để verify_password() vẫn tốn thời gian tương đương như khi email có thật
# -> tránh lộ qua độ trễ phản hồi việc "email này có đăng ký hay không".
_DUMMY_PASSWORD_HASH = hash_password("timing-attack-mitigation-placeholder")


class AuthService:
    def __init__(self, user_repository: UserRepository, session_repository: SessionRepository) -> None:
        self._users = user_repository
        self._sessions = session_repository

    def register(self, email: str, passphrase: str, confirm_passphrase: str) -> dict:
        if passphrase != confirm_passphrase:
            raise PassphraseMismatchError()
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise WeakPassphraseError()

        password_hash = hash_password(passphrase)
        user_row = self._users.create(email, password_hash)

        return {"email": user_row["email"], "created_at": user_row["created_at"]}

    def login(self, email: str, passphrase: str) -> dict:
        user = self._users.get_by_email(email)

        if user is None:
            verify_password(passphrase, _DUMMY_PASSWORD_HASH)  # giữ thời gian phản hồi đều
            raise InvalidCredentialsError()

        if user["locked_until"] is not None:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now(timezone.utc) < locked_until:
                raise AccountLockedError()

        if not verify_password(passphrase, user["password_hash"]):
            self._register_failed_attempt(user)
            raise InvalidCredentialsError()

        self._users.reset_login_failures(user["id"])

        token = generate_session_token()
        expires_at = compute_expiry()
        self._sessions.create(user["id"], hash_token(token), expires_at.isoformat())

        return {"token": token, "expires_at": expires_at.isoformat()}

    def _register_failed_attempt(self, user) -> None:
        new_count = user["failed_attempts"] + 1
        locked_until = compute_lockout_until().isoformat() if new_count >= MAX_FAILED_ATTEMPTS else None
        self._users.update_after_failed_login(user["id"], new_count, locked_until)
```

---

## src\auth\session.py

```py
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
```

---

## src\auth\session_repository.py

```py
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.storage.database import Database


class SessionRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, user_id: int, token_hash: str, expires_at: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (user_id, token_hash, expires_at, revoked_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
                """,
                (user_id, token_hash, expires_at, now),
            )

    def find_active_by_token_hash(self, token_hash: str) -> Optional[sqlite3.Row]:
        """Chỉ trả session còn hạn và chưa bị thu hồi; kèm email để dùng cho auth dependency ở bước 3."""
        with self._database.connection() as conn:
            cursor = conn.execute(
                """
                SELECT sessions.*, users.email AS user_email
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.revoked_at IS NULL
                """,
                (token_hash,),
            )
            return cursor.fetchone()
```

---

## src\core\__init__.py

```py

```

---

## src\core\crypto.py

```py
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_256_KEY_LENGTH = 32
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16


@dataclass(frozen=True)
class EncryptedBlob:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def generate_dek() -> bytes:
    """Sinh Data Encryption Key 256 bit bằng CSPRNG của thư viện cryptography."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes) -> EncryptedBlob:
    """Mã hóa và xác thực dữ liệu bằng AES-256-GCM."""

    if len(key) != AES_256_KEY_LENGTH:
        raise ValueError("AES-256 key must contain exactly 32 bytes")

    nonce = secrets.token_bytes(GCM_NONCE_LENGTH)
    encrypted = AESGCM(key).encrypt(nonce, plaintext, associated_data)

    return EncryptedBlob(
        nonce=nonce,
        ciphertext=encrypted[:-GCM_TAG_LENGTH],
        tag=encrypted[-GCM_TAG_LENGTH:],
    )


def decrypt_aes_gcm(key: bytes, blob: EncryptedBlob, associated_data: bytes) -> bytes:
    """Ghép ciphertext + tag rồi giải mã; sai key/tag/AAD sẽ phát sinh InvalidTag."""

    if len(key) != AES_256_KEY_LENGTH:
        raise ValueError("AES-256 key must contain exactly 32 bytes")
    if len(blob.nonce) != GCM_NONCE_LENGTH:
        raise ValueError("AES-GCM nonce must contain exactly 12 bytes")
    if len(blob.tag) != GCM_TAG_LENGTH:
        raise ValueError("AES-GCM tag must contain exactly 16 bytes")

    return AESGCM(key).decrypt(
        blob.nonce,
        blob.ciphertext + blob.tag,
        associated_data,
    )

```

---

## src\core\encoding.py

```py
import base64


def encode_b64(data: bytes) -> str:
    """Chuyển bytes thành chuỗi Base64 có thể lưu trong JSON."""
    return base64.b64encode(data).decode("ascii")


def decode_b64(value: str) -> bytes:
    """Chuyển chuỗi Base64 hợp lệ về bytes."""
    if not isinstance(value, str):
        raise ValueError("Base64 value must be a string")
    return base64.b64decode(value.encode("ascii"), validate=True)

```

---

## src\core\exceptions.py

```py
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

```

---

## src\core\kdf.py

```py
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw


@dataclass(frozen=True)
class KDFParameters:
    """Tham số Argon2id được lưu cùng cấu hình để unlock có thể tái tạo khóa."""

    time_cost: int = 3
    memory_cost: int = 65536  # KiB = 64 MiB
    parallelism: int = 4
    hash_len: int = 32  # 32 bytes = 256 bits


DEFAULT_KDF_PARAMETERS = KDFParameters()


def derive_wrapping_key(
    master_passphrase: str,
    salt: bytes,
    parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
) -> bytes:
    """Dẫn xuất wrapping key 32 byte từ Master Passphrase bằng Argon2id."""

    if not isinstance(master_passphrase, str):
        raise TypeError("Master Passphrase must be a string")
    if not master_passphrase:
        raise ValueError("Master Passphrase cannot be empty")
    if len(salt) < 16:
        raise ValueError("KDF salt must contain at least 16 bytes")

    return hash_secret_raw(
        secret=master_passphrase.encode("utf-8"),
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_cost,
        parallelism=parameters.parallelism,
        hash_len=parameters.hash_len,
        type=Type.ID,
    )

```

---

## src\core\state.py

```py
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

```

---

## src\core\vault.py

```py
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag

from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm, generate_dek
from src.core.encoding import decode_b64, encode_b64
from src.core.exceptions import (
    InvalidMasterPassphraseError,
    InvalidMasterPassphrasePolicyError,
    VaultAlreadyInitializedError,
    VaultConfigCorruptedError,
    VaultNotInitializedError,
)
from src.core.kdf import KDFParameters, derive_wrapping_key
from src.core.state import VaultState
from src.storage.config_store import JsonConfigStore


CONFIG_VERSION = 1
DEK_WRAP_AAD = b"mini-vault:dek-wrap:v1"


class VaultService:
    """Điều phối init, unlock, lock và cung cấp DEK cho service nội bộ."""

    def __init__(self, config_store: JsonConfigStore, state: VaultState) -> None:
        self.config_store = config_store
        self.state = state

    def is_initialized(self) -> bool:
        return self.config_store.exists()

    def initialize(self, master_passphrase: str) -> dict[str, Any]:
        if self.is_initialized():
            raise VaultAlreadyInitializedError()

        self._validate_master_passphrase(master_passphrase)

        salt = secrets.token_bytes(16)
        parameters = KDFParameters()
        wrapping_key = derive_wrapping_key(master_passphrase, salt, parameters)
        dek = generate_dek()

        encrypted_dek = encrypt_aes_gcm(
            key=wrapping_key,
            plaintext=dek,
            associated_data=DEK_WRAP_AAD,
        )

        config = {
            "version": CONFIG_VERSION,
            "status": "locked",
            "kdf": "argon2id",
            "kdf_salt_b64": encode_b64(salt),
            "kdf_parameters": {
                "time_cost": parameters.time_cost,
                "memory_cost": parameters.memory_cost,
                "parallelism": parameters.parallelism,
                "hash_len": parameters.hash_len,
            },
            "dek_nonce_b64": encode_b64(encrypted_dek.nonce),
            "encrypted_dek_b64": encode_b64(encrypted_dek.ciphertext),
            "dek_tag_b64": encode_b64(encrypted_dek.tag),
        }

        self.config_store.save_atomic(config)
        self.state.lock()  # init xong vẫn locked theo thiết kế của nhóm
        return self.status()

    def unlock(self, master_passphrase: str) -> dict[str, Any]:
        if not self.is_initialized():
            raise VaultNotInitializedError()

        self.state.lock()  # thử unlock thất bại thì Vault chắc chắn vẫn khóa
        config = self._load_and_validate_config()

        try:
            salt = decode_b64(config["kdf_salt_b64"])
            parameter_data = config["kdf_parameters"]
            parameters = KDFParameters(
                time_cost=int(parameter_data["time_cost"]),
                memory_cost=int(parameter_data["memory_cost"]),
                parallelism=int(parameter_data["parallelism"]),
                hash_len=int(parameter_data["hash_len"]),
            )

            wrapping_key = derive_wrapping_key(master_passphrase, salt, parameters)
            encrypted_dek = EncryptedBlob(
                nonce=decode_b64(config["dek_nonce_b64"]),
                ciphertext=decode_b64(config["encrypted_dek_b64"]),
                tag=decode_b64(config["dek_tag_b64"]),
            )
            dek = decrypt_aes_gcm(
                key=wrapping_key,
                blob=encrypted_dek,
                associated_data=DEK_WRAP_AAD,
            )
        except InvalidTag as exc:
            # Không tiết lộ là sai passphrase hay tag/ciphertext bị sửa.
            raise InvalidMasterPassphraseError() from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultConfigCorruptedError() from exc

        if len(dek) != 32:
            raise VaultConfigCorruptedError()

        self.state.set_dek(dek)
        return self.status()

    def lock(self) -> dict[str, Any]:
        self.state.lock()
        return self.status()

    def require_unlocked(self) -> None:
        self.state.get_dek()

    def get_dek(self) -> bytes:
        """Chỉ dùng trong service nội bộ; không đưa giá trị này vào API response."""
        return self.state.get_dek()

    def status(self) -> dict[str, Any]:
        if not self.is_initialized():
            return {"initialized": False, "status": "not_initialized"}
        return {
            "initialized": True,
            "status": "unlocked" if self.state.is_unlocked else "locked",
        }

    def _load_and_validate_config(self) -> dict[str, Any]:
        config = self.config_store.load()
        required_fields = {
            "version",
            "status",
            "kdf",
            "kdf_salt_b64",
            "kdf_parameters",
            "dek_nonce_b64",
            "encrypted_dek_b64",
            "dek_tag_b64",
        }

        if not required_fields.issubset(config.keys()):
            raise VaultConfigCorruptedError()
        if config["version"] != CONFIG_VERSION:
            raise VaultConfigCorruptedError()
        if config["kdf"] != "argon2id":
            raise VaultConfigCorruptedError()
        return config

    @staticmethod
    def _validate_master_passphrase(master_passphrase: str) -> None:
        if not isinstance(master_passphrase, str):
            raise InvalidMasterPassphrasePolicyError()
        if len(master_passphrase) < 12 or master_passphrase.isspace():
            raise InvalidMasterPassphrasePolicyError()

```

---

## src\kv\__init__.py

```py

```

---

## src\kv\audit_repository.py

```py
from datetime import datetime, timezone

from src.storage.database import Database


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def log_denied_access(self, requester_email: str, target_type: str, target_identifier: str) -> None:
        """Ghi lại 1 lần truy cập bị từ chối. KHÔNG BAO GIỜ nhận/lưu secret hoặc token
        vào đây — chỉ lưu ai, cố truy cập cái gì, kết quả gì."""
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs
                    (requester_email, action, target_type, target_identifier, result, created_at)
                VALUES (?, 'ACCESS_DENIED', ?, ?, 'DENIED', ?)
                """,
                (requester_email, target_type, target_identifier, now),
            )
```

---

## src\kv\exceptions.py

```py
class KvError(Exception):
    """Lớp cha cho mọi lỗi liên quan đến KV Engine."""


class RecordNotFoundError(KvError):
    """Không tìm thấy record tại path được yêu cầu."""


class RecordTamperedError(KvError):
    """Dữ liệu trên đĩa đã bị sửa — GCM tag không khớp khi giải mã."""


class PermissionDeniedError(KvError):
    """Path không thuộc quyền sở hữu của người gọi."""


class InvalidPathError(KvError):
    """Path không đúng định dạng secret/<email>/..."""
```

---

## src\kv\paths.py

```py
PATH_PREFIX = "secret/"


def extract_owner_email_from_path(path: str) -> str:
    """Tách phần email ra khỏi path dạng 'secret/<email>/...'.
    Raise ValueError nếu path không đúng định dạng tối thiểu."""
    if not path.startswith(PATH_PREFIX):
        raise ValueError("Path must start with 'secret/'")

    remainder = path[len(PATH_PREFIX):]
    segments = remainder.split("/", 1)

    if len(segments) < 2 or not segments[0] or not segments[1]:
        raise ValueError("Path must follow 'secret/<email>/<name>' format")

    return segments[0]
```

---

## src\kv\repository.py

```py
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from src.storage.database import Database


class KvRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def upsert(
        self, owner_email: str, path: str, nonce_b64: str, ciphertext_b64: str, tag_b64: str
    ) -> dict:
        """Ghi mới hoặc ghi đè trực tiếp (không giữ version cũ) — dùng UPSERT
        nguyên tử của SQLite thay vì tự đọc-rồi-ghi, để tránh race condition
        khi 2 request cùng ghi 1 path đồng thời."""
        now = datetime.now(timezone.utc).isoformat()
        with self._database.connection() as conn:
            conn.execute(
                """
                INSERT INTO kv_records
                    (owner_email, path, nonce_b64, ciphertext_b64, tag_b64, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_email, path) DO UPDATE SET
                    nonce_b64 = excluded.nonce_b64,
                    ciphertext_b64 = excluded.ciphertext_b64,
                    tag_b64 = excluded.tag_b64,
                    updated_at = excluded.updated_at
                """,
                (owner_email, path, nonce_b64, ciphertext_b64, tag_b64, now, now),
            )
            row = conn.execute(
                "SELECT created_at, updated_at FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            ).fetchone()

        return {"created_at": row["created_at"], "updated_at": row["updated_at"]}

    def get(self, owner_email: str, path: str) -> Optional[sqlite3.Row]:
        with self._database.connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            )
            return cursor.fetchone()

    def delete(self, owner_email: str, path: str) -> bool:
        with self._database.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM kv_records WHERE owner_email = ? AND path = ?",
                (owner_email, path),
            )
            return cursor.rowcount > 0
```

---

## src\kv\service.py

```py
import json
from typing import Any

from cryptography.exceptions import InvalidTag

from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm
from src.core.encoding import decode_b64, encode_b64
from src.core.vault import VaultService
from src.kv.audit_repository import AuditRepository
from src.kv.exceptions import PermissionDeniedError, RecordNotFoundError, RecordTamperedError
from src.kv.paths import extract_owner_email_from_path
from src.kv.repository import KvRepository


class KvService:
    def __init__(
        self, vault_service: VaultService, kv_repository: KvRepository, audit_repository: AuditRepository
    ) -> None:
        self._vault = vault_service
        self._records = kv_repository
        self._audit = audit_repository

    def _authorize(self, requester_email: str, path: str) -> None:
        """Kiểm tra requester có đúng là chủ sở hữu của path hay không.
        Raise PermissionDeniedError cho MỌI trường hợp không khớp -- bao gồm
        cả path sai định dạng -- để không tiết lộ path đó có tồn tại hay
        đúng cấu trúc hay không (tránh làm oracle cho kẻ tấn công dò path)."""
        try:
            path_owner_email = extract_owner_email_from_path(path)
        except ValueError:
            path_owner_email = None

        if path_owner_email is None or path_owner_email != requester_email:
            self._audit.log_denied_access(requester_email, "kv_path", path)
            raise PermissionDeniedError(path)

    @staticmethod
    def _build_aad(owner_email: str, path: str) -> bytes:
        return f"kv:{owner_email}:{path}".encode("utf-8")

    def write(self, owner_email: str, path: str, data: dict[str, Any]) -> dict:
        self._vault.require_unlocked()
        self._authorize(owner_email, path)

        plaintext = json.dumps(data).encode("utf-8")
        dek = self._vault.get_dek()
        blob = encrypt_aes_gcm(dek, plaintext, self._build_aad(owner_email, path))

        return self._records.upsert(
            owner_email=owner_email,
            path=path,
            nonce_b64=encode_b64(blob.nonce),
            ciphertext_b64=encode_b64(blob.ciphertext),
            tag_b64=encode_b64(blob.tag),
        )

    def read(self, owner_email: str, path: str) -> dict[str, Any]:
        self._vault.require_unlocked()
        self._authorize(owner_email, path)

        record = self._records.get(owner_email, path)
        if record is None:
            raise RecordNotFoundError(path)

        try:
            blob = EncryptedBlob(
                nonce=decode_b64(record["nonce_b64"]),
                ciphertext=decode_b64(record["ciphertext_b64"]),
                tag=decode_b64(record["tag_b64"]),
            )
            dek = self._vault.get_dek()
            plaintext = decrypt_aes_gcm(dek, blob, self._build_aad(owner_email, path))
        except (InvalidTag, ValueError) as exc:
            raise RecordTamperedError(path) from exc

        return json.loads(plaintext)

    def delete(self, owner_email: str, path: str) -> None:
        self._vault.require_unlocked()
        self._authorize(owner_email, path)

        deleted = self._records.delete(owner_email, path)
        if not deleted:
            raise RecordNotFoundError(path)
```

---

## src\storage\__init__.py

```py

```

---

## src\storage\config_store.py

```py
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

```

---

## src\storage\database.py

```py
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DATABASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS kv_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_email TEXT NOT NULL,
    path TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    tag_b64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_email, path)
);
CREATE INDEX IF NOT EXISTS idx_kv_owner_email ON kv_records(owner_email);

CREATE TABLE IF NOT EXISTS named_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_email TEXT NOT NULL,
    key_name TEXT NOT NULL,
    key_usage TEXT NOT NULL CHECK (key_usage IN ('ENCRYPT_DECRYPT', 'SIGN_VERIFY')),
    signing_algorithm TEXT,
    nonce_b64 TEXT NOT NULL,
    encrypted_key_material_b64 TEXT NOT NULL,
    tag_b64 TEXT NOT NULL,
    public_key_b64 TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(owner_email, key_name)
);
CREATE INDEX IF NOT EXISTS idx_named_keys_owner_email ON named_keys(owner_email);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_identifier TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(DATABASE_SCHEMA)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

```

---

## src\transit\__init__.py

```py

```

---

## tests\__init__.py

```py

```

---

## tests\test_auth.py

```py
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app

VALID_PASSPHRASE = "MySecurePass123"


def create_test_client(temporary_directory: Path) -> TestClient:
    app = create_app(
        config_path=temporary_directory / "vault_config.json",
        database_path=temporary_directory / "mini_vault.db",
    )
    return TestClient(app)


def test_register_success(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "alice@example.com",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": VALID_PASSPHRASE,
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "alice@example.com"
        assert "created_at" in body
        assert "password_hash" not in body
        assert "passphrase" not in body


def test_register_normalizes_email_case(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "Alice@Example.COM",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": VALID_PASSPHRASE,
            },
        )
        assert response.status_code == 201
        assert response.json()["email"] == "alice@example.com"


def test_register_rejects_duplicate_email(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        payload = {
            "email": "bob@example.com",
            "passphrase": VALID_PASSPHRASE,
            "confirm_passphrase": VALID_PASSPHRASE,
        }
        assert client.post("/v1/auth/register", json=payload).status_code == 201

        second = client.post("/v1/auth/register", json=payload)
        assert second.status_code == 409
        assert second.json()["error"] == "EMAIL_ALREADY_REGISTERED"


def test_register_rejects_mismatched_confirm_passphrase(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "carol@example.com",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": "DifferentPass123",
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "PASSPHRASE_MISMATCH"


def test_register_rejects_weak_passphrase(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "dave@example.com",
                "passphrase": "short1",
                "confirm_passphrase": "short1",
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "WEAK_PASSPHRASE"


def test_password_is_not_stored_in_plaintext(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/auth/register",
            json={
                "email": "erin@example.com",
                "passphrase": VALID_PASSPHRASE,
                "confirm_passphrase": VALID_PASSPHRASE,
            },
        )

    conn = sqlite3.connect(database_path)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE email = ?", ("erin@example.com",)
    ).fetchone()
    conn.close()

    assert row is not None
    stored_hash = row[0]
    assert VALID_PASSPHRASE not in stored_hash
    assert stored_hash.startswith("$argon2")
```

---

## tests\test_auth_login.py

```py
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app

VALID_PASSPHRASE = "MySecurePass123"
WRONG_PASSPHRASE = "WrongPass456"
EMAIL = "alice@example.com"


def create_test_client(temporary_directory: Path) -> TestClient:
    app = create_app(
        config_path=temporary_directory / "vault_config.json",
        database_path=temporary_directory / "mini_vault.db",
    )
    return TestClient(app)


def register(client, email=EMAIL):
    return client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": VALID_PASSPHRASE, "confirm_passphrase": VALID_PASSPHRASE},
    )


def login(client, email=EMAIL, passphrase=VALID_PASSPHRASE):
    return client.post("/v1/auth/login", json={"email": email, "passphrase": passphrase})


def test_login_success_returns_token_and_expiry(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        register(client)
        response = login(client)
        assert response.status_code == 200
        body = response.json()
        assert "token" in body and len(body["token"]) > 20
        assert "expires_at" in body


def test_login_rejects_wrong_password(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        register(client)
        response = login(client, passphrase=WRONG_PASSPHRASE)
        assert response.status_code == 401
        assert response.json()["error"] == "INVALID_CREDENTIALS"


def test_login_rejects_nonexistent_email(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = login(client, email="nobody@example.com")
        assert response.status_code == 401
        assert response.json()["error"] == "INVALID_CREDENTIALS"  # không lộ email có tồn tại hay không


def test_account_locks_after_five_failed_attempts(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        register(client)

        for _ in range(5):
            response = login(client, passphrase=WRONG_PASSPHRASE)
            assert response.status_code == 401

        # Lần thứ 6, dù nhập ĐÚNG password, vẫn phải bị từ chối vì đang khóa
        response = login(client, passphrase=VALID_PASSPHRASE)
        assert response.status_code == 423
        assert response.json()["error"] == "ACCOUNT_LOCKED"


def test_login_success_resets_failed_attempts_counter(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_test_client(tmp_path) as client:
        register(client)
        login(client, passphrase=WRONG_PASSPHRASE)
        login(client, passphrase=WRONG_PASSPHRASE)
        response = login(client, passphrase=VALID_PASSPHRASE)
        assert response.status_code == 200

    conn = sqlite3.connect(database_path)
    row = conn.execute("SELECT failed_attempts FROM users WHERE email = ?", (EMAIL,)).fetchone()
    conn.close()
    assert row[0] == 0


def test_lock_expires_after_five_minutes(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_test_client(tmp_path) as client:
        register(client)
        for _ in range(5):
            login(client, passphrase=WRONG_PASSPHRASE)

        # Mô phỏng đã qua 5 phút: chỉnh locked_until về quá khứ
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        conn = sqlite3.connect(database_path)
        conn.execute("UPDATE users SET locked_until = ? WHERE email = ?", (past, EMAIL))
        conn.commit()
        conn.close()

        response = login(client, passphrase=VALID_PASSPHRASE)
        assert response.status_code == 200


def test_login_rejects_malformed_email(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/auth/login", json={"email": "not-an-email", "passphrase": VALID_PASSPHRASE}
        )
        assert response.status_code == 422  # Pydantic validation error, không tới được service
```

---

## tests\test_core.py

```py
import json
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app


MASTER_PASSPHRASE = "MiniVault-Master-2026!"


def create_test_client(temporary_directory: Path) -> TestClient:
    app = create_app(
        config_path=temporary_directory / "vault_config.json",
        database_path=temporary_directory / "mini_vault.db",
    )
    return TestClient(app)


def test_first_status_is_not_initialized(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.get("/v1/vault/status")
        assert response.status_code == 200
        assert response.json() == {
            "initialized": False,
            "status": "not_initialized",
        }


def test_initialize_creates_locked_vault(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert response.status_code == 201
        assert response.json() == {"initialized": True, "status": "locked"}


def test_config_does_not_store_passphrase_or_plaintext_dek(tmp_path: Path) -> None:
    config_path = tmp_path / "vault_config.json"

    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )

    raw_config = config_path.read_text(encoding="utf-8")
    assert MASTER_PASSPHRASE not in raw_config

    config = json.loads(raw_config)
    assert "encrypted_dek_b64" in config
    assert "dek_nonce_b64" in config
    assert "dek_tag_b64" in config
    assert "dek" not in config
    assert "plaintext_dek" not in config


def test_wrong_passphrase_does_not_unlock(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        response = client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": "This-is-the-wrong-passphrase"},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "UNLOCK_FAILED"
        assert client.get("/v1/vault/status").json()["status"] == "locked"


def test_correct_passphrase_unlocks(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        response = client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "unlocked"


def test_restart_returns_to_locked_state(tmp_path: Path) -> None:
    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert client.get("/v1/vault/status").json()["status"] == "unlocked"

    # TestClient mới mô phỏng process/server restart, dùng lại cùng file config.
    with create_test_client(tmp_path) as restarted_client:
        assert restarted_client.get("/v1/vault/status").json() == {
            "initialized": True,
            "status": "locked",
        }


def test_tampered_wrapped_dek_cannot_unlock(tmp_path: Path) -> None:
    config_path = tmp_path / "vault_config.json"

    with create_test_client(tmp_path) as client:
        client.post(
            "/v1/vault/init",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    original = config["encrypted_dek_b64"]
    replacement = "A" if original[0] != "A" else "B"
    config["encrypted_dek_b64"] = replacement + original[1:]
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    with create_test_client(tmp_path) as client:
        response = client.post(
            "/v1/vault/unlock",
            json={"master_passphrase": MASTER_PASSPHRASE},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "UNLOCK_FAILED"
        assert client.get("/v1/vault/status").json()["status"] == "locked"

```

---

## tests\test_kv.py

```py
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient
from contextlib import contextmanager
from main import create_app

MASTER_PASSPHRASE = "MiniVault-Master-2026!"
PASSPHRASE = "MySecurePass123"
EMAIL = "alice@example.com"
PATH = "secret/alice@example.com/db"


@contextmanager
def create_ready_client(tmp_path: Path):
    """Context manager: vault đã init+unlock, user đã register+login (token gắn sẵn header)."""
    app = create_app(
        config_path=tmp_path / "vault_config.json",
        database_path=tmp_path / "mini_vault.db",
    )
    with TestClient(app) as client:
        client.post("/v1/vault/init", json={"master_passphrase": MASTER_PASSPHRASE})
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER_PASSPHRASE})
        client.post(
            "/v1/auth/register",
            json={"email": EMAIL, "passphrase": PASSPHRASE, "confirm_passphrase": PASSPHRASE},
        )
        login_response = client.post("/v1/auth/login", json={"email": EMAIL, "passphrase": PASSPHRASE})
        token = login_response.json()["token"]
        client.headers.update({"Authorization": f"Bearer {token}"})
        yield client


def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        write_response = client.post(
            "/v1/kv/entries", json={"path": PATH, "data": {"password": "hunter2"}}
        )
        assert write_response.status_code == 200
        assert "created_at" in write_response.json()

        read_response = client.get("/v1/kv/entries", params={"path": PATH})
        assert read_response.status_code == 200
        assert read_response.json()["data"] == {"password": "hunter2"}


def test_overwrite_does_not_keep_version_history(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "old"}})
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "new"}})

        read_response = client.get("/v1/kv/entries", params={"path": PATH})
        assert read_response.json()["data"] == {"password": "new"}  # chỉ còn bản mới nhất


def test_read_nonexistent_path_returns_not_found(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        response = client.get("/v1/kv/entries", params={"path": "secret/alice@example.com/ghost"})
        assert response.status_code == 404
        assert response.json()["error"] == "NOT_FOUND"


def test_delete_removes_record(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "hunter2"}})

        delete_response = client.delete("/v1/kv/entries", params={"path": PATH})
        assert delete_response.status_code == 204

        read_response = client.get("/v1/kv/entries", params={"path": PATH})
        assert read_response.status_code == 404


def test_delete_nonexistent_path_returns_not_found(tmp_path: Path) -> None:
    with create_ready_client(tmp_path) as client:
        response = client.delete("/v1/kv/entries", params={"path": "secret/alice@example.com/ghost"})
        assert response.status_code == 404


def test_disk_never_contains_plaintext_secret(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_ready_client(tmp_path) as client:
        client.post(
            "/v1/kv/entries",
            json={"path": PATH, "data": {"password": "very-secret-value-12345"}},
        )

    conn = sqlite3.connect(database_path)
    row = conn.execute(
        "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM kv_records WHERE path = ?", (PATH,)
    ).fetchone()
    conn.close()

    assert row is not None
    for column_value in row:
        assert "very-secret-value-12345" not in column_value
        assert "password" not in column_value


def test_tampered_tag_is_rejected_on_read(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"
    config_path = tmp_path / "vault_config.json"

    with create_ready_client(tmp_path) as client:
        client.post("/v1/kv/entries", json={"path": PATH, "data": {"password": "hunter2"}})

    # Sửa tay 1 byte trong tag_b64 trên đĩa, mô phỏng dữ liệu bị tamper
    conn = sqlite3.connect(database_path)
    row = conn.execute("SELECT tag_b64 FROM kv_records WHERE path = ?", (PATH,)).fetchone()
    original_tag = row[0]
    tampered_tag = ("Y" if original_tag[0] != "Y" else "Z") + original_tag[1:]
    conn.execute("UPDATE kv_records SET tag_b64 = ? WHERE path = ?", (tampered_tag, PATH))
    conn.commit()
    conn.close()

    # Mở app mới trên CÙNG config + database (đã bị tamper), unlock lại, rồi thử đọc
    app = create_app(config_path=config_path, database_path=database_path)
    with TestClient(app) as client:
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER_PASSPHRASE})
        login_response = client.post("/v1/auth/login", json={"email": EMAIL, "passphrase": PASSPHRASE})
        token = login_response.json()["token"]
        client.headers.update({"Authorization": f"Bearer {token}"})

        response = client.get("/v1/kv/entries", params={"path": PATH})
        assert response.status_code == 409
        assert response.json()["error"] == "TAMPER_DETECTED"
```

---

## tests\test_kv_ownership.py

```py
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

from main import create_app

MASTER_PASSPHRASE = "MiniVault-Master-2026!"
PASSPHRASE = "MySecurePass123"
ALICE_EMAIL = "alice@example.com"
BOB_EMAIL = "bob@example.com"


@contextmanager
def create_unlocked_client(tmp_path: Path):
    app = create_app(
        config_path=tmp_path / "vault_config.json",
        database_path=tmp_path / "mini_vault.db",
    )
    with TestClient(app) as client:
        client.post("/v1/vault/init", json={"master_passphrase": MASTER_PASSPHRASE})
        client.post("/v1/vault/unlock", json={"master_passphrase": MASTER_PASSPHRASE})
        yield client


def register_and_login(client: TestClient, email: str) -> dict:
    client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": PASSPHRASE, "confirm_passphrase": PASSPHRASE},
    )
    login_response = client.post("/v1/auth/login", json={"email": email, "passphrase": PASSPHRASE})
    token = login_response.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_cross_user_read_is_denied(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "alice-secret"}}, headers=alice_headers)

        response = client.get("/v1/kv/entries", params={"path": alice_path}, headers=bob_headers)
        assert response.status_code == 403
        assert response.json()["error"] == "PERMISSION_DENIED"


def test_cross_user_write_is_denied(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        response = client.post(
            "/v1/kv/entries", json={"path": alice_path, "data": {"password": "hacked"}}, headers=bob_headers
        )
        assert response.status_code == 403
        assert response.json()["error"] == "PERMISSION_DENIED"


def test_cross_user_delete_is_denied(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "alice-secret"}}, headers=alice_headers)

        response = client.delete("/v1/kv/entries", params={"path": alice_path}, headers=bob_headers)
        assert response.status_code == 403

        still_there = client.get("/v1/kv/entries", params={"path": alice_path}, headers=alice_headers)
        assert still_there.status_code == 200  # record của Alice không bị xóa nhầm


def test_malformed_path_is_denied_not_leaked_as_400(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)

        response = client.post(
            "/v1/kv/entries", json={"path": "not-a-valid-path", "data": {"password": "x"}}, headers=alice_headers
        )
        assert response.status_code == 403
        assert response.json()["error"] == "PERMISSION_DENIED"


def test_own_path_still_works(tmp_path: Path) -> None:
    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        response = client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "ok"}}, headers=alice_headers)
        assert response.status_code == 200


def test_denied_access_is_audited(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "alice-secret"}}, headers=alice_headers)
        client.get("/v1/kv/entries", params={"path": alice_path}, headers=bob_headers)

    conn = sqlite3.connect(database_path)
    row = conn.execute(
        "SELECT requester_email, target_identifier, result FROM audit_logs WHERE requester_email = ?",
        (BOB_EMAIL,),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == BOB_EMAIL
    assert row[1] == alice_path
    assert row[2] == "DENIED"


def test_audit_log_never_contains_secret_or_token(tmp_path: Path) -> None:
    database_path = tmp_path / "mini_vault.db"

    with create_unlocked_client(tmp_path) as client:
        alice_headers = register_and_login(client, ALICE_EMAIL)
        bob_headers = register_and_login(client, BOB_EMAIL)
        alice_path = f"secret/{ALICE_EMAIL}/db"

        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "top-secret-value"}}, headers=alice_headers)
        client.post("/v1/kv/entries", json={"path": alice_path, "data": {"password": "attacker-attempt"}}, headers=bob_headers)

    conn = sqlite3.connect(database_path)
    rows = conn.execute("SELECT * FROM audit_logs").fetchall()
    conn.close()

    for row in rows:
        row_text = " ".join(str(value) for value in row)
        assert "top-secret-value" not in row_text
        assert "attacker-attempt" not in row_text
        assert "Bearer" not in row_text
```

