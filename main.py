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
