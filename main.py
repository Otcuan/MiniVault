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


def create_app(
    config_path: Path = Path("data/vault_config.json"),
    database_path: Path = Path("data/mini_vault.db"),
) -> FastAPI:
    vault_state = VaultState()
    config_store = JsonConfigStore(config_path)
    vault_service = VaultService(config_store=config_store, state=vault_state)
    database = Database(database_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        vault_service.lock()  # Mỗi process mới đều bắt đầu ở trạng thái locked.
        app.state.vault_service = vault_service
        app.state.database = database
        yield
        vault_service.lock()

    app = FastAPI(title="Mini Vault", version="1.0.0", lifespan=lifespan)
    app.include_router(core_router)
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


app = create_app()
