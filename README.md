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
