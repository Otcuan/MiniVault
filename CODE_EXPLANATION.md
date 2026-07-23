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
