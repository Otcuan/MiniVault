# Demo Script 3–5 phút

## Chuẩn bị

```cmd
reset_runtime_data_cmd.bat
.venv\Scripts\activate.bat
python -m pytest -q
python -m uvicorn main:app --reload
```

Mở `http://127.0.0.1:8000/docs`.

## Kịch bản

1. **Init/Unlock:** status ban đầu `not_initialized`; init xong `locked`; unlock sai thất bại; unlock đúng thành công.
2. **Auth:** đăng ký Alice, login nhận token; nhập token bằng nút Authorize.
3. **KV:** ghi `secret/alice@minivault.test/demo`, đọc lại; mở DB cho thấy chỉ nonce/ciphertext/tag. Đăng nhập Bob và chứng minh Bob nhận `PERMISSION_DENIED`.
4. **Transit Encrypt/Decrypt:** tạo `demo-aes`; encrypt Base64; ciphertext bắt đầu `vault:demo-aes:`; decrypt trả plaintext Base64 ban đầu. Sửa một ký tự ciphertext để nhận `TAMPER_DETECTED`.
5. **Sign/Verify:** tạo `demo-sign` ED25519; sign RAW; verify đúng trả `true`; đổi message trả `false`.
6. **Kết thúc:** chạy lại `python -m pytest -q`, chỉ vào `tests/test_matrix.md` và báo cáo.

Không quay hoặc hiển thị passphrase/token thật dùng ngoài demo.
