# MINI VAULT — BÁO CÁO ĐỒ ÁN

## 1. Thành viên và phân công

| Thành viên | Vai trò/đóng góp |
|---|---|
| Lê Công Tuấn | Core Vault, tích hợp hệ thống, security review, kiểm thử cuối, đóng gói |
| Nguyễn Tuấn An | Authentication, Session, KV Engine, KV ownership |
| Trần Thọ | Test framework, Transit ciphertext parser, kế hoạch kiểm thử |

Phần hoàn thiện tích hợp Transit, Sign/Verify, tài liệu và regression cuối được Lê Công Tuấn thực hiện khi hai thành viên còn lại bận.

> Điền MSSV chính xác trước khi xuất PDF.

## 2. Mục tiêu

Hệ thống cung cấp KV Engine mã hóa dữ liệu lưu trữ và Transit Engine thực hiện mã hóa/ký số mà không xuất khóa ra client. Ba thuộc tính trọng tâm: bí mật, toàn vẹn và kiểm soát truy cập.

## 3. Kiến trúc

`Client -> FastAPI Routes -> Authentication/Authorization -> Services -> Repositories -> SQLite/Config`

- Vault Core quản lý DEK trong RAM.
- Auth quản lý user, lockout và session token.
- KV dùng DEK để AEAD dữ liệu tại rest.
- Transit dùng DEK để bọc named AES key hoặc ED25519 private key.

## 4. Cơ chế mật mã

### Init/Unlock

Master Passphrase được dẫn xuất bằng Argon2id với salt riêng. Wrapping key mã hóa DEK bằng AES-256-GCM. Sai passphrase hoặc config bị sửa đều thất bại xác thực GCM.

### KV Engine

Dữ liệu JSON được serialize UTF-8 và mã hóa AES-256-GCM. AAD gắn owner và path, nên ciphertext không thể chuyển sang user/path khác.

### Transit Engine

- Named AES key dùng `ENCRYPT_DECRYPT`.
- ED25519 private key dùng `SIGN_VERIFY` và được DEK mã hóa.
- Ciphertext: `vault:<key_name>:<base64(nonce||ct||tag)>`.
- RAW: SHA-256(message) rồi ký ED25519.
- DIGEST: đầu vào phải đúng 32 byte.

## 5. Authentication và Access Control

Passphrase user dùng Argon2id. Token session ngẫu nhiên, DB chỉ lưu SHA-256 hash. Sau năm lần sai, tài khoản khóa năm phút. KV path phải theo `secret/<email>/...`. Named key chỉ truy xuất bằng `(owner_email, key_name)`; kiểm tra owner diễn ra trước unwrap.

## 6. Xử lý lỗi và chống rò rỉ

- Email tồn tại/không tồn tại khi login đều trả `INVALID_CREDENTIALS`.
- Key thiếu hoặc thuộc user khác dùng cùng lỗi `PERMISSION_DENIED`.
- Tamper dữ liệu trả `TAMPER_DETECTED`.
- Verify signature sai/malformed trả `signature_valid=false`, không crash.
- Log không nhận secret/token/private key.

## 7. Kiểm thử

Test bao phủ positive flow, negative flow, tamper, restart, expiry, lockout, cross-user, wrong key usage, revoked key, RAW/DIGEST và end-to-end. Kết quả xác minh cuối: **58 tests passed**, warnings-as-errors passed và statement coverage **96%**. Chi tiết tại `docs/TEST_RESULTS.md`.

## 8. Hạn chế

- Demo chạy local, chưa triển khai TLS/reverse proxy production.
- SQLite phù hợp đồ án/local; chưa tối ưu multi-instance.
- Python không đảm bảo zeroization tuyệt đối với mọi immutable object.
- Video demo phải được nhóm tự quay và nộp theo yêu cầu.

## 9. Kết luận

Thiết kế đáp ứng các mục rubric 0.1–2.4 và ba tiêu chí: ciphertext at rest, ownership enforcement và key material không rời server.
