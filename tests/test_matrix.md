# Test Matrix (THO-01)

Bảng ánh xạ 8 hạng mục rubric bắt buộc sang test dự kiến. Cập nhật cột
**Trạng thái** khi test được viết (`planned` → `done`); không xóa dòng đã có.

| # | Hạng mục rubric | Module | Test dự kiến | File | Owner | Trạng thái |
|---|---|---|---|---|---|---|
| 0.1 | Vault Init & Unlock | Core | Restart về locked; sai/đúng passphrase; không lưu plaintext DEK; feature bị chặn khi locked | `tests/test_core.py` | Lê Công Tuấn | done |
| 0.2 | Authentication (Register/Login/Session/Lockout) | Auth | Duplicate register; 5 lần sai khóa 5 phút; đúng password nhưng vault locked; token hết hạn/thiếu | `tests/test_auth.py` | Nguyễn Tuấn An | planned |
| 1.1 | KV Engine (AEAD at rest) | KV | Round-trip; không lộ plaintext khi tìm kiếm; tamper ciphertext; NOT_FOUND | `tests/test_kv.py` | Nguyễn Tuấn An | planned |
| 1.2 | KV Ownership | KV | Cross-user read/write/delete bị chặn 100% | `tests/test_kv.py` | Nguyễn Tuấn An | planned |
| 2.1 | Named Key Management | Transit | Key material không trả qua API; duplicate key; revoke; locked vault từ chối | `tests/test_transit_keys.py` | Trần Thọ | planned |
| 2.2 | Transit Encrypt/Decrypt | Transit | Text/JSON/binary round-trip; malformed/truncated ciphertext; tamper 1 byte; key revoked | `tests/test_transit_crypto.py` | Trần Thọ | planned |
| 2.3 | Named-key Access Control | Transit | Cross-user không dùng được key; permission check trước unwrap; không tiết lộ key tồn tại; audit khi denied | `tests/test_transit_ownership.py` | Trần Thọ | planned |
| 2.4 | Sign/Verify | Transit | RAW/DIGEST; sai độ dài digest; message bị sửa; cross-key; malformed signature không crash | `tests/test_sign_verify.py` | Trần Thọ | planned |
| — | End-to-end | Toàn hệ thống | Unlock → Auth → KV → Transit → Sign/Verify → các case bị từ chối | `tests/test_end_to_end.py` | Trần Thọ | planned |

## Quy ước dùng chung

- Mọi test dùng fixture trong `tests/conftest.py` (`client`, `unlocked_client`, `alice`, `bob`) — không tự tạo `TestClient`/DB riêng.
- Alice và Bob (`ALICE_EMAIL`/`BOB_EMAIL` trong `conftest.py`) là 2 user chuẩn cho mọi test cross-user; không đổi tên user khác trong test mới.
- Mỗi test phải chạy độc lập trên `tmp_path` — không phụ thuộc dữ liệu do test khác để lại.
- Test liên quan mật mã (KV, Transit, Sign/Verify) bắt buộc có ít nhất một tamper test.
- Test liên quan authorization (KV, Transit) bắt buộc có ít nhất một cross-user test.
