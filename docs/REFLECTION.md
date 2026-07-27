# Reflection Check

## Đã đáp ứng

- [x] Argon2id + salt riêng cho Master Passphrase.
- [x] DEK 256 bit được AES-GCM wrap, không lưu plaintext.
- [x] Restart mặc định locked.
- [x] User password Argon2id, token có expiry, DB chỉ lưu token hash.
- [x] Lockout 5 lần/5 phút và reset đúng sau khi hết hạn.
- [x] KV ciphertext-at-rest, AAD, tamper detection.
- [x] KV cross-user read/write/delete bị chặn.
- [x] Named AES và ED25519 key material được mã hóa; API không export key.
- [x] Transit round-trip và format ciphertext theo đề.
- [x] Named-key owner check trước unwrap/Vault-state check.
- [x] Sign/Verify RAW và DIGEST; digest sai độ dài bị chặn.
- [x] Message sửa/cross-key/malformed signature không tạo unhandled exception.
- [x] Automated regression và end-to-end tests.
- [x] README, traceability, report, demo script.

## Reflection bảo mật

1. **Confidentiality:** plaintext secret và key material không được persistence dưới dạng rõ; token thật không lưu DB.
2. **Integrity:** AES-GCM tag phát hiện sửa đổi config, KV, named key và transit ciphertext; signature phát hiện message bị sửa.
3. **Authorization:** identity lấy từ bearer token, không lấy owner từ request body; owner check trước giải mã/unwrap.
4. **Error handling:** lỗi đối ngoại có mã ổn định, không trả stack trace hoặc nguyên nhân mật mã chi tiết.
5. **Residual risks:** local HTTP chưa có TLS; SQLite chưa dành cho multi-instance; Python memory zeroization là best-effort; rate limiting ở reverse proxy chưa triển khai.

## Còn phải làm thủ công trước khi nộp

- [ ] Điền MSSV trong báo cáo.
- [ ] Xuất báo cáo thành PDF tên theo quy định.
- [ ] Quay video demo 3–5 phút.
- [ ] Đổi tên thư mục/ZIP thành `MSSV1_MSSV2_MSSV3.zip`.
- [ ] Xóa runtime DB/config và kiểm tra ZIP không chứa secret.
