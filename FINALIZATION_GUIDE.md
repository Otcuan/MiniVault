# HƯỚNG DẪN TÍCH HỢP VÀ NỘP BÀI CUỐI

Bản này là source hoàn chỉnh đã được kiểm tra với 58 automated tests và statement coverage 96%.

## 1. Đưa source hoàn chỉnh vào repository hiện tại

Thực hiện trên Windows CMD. Thay `D:\MiniVault` bằng đường dẫn repository local của bạn.

```cmd
cd /d D:\MiniVault
git checkout main
git pull --ff-only origin main
git checkout -b feature/finalize-minivault
```

Giữ nguyên thư mục `.git`. Xóa các file source cũ trong working tree, sau đó giải nén nội dung của gói hoàn chỉnh vào đúng thư mục repository. Không chép thư mục `.git` từ nơi khác.

Kiểm tra thay đổi:

```cmd
git status
git diff --stat
```

## 2. Cài đặt và kiểm thử

```cmd
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q -W error
python -m compileall -q main.py src tests
python -m coverage run -m pytest -q
python -m coverage report -m
```

Tiêu chí đạt:

- `58 passed`.
- Không có failed/error/warning trong lần chạy `-W error`.
- Coverage xấp xỉ 96% (có thể chênh rất nhỏ theo phiên bản thư viện).

## 3. Chạy thử Swagger

```cmd
python -m uvicorn main:app --reload
```

Mở `http://127.0.0.1:8000/docs` và kiểm tra đủ bốn nhóm API:

- Vault Core.
- Authentication.
- KV Engine.
- Transit Engine, gồm Encrypt/Decrypt và Sign/Verify.

## 4. Commit và Pull Request

```cmd
git add .
git commit -m "feat: complete Mini Vault transit, signing, tests, and documentation"
git push -u origin feature/finalize-minivault
```

Tạo Pull Request:

- Base: `main`.
- Compare: `feature/finalize-minivault`.
- Không merge nếu `Files changed` có runtime DB, Vault config, `.venv`, cache hoặc secret.

Sau khi merge:

```cmd
git checkout main
git pull --ff-only origin main
python -m pytest -q -W error
```

## 5. Việc thủ công bắt buộc trước khi nộp

1. Điền MSSV chính xác của ba thành viên vào báo cáo.
2. Xuất báo cáo PDF tên `Report_MSSV1_MSSV2_MSSV3.pdf`.
3. Quay video demo 3-5 phút theo `docs/DEMO_SCRIPT.md`.
4. Chạy `reset_runtime_data_cmd.bat` và xác nhận không còn dữ liệu runtime.
5. Xóa `.venv`, `.pytest_cache`, `__pycache__`, `.coverage` và `htmlcov` khỏi bản nộp.
6. Đổi tên thư mục/ZIP thành `MSSV1_MSSV2_MSSV3.zip`.
7. Giải nén ZIP sang thư mục mới và chạy lại setup/test một lần cuối.

## 6. Reflection gate

Không xem project là hoàn thành chỉ vì server chạy. Chỉ đóng gói khi cả ba điều sau đều có bằng chứng:

- Confidentiality: tìm kiếm toàn bộ DB/config không thấy plaintext secret, password, token thật hoặc private key.
- Integrity: tamper config/KV/transit ciphertext làm thao tác thất bại an toàn.
- Authorization: Bob không đọc/ghi KV hoặc sử dụng named key của Alice, kể cả khi Vault đang locked.
