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
