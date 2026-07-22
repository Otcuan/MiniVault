@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat (
  echo Chua co .venv. Hay chay setup_cmd.bat truoc.
  exit /b 1
)
call .venv\Scripts\activate.bat
uvicorn main:app --reload
endlocal
