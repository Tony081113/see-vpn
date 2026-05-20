@echo off
setlocal
cd /d "%~dp0"

echo === 教室網路政策監控器 安裝程式 ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo 安裝失敗，錯誤碼：%EXIT_CODE%
  pause
  exit /b %EXIT_CODE%
)

echo.
echo 安裝成功。
pause
exit /b 0
