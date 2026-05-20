@echo off
setlocal
cd /d "%~dp0"

echo === 一鍵打包 install.exe ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_exe.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo 打包失敗，錯誤碼：%EXIT_CODE%
  pause
  exit /b %EXIT_CODE%
)

echo.
echo 打包成功，輸出在 dist\install.exe
pause
exit /b 0
