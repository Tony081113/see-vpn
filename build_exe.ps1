Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-PythonLauncher {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @{ Command = "py"; Args = @("-3") }
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @{ Command = "python"; Args = @() }
    }

    throw "找不到 Python，請先安裝 Python 3。"
}

function Invoke-PythonCommand {
    param(
        [hashtable]$Launcher,
        [string[]]$PyArgs
    )

    $launcherArgs = @($Launcher.Args)
    & $Launcher.Command @launcherArgs @PyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Python 指令執行失敗：$($PyArgs -join ' ')"
    }
}

try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    Set-Location $scriptDir

    Write-Host "=== 一鍵打包 install.exe ===" -ForegroundColor Cyan

    $launcher = Get-PythonLauncher
    Write-Host "[1/6] 檢查 Python 完成" -ForegroundColor Yellow

    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        Write-Host "[2/6] 建立虛擬環境 .venv" -ForegroundColor Yellow
        Invoke-PythonCommand -Launcher $launcher -PyArgs @("-m", "venv", ".venv")
    }
    else {
        Write-Host "[2/6] 使用既有虛擬環境 .venv" -ForegroundColor Yellow
    }

    $venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        throw "找不到虛擬環境 Python：$venvPython"
    }

    Write-Host "[3/6] 安裝執行與打包依賴" -ForegroundColor Yellow
    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "升級 pip 失敗"
    }

    & $venvPython -m pip install -r ".\requirements.txt" pyinstaller
    if ($LASTEXITCODE -ne 0) {
        throw "安裝依賴或 PyInstaller 失敗"
    }

    Write-Host "[4/6] 清理舊的打包輸出" -ForegroundColor Yellow
    if (Test-Path ".\build") {
        Remove-Item ".\build" -Recurse -Force
    }
    if (Test-Path ".\dist") {
        Remove-Item ".\dist" -Recurse -Force
    }

    Write-Host "[5/6] 先打包主程式 lab_policy_watchdog.exe" -ForegroundColor Yellow
    & $venvPython -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --name "lab_policy_watchdog" `
        --distpath ".\dist\app" `
        --workpath ".\build\app" `
        --specpath ".\build\app" `
        ".\lab_policy_watchdog.py"
    if ($LASTEXITCODE -ne 0) {
        throw "主程式 PyInstaller 打包失敗"
    }

    $appExePath = Join-Path $scriptDir "dist\app\lab_policy_watchdog.exe"
    $readmePath = Join-Path $scriptDir "README.md"
    if (-not (Test-Path $appExePath)) {
        throw "找不到主程式 EXE：$appExePath"
    }

    Write-Host "[6/6] 執行 PyInstaller 打包 install.exe" -ForegroundColor Yellow
    & $venvPython -m PyInstaller `
        --noconfirm `
        --onefile `
        --name "install" `
        --add-data "${appExePath};." `
        --distpath ".\dist" `
        --workpath ".\build\installer" `
        --specpath ".\build\installer" `
        ".\installer_bootstrap.py"
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller 打包失敗"
    }

    $exePath = Join-Path $scriptDir "dist\install.exe"
    if (-not (Test-Path $exePath)) {
        throw "打包完成但找不到 EXE：$exePath"
    }

    Write-Host "打包完成：$exePath" -ForegroundColor Green
}
catch {
    Write-Host "打包失敗：$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
