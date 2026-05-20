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

    Write-Host "=== 教室網路政策監控器 安裝程式 ===" -ForegroundColor Cyan

    $launcher = Get-PythonLauncher
    Write-Host "[1/4] 檢查 Python 完成" -ForegroundColor Yellow

    Write-Host "[2/4] 建立虛擬環境 .venv" -ForegroundColor Yellow
    Invoke-PythonCommand -Launcher $launcher -PyArgs @("-m", "venv", ".venv")

    $venvPython = Join-Path $scriptDir ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        throw "找不到虛擬環境 Python：$venvPython"
    }

    Write-Host "[3/4] 安裝依賴套件" -ForegroundColor Yellow
    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "升級 pip 失敗"
    }

    & $venvPython -m pip install -r ".\requirements.txt"
    if ($LASTEXITCODE -ne 0) {
        throw "安裝 requirements.txt 失敗"
    }

    Write-Host "[4/4] 初始化管理密碼" -ForegroundColor Yellow
    Write-Host "請依提示輸入管理密碼（此密碼用於解安裝/擴充介面/白名單管理）。" -ForegroundColor White
    & $venvPython ".\lab_policy_watchdog.py" --install-init
    if ($LASTEXITCODE -ne 0) {
        throw "初始化管理密碼失敗"
    }

    Write-Host "安裝完成。" -ForegroundColor Green
    Write-Host "啟動方式：.\.venv\Scripts\python.exe .\lab_policy_watchdog.py" -ForegroundColor Green
}
catch {
    Write-Host "安裝失敗：$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
