# see-vpn

在 Windows 上執行的 Python 圖形化監控工具，用於維持教室網路政策遵循。

## 依賴套件

| 套件 | 用途 |
| --- | --- |
| psutil | 讀取網路介面、監聽連線埠與程序資訊，供政策管制使用 |

安裝依賴：

```powershell
python -m pip install -r .\requirements.txt
```

## 安裝初始化（設定管理密碼）

第一次使用請先初始化，建立管理密碼：

```powershell
python .\lab_policy_watchdog.py --install-init
```

## 安裝程式（建議）

可直接執行安裝程式，一次完成：

1. 建立 `.venv` 虛擬環境
2. 安裝依賴套件
3. 初始化管理密碼

執行方式（二選一）：

```powershell
.\install.cmd
```

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

安裝完成後啟動：

```powershell
.\.venv\Scripts\python.exe .\lab_policy_watchdog.py
```

## 一鍵打包 install.exe

可直接執行打包程式，一次完成環境準備與打包：

1. 建立或重用 `.venv`
2. 安裝/更新依賴與 PyInstaller
3. 輸出安裝程式 `install.exe`

執行方式（二選一）：

```powershell
.\build_exe.cmd
```

```powershell
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
```

打包輸出檔案：

```text
dist\install.exe
```

`install.exe` 會在執行時：

1. 將內嵌的主程式 `lab_policy_watchdog.exe` 解壓出來
2. 安裝到 Windows 使用者的自啟動路徑
3. 以不回顯方式要求輸入管理密碼
4. 建立管理設定檔（只保存雜湊，不保存明文密碼）

安裝完成後可直接執行：

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\lab_policy_watchdog.exe
```

管理密碼可用於以下管理設定：

1. 解安裝
2. 擴充未授權隧道介面關鍵字
3. 設定介面白名單

## 執行

```powershell
python .\lab_policy_watchdog.py
```

## 管理指令

查看目前設定：

```powershell
python .\lab_policy_watchdog.py --show-settings
```

新增未授權隧道介面關鍵字（需密碼）：

```powershell
python .\lab_policy_watchdog.py --add-interface-pattern zerotier
```

移除未授權隧道介面關鍵字（需密碼）：

```powershell
python .\lab_policy_watchdog.py --remove-interface-pattern zerotier
```

新增介面白名單（需密碼）：

```powershell
python .\lab_policy_watchdog.py --add-interface-whitelist "Ethernet 2"
```

移除介面白名單（需密碼）：

```powershell
python .\lab_policy_watchdog.py --remove-interface-whitelist "Ethernet 2"
```

解安裝（刪除設定與記錄，需密碼）：

```powershell
python .\lab_policy_watchdog.py --uninstall
```
