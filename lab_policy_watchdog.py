import argparse
import ctypes
import getpass
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from typing import Any

import psutil


UNAUTHORIZED_INTERFACE_PATTERNS = (
    "tun",
    "tap",
    "vpn",
    "wireguard",
    "cloudflare",
)
UNAUTHORIZED_PROXY_PORTS = {7890, 1080, 1081, 10808}
CHECK_INTERVAL_MS = 5000
INITIAL_CHECK_DELAY_MS = 500
NETSH_COMMAND_TIMEOUT_SECONDS = 10
PROCESS_TERMINATE_TIMEOUT_SECONDS = 3
PASSWORD_HASH_ITERATIONS = 200000
POLICY_CONFIG_FILE_NAME = "policy_config.json"
WARNING_POPUP_COOLDOWN_SECONDS = 60


class PolicyWatchdogApp:
    def __init__(self, root: tk.Tk, policy_config: dict[str, Any]) -> None:
        self.root = root
        self.root.title("教室網路政策監控器")
        self.root.geometry("560x140")
        self.root.resizable(False, False)

        self.unauthorized_interface_patterns = tuple(
            get_effective_interface_patterns(policy_config)
        )
        self.interface_whitelist = {
            str(name).strip().lower()
            for name in policy_config.get("interface_whitelist", [])
            if str(name).strip()
        }

        self.status_text = tk.StringVar(
            value="正在監控 VPN/Proxy 政策遵循狀態"
        )
        self.status_label = tk.Label(
            root,
            textvariable=self.status_text,
            font=("Segoe UI", 11),
            wraplength=540,
            justify="left",
            anchor="w",
            padx=12,
            pady=20,
        )
        self.status_label.pack(fill="both", expand=True)

        self.disabled_interfaces = set()
        self.last_warning_popup_at = 0.0
        # 介面建立後即開始監控。
        self._schedule_next_check(initial=True)

    def _schedule_next_check(self, initial: bool = False) -> None:
        # 第一次使用較短延遲，啟動後可更快偵測違規。
        delay = INITIAL_CHECK_DELAY_MS if initial else CHECK_INTERVAL_MS
        self.root.after(delay, self.run_policy_checks)

    def run_policy_checks(self) -> None:
        try:
            interface_actions = self.remediate_network_interfaces()
            process_actions = self.enforce_process_policy()

            if interface_actions or process_actions:
                self.status_text.set(
                    "已執行政策管制動作，持續監控中。"
                )
            else:
                self.status_text.set("正在監控 VPN/Proxy 政策遵循狀態")
        except Exception as exc:  # noqa: BLE001 - 監控程式必須持續運行
            logging.exception("政策檢查發生錯誤：%s", exc)
            self.status_text.set(
                "政策檢查發生錯誤，詳情請查看 enforcement.log。"
            )
        finally:
            self._schedule_next_check()

    def remediate_network_interfaces(self) -> list[str]:
        actions = []
        try:
            interfaces = psutil.net_if_addrs()
        except Exception as exc:  # noqa: BLE001 - 權限或系統提供者錯誤
            logging.exception("查詢網路介面失敗：%s", exc)
            return actions

        for interface_name in interfaces:
            lower_name = interface_name.lower()

            if lower_name in self.interface_whitelist:
                continue

            # 以名稱關鍵字做啟發式比對，封鎖疑似 VPN/隧道介面。
            if not any(
                pattern in lower_name
                for pattern in self.unauthorized_interface_patterns
            ):
                continue

            if interface_name in self.disabled_interfaces:
                continue

            command = [
                "netsh",
                "interface",
                "set",
                "interface",
                interface_name,
                "admin=disable",
            ]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=NETSH_COMMAND_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                logging.error("停用介面 %s 時逾時", interface_name)
                continue
            if result.returncode == 0:
                self.disabled_interfaces.add(interface_name)
                action = f"已停用未授權網路介面：{interface_name}"
                actions.append(action)
                logging.info(action)
            else:
                logging.error(
                    "停用介面 %s 失敗（代碼 %s）：%s",
                    interface_name,
                    result.returncode,
                    (result.stderr or result.stdout).strip(),
                )
        return actions

    def enforce_process_policy(self) -> list[str]:
        actions = []
        violating_pids = set()

        try:
            for connection in psutil.net_connections(kind="inet"):
                # 找出監聽未授權代理埠的程序，稍後統一終止。
                if (
                    connection.status == psutil.CONN_LISTEN
                    and connection.laddr
                    and connection.laddr.port in UNAUTHORIZED_PROXY_PORTS
                    and isinstance(connection.pid, int)
                    and connection.pid > 0
                ):
                    violating_pids.add(connection.pid)
        except Exception as exc:  # noqa: BLE001 - 權限或系統提供者錯誤
            logging.exception("列舉監聽中的連線埠失敗：%s", exc)
            return actions

        for pid in violating_pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.terminate()
                try:
                    # 先嘗試正常結束，逾時才強制 kill。
                    proc.wait(timeout=PROCESS_TERMINATE_TIMEOUT_SECONDS)
                except psutil.TimeoutExpired:
                    proc.kill()
                action = f"已終止監聽未授權代理埠的程序：{proc_name}（PID {pid}）"
                actions.append(action)
                logging.warning(action)
            except psutil.NoSuchProcess:
                continue
            except Exception as exc:  # noqa: BLE001 - 監控程式必須持續運行
                logging.exception("終止 PID %s 失敗：%s", pid, exc)

        if actions and time.monotonic() - self.last_warning_popup_at >= WARNING_POPUP_COOLDOWN_SECONDS:
            self.last_warning_popup_at = time.monotonic()
            messagebox.showwarning(
                "政策管制",
                f"偵測到 VPN/Proxy 使用行為，已依政策終止 {len(actions)} 個程序。",
            )
        return actions


def get_program_data_dir() -> Path:
    return Path(os.environ.get("ProgramData", "C:/ProgramData"))


def get_app_data_dir() -> Path:
    return get_program_data_dir() / "LabMonitor"


def get_policy_config_path() -> Path:
    return get_app_data_dir() / POLICY_CONFIG_FILE_NAME


def get_startup_dir() -> Path:
    return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def get_installed_exe_path() -> Path:
    current_executable = Path(sys.executable)
    if current_executable.suffix.lower() == ".exe":
        return current_executable
    return get_startup_dir() / "lab_policy_watchdog.exe"


def build_default_policy_config() -> dict[str, Any]:
    return {
        "password_salt": "",
        "password_hash": "",
        "extra_interface_patterns": [],
        "interface_whitelist": [],
    }


def normalize_string_list(values: Any) -> list[str]:
    normalized = []
    seen = set()
    if not isinstance(values, list):
        return normalized
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        item_key = item.lower()
        if item_key in seen:
            continue
        normalized.append(item)
        seen.add(item_key)
    return normalized


def load_policy_config() -> dict[str, Any]:
    config = build_default_policy_config()
    config_path = get_policy_config_path()

    if not config_path.exists():
        return config

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - 配置檔毀損時回退預設值
        logging.exception("讀取設定檔失敗，改用預設值：%s", exc)
        return config

    if not isinstance(raw, dict):
        return config

    config["password_salt"] = str(raw.get("password_salt", ""))
    config["password_hash"] = str(raw.get("password_hash", ""))
    config["extra_interface_patterns"] = normalize_string_list(
        raw.get("extra_interface_patterns", [])
    )
    config["interface_whitelist"] = normalize_string_list(
        raw.get("interface_whitelist", [])
    )
    return config


def save_policy_config(config: dict[str, Any]) -> None:
    app_dir = get_app_data_dir()
    app_dir.mkdir(parents=True, exist_ok=True)
    config_path = get_policy_config_path()
    payload = {
        "password_salt": str(config.get("password_salt", "")),
        "password_hash": str(config.get("password_hash", "")),
        "extra_interface_patterns": normalize_string_list(
            config.get("extra_interface_patterns", [])
        ),
        "interface_whitelist": normalize_string_list(
            config.get("interface_whitelist", [])
        ),
    }
    config_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def get_effective_interface_patterns(policy_config: dict[str, Any]) -> list[str]:
    patterns = []
    seen = set()

    for pattern in UNAUTHORIZED_INTERFACE_PATTERNS:
        lower = pattern.strip().lower()
        if lower and lower not in seen:
            patterns.append(lower)
            seen.add(lower)

    for pattern in policy_config.get("extra_interface_patterns", []):
        lower = str(pattern).strip().lower()
        if lower and lower not in seen:
            patterns.append(lower)
            seen.add(lower)

    return patterns


def has_initialized_password(policy_config: dict[str, Any]) -> bool:
    return bool(
        str(policy_config.get("password_salt", "")).strip()
        and str(policy_config.get("password_hash", "")).strip()
    )


def derive_password_hash(password: str, salt_hex: str) -> str:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return ""
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return digest.hex()


def prompt_new_password() -> str | None:
    password = getpass.getpass("請設定管理密碼：").strip()
    if len(password) < 6:
        print("密碼長度至少需要 6 個字元。", file=sys.stderr)
        return None

    confirm = getpass.getpass("請再次輸入管理密碼：").strip()
    if password != confirm:
        print("兩次輸入的密碼不一致。", file=sys.stderr)
        return None
    return password


def set_admin_password(policy_config: dict[str, Any], new_password: str) -> None:
    salt_hex = secrets.token_hex(16)
    password_hash = derive_password_hash(new_password, salt_hex)
    policy_config["password_salt"] = salt_hex
    policy_config["password_hash"] = password_hash


def verify_admin_password(policy_config: dict[str, Any]) -> bool:
    if not has_initialized_password(policy_config):
        print("尚未初始化管理密碼，請先執行 --install-init。", file=sys.stderr)
        return False

    password = getpass.getpass("請輸入管理密碼：")
    expected_hash = str(policy_config.get("password_hash", ""))
    actual_hash = derive_password_hash(
        password,
        str(policy_config.get("password_salt", "")),
    )
    return bool(actual_hash) and hmac.compare_digest(actual_hash, expected_hash)


def print_policy_settings(policy_config: dict[str, Any]) -> None:
    patterns = get_effective_interface_patterns(policy_config)
    whitelist = normalize_string_list(policy_config.get("interface_whitelist", []))

    print("目前政策設定：")
    print("- 未授權介面關鍵字：")
    for pattern in patterns:
        print(f"  - {pattern}")

    print("- 介面白名單：")
    if whitelist:
        for interface_name in whitelist:
            print(f"  - {interface_name}")
    else:
        print("  - （無）")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="教室網路政策監控器與管理工具"
    )
    command_group = parser.add_mutually_exclusive_group(required=False)
    command_group.add_argument(
        "--install-init",
        action="store_true",
        help="初始化安裝設定並建立管理密碼",
    )
    command_group.add_argument(
        "--show-settings",
        action="store_true",
        help="顯示目前設定（不需密碼）",
    )
    command_group.add_argument(
        "--add-interface-pattern",
        metavar="KEYWORD",
        help="新增未授權隧道介面關鍵字（需密碼）",
    )
    command_group.add_argument(
        "--remove-interface-pattern",
        metavar="KEYWORD",
        help="移除未授權隧道介面關鍵字（需密碼）",
    )
    command_group.add_argument(
        "--add-interface-whitelist",
        metavar="INTERFACE",
        help="新增介面白名單（需密碼）",
    )
    command_group.add_argument(
        "--remove-interface-whitelist",
        metavar="INTERFACE",
        help="移除介面白名單（需密碼）",
    )
    command_group.add_argument(
        "--uninstall",
        action="store_true",
        help="解安裝並刪除設定與記錄（需密碼）",
    )
    return parser.parse_args()


def has_management_command(args: argparse.Namespace) -> bool:
    return any(
        (
            args.install_init,
            args.show_settings,
            args.add_interface_pattern,
            args.remove_interface_pattern,
            args.add_interface_whitelist,
            args.remove_interface_whitelist,
            args.uninstall,
        )
    )


def show_startup_error(title: str, message: str) -> None:
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        print(message, file=sys.stderr)


def handle_management_command(args: argparse.Namespace) -> int:
    if not has_management_command(args):
        return -1

    policy_config = load_policy_config()

    if args.install_init:
        if has_initialized_password(policy_config):
            print("已存在管理密碼，請先驗證身分以重設。")
            if not verify_admin_password(policy_config):
                print("管理密碼錯誤。", file=sys.stderr)
                return 1

        new_password = prompt_new_password()
        if not new_password:
            return 1

        set_admin_password(policy_config, new_password)
        save_policy_config(policy_config)
        print(f"初始化完成，設定檔位置：{get_policy_config_path()}")
        return 0

    if args.show_settings:
        print_policy_settings(policy_config)
        return 0

    if not verify_admin_password(policy_config):
        print("管理密碼錯誤。", file=sys.stderr)
        return 1

    if args.add_interface_pattern:
        pattern = args.add_interface_pattern.strip().lower()
        if not pattern:
            print("關鍵字不可為空。", file=sys.stderr)
            return 1

        current = normalize_string_list(policy_config.get("extra_interface_patterns", []))
        if pattern in {item.lower() for item in current}:
            print(f"關鍵字已存在：{pattern}")
            return 0

        current.append(pattern)
        policy_config["extra_interface_patterns"] = current
        save_policy_config(policy_config)
        print(f"已新增未授權介面關鍵字：{pattern}")
        return 0

    if args.remove_interface_pattern:
        pattern = args.remove_interface_pattern.strip().lower()
        if not pattern:
            print("關鍵字不可為空。", file=sys.stderr)
            return 1

        current = normalize_string_list(policy_config.get("extra_interface_patterns", []))
        filtered = [item for item in current if item.lower() != pattern]
        if len(filtered) == len(current):
            print(f"找不到關鍵字：{pattern}")
            return 1

        policy_config["extra_interface_patterns"] = filtered
        save_policy_config(policy_config)
        print(f"已移除未授權介面關鍵字：{pattern}")
        return 0

    if args.add_interface_whitelist:
        interface_name = args.add_interface_whitelist.strip()
        if not interface_name:
            print("介面名稱不可為空。", file=sys.stderr)
            return 1

        current = normalize_string_list(policy_config.get("interface_whitelist", []))
        if interface_name.lower() in {item.lower() for item in current}:
            print(f"白名單已存在：{interface_name}")
            return 0

        current.append(interface_name)
        policy_config["interface_whitelist"] = current
        save_policy_config(policy_config)
        print(f"已新增介面白名單：{interface_name}")
        return 0

    if args.remove_interface_whitelist:
        interface_name = args.remove_interface_whitelist.strip()
        if not interface_name:
            print("介面名稱不可為空。", file=sys.stderr)
            return 1

        current = normalize_string_list(policy_config.get("interface_whitelist", []))
        filtered = [item for item in current if item.lower() != interface_name.lower()]
        if len(filtered) == len(current):
            print(f"白名單不存在：{interface_name}")
            return 1

        policy_config["interface_whitelist"] = filtered
        save_policy_config(policy_config)
        print(f"已移除介面白名單：{interface_name}")
        return 0

    if args.uninstall:
        app_dir = get_app_data_dir()
        installed_exe_path = get_installed_exe_path()
        if installed_exe_path.exists():
            installed_exe_path.unlink()
            print(f"已移除自啟動主程式：{installed_exe_path}")
        if app_dir.exists():
            shutil.rmtree(app_dir)
            print(f"已完成解安裝，移除資料夾：{app_dir}")
        else:
            print("未找到安裝資料夾，無需解安裝。")
        return 0

    return -1


def configure_logging() -> None:
    # 將記錄寫入 ProgramData，讓不同使用者工作階段都能存取。
    log_dir = get_app_data_dir()
    log_dir.mkdir(parents=True, exist_ok=True)

    log_path = log_dir / "enforcement.log"
    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def is_windows_admin() -> bool:
    try:
        # 執行 netsh 停用網路介面需要系統管理員權限。
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> int:
    args = parse_args()

    if os.name != "nt":
        print("此工具僅支援在 Windows 上執行。", file=sys.stderr)
        return 1

    if not is_windows_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "需要系統管理員權限",
            "請以系統管理員身分執行此應用程式。",
        )
        root.destroy()
        return 1

    command_result = handle_management_command(args)
    if command_result >= 0:
        return command_result

    configure_logging()
    policy_config = load_policy_config()
    if not has_initialized_password(policy_config):
        show_startup_error(
            "尚未完成初始化",
            "尚未初始化管理密碼，請先執行 install.cmd 或使用 --install-init。",
        )
        return 1

    logging.info("教室網路政策監控器已啟動。")

    root = tk.Tk()
    PolicyWatchdogApp(root, policy_config)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
