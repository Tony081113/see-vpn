import getpass
import hashlib
import json
import os
import secrets
import shutil
import sys
from pathlib import Path


BUNDLED_FILES = (
    "lab_policy_watchdog.exe",
)
PASSWORD_HASH_ITERATIONS = 200000
POLICY_CONFIG_FILE_NAME = "policy_config.json"
APP_EXE_NAME = "lab_policy_watchdog.exe"


def get_bundle_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def get_install_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def get_startup_dir() -> Path:
    app_data = Path(os.environ.get("APPDATA", ""))
    if not app_data:
        raise RuntimeError("找不到 APPDATA，無法取得自啟動路徑。")
    return app_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def get_installed_exe_path() -> Path:
    return get_startup_dir() / APP_EXE_NAME


def copy_bundled_files(bundle_dir: Path, install_dir: Path) -> None:
    install_dir.mkdir(parents=True, exist_ok=True)
    for file_name in BUNDLED_FILES:
        source = bundle_dir / file_name
        target = install_dir / file_name
        shutil.copy2(source, target)


def get_program_data_dir() -> Path:
    return Path(os.environ.get("ProgramData", "C:/ProgramData"))


def get_app_data_dir() -> Path:
    return get_program_data_dir() / "LabMonitor"


def get_policy_config_path() -> Path:
    return get_app_data_dir() / POLICY_CONFIG_FILE_NAME


def derive_password_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return digest.hex()


def prompt_new_password() -> str:
    password = getpass.getpass("請設定管理密碼：").strip()
    if len(password) < 6:
        raise RuntimeError("密碼長度至少需要 6 個字元。")

    confirm = getpass.getpass("請再次輸入管理密碼：").strip()
    if password != confirm:
        raise RuntimeError("兩次輸入的密碼不一致。")

    return password


def write_policy_config(password: str) -> None:
    app_data_dir = get_app_data_dir()
    app_data_dir.mkdir(parents=True, exist_ok=True)
    salt_hex = secrets.token_hex(16)
    payload = {
        "password_salt": salt_hex,
        "password_hash": derive_password_hash(password, salt_hex),
        "extra_interface_patterns": [],
        "interface_whitelist": [],
    }
    get_policy_config_path().write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def install() -> None:
    bundle_dir = get_bundle_dir()
    install_dir = get_install_dir()
    startup_dir = get_startup_dir()
    installed_exe_path = get_installed_exe_path()

    print("=== 教室網路政策監控器 安裝程式 ===")
    print(f"安裝來源：{install_dir}")
    print(f"自啟動路徑：{startup_dir}")

    print("[1/3] 解出並安裝主程式到自啟動路徑")
    copy_bundled_files(bundle_dir, install_dir)
    startup_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(install_dir / APP_EXE_NAME, installed_exe_path)

    print("[2/3] 初始化管理密碼")
    password = prompt_new_password()
    write_policy_config(password)

    print("[3/3] 安裝完成")
    print("啟動方式：")
    print(installed_exe_path)


def main() -> int:
    try:
        install()
        input("按 Enter 結束安裝程式...")
        return 0
    except Exception as exc:  # noqa: BLE001 - 安裝程式需顯示所有錯誤
        print(f"安裝失敗：{exc}", file=sys.stderr)
        input("按 Enter 關閉安裝程式...")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())