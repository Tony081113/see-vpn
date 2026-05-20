import ctypes
import logging
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

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


class PolicyWatchdogApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Classroom Network Policy Watchdog")
        self.root.geometry("560x140")
        self.root.resizable(False, False)

        self.status_text = tk.StringVar(
            value="Monitoring for VPN/Proxy Policy Compliance"
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
        self._schedule_next_check(initial=True)

    def _schedule_next_check(self, initial: bool = False) -> None:
        delay = INITIAL_CHECK_DELAY_MS if initial else CHECK_INTERVAL_MS
        self.root.after(delay, self.run_policy_checks)

    def run_policy_checks(self) -> None:
        try:
            interface_actions = self.remediate_network_interfaces()
            process_actions = self.enforce_process_policy()

            if interface_actions or process_actions:
                self.status_text.set(
                    "Policy enforcement actions executed. Monitoring continues."
                )
            else:
                self.status_text.set("Monitoring for VPN/Proxy Policy Compliance")
        except Exception as exc:  # noqa: BLE001 - watchdog must continue running
            logging.exception("Policy check error: %s", exc)
            self.status_text.set(
                "Policy check encountered an error. See enforcement.log for details."
            )
        finally:
            self._schedule_next_check()

    def remediate_network_interfaces(self) -> list[str]:
        actions = []
        try:
            interfaces = psutil.net_if_addrs()
        except Exception as exc:  # noqa: BLE001 - permission/provider errors
            logging.exception("Failed to query network interfaces: %s", exc)
            return actions

        for interface_name in interfaces:
            lower_name = interface_name.lower()
            if not any(
                pattern in lower_name for pattern in UNAUTHORIZED_INTERFACE_PATTERNS
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
                logging.error("Timed out while disabling interface %s", interface_name)
                continue
            if result.returncode == 0:
                self.disabled_interfaces.add(interface_name)
                action = f"Disabled unauthorized interface: {interface_name}"
                actions.append(action)
                logging.info(action)
            else:
                logging.error(
                    "Failed disabling interface %s (code %s): %s",
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
                if (
                    connection.status == psutil.CONN_LISTEN
                    and connection.laddr
                    and connection.laddr.port in UNAUTHORIZED_PROXY_PORTS
                    and isinstance(connection.pid, int)
                    and connection.pid > 0
                ):
                    violating_pids.add(connection.pid)
        except Exception as exc:  # noqa: BLE001 - permission/provider errors
            logging.exception("Failed to enumerate listening sockets: %s", exc)
            return actions

        for pid in violating_pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.terminate()
                try:
                    proc.wait(timeout=PROCESS_TERMINATE_TIMEOUT_SECONDS)
                except psutil.TimeoutExpired:
                    proc.kill()
                action = f"Terminated process on unauthorized proxy port: {proc_name} (PID {pid})"
                actions.append(action)
                logging.warning(action)
            except psutil.NoSuchProcess:
                continue
            except Exception as exc:  # noqa: BLE001 - watchdog must continue
                logging.exception("Failed terminating PID %s: %s", pid, exc)

        if actions:
            messagebox.showwarning(
                "Policy Enforcement",
                f"VPN/Proxy usage detected. Terminated {len(actions)} process(es) for policy compliance.",
            )
        return actions


def configure_logging() -> None:
    program_data = Path(os.environ.get("ProgramData", "C:/ProgramData"))
    log_dir = program_data / "LabMonitor"
    log_dir.mkdir(parents=True, exist_ok=True)

    log_path = log_dir / "enforcement.log"
    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> int:
    if os.name != "nt":
        print("This tool is intended to run on Windows.", file=sys.stderr)
        return 1

    if not is_windows_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Administrator Privileges Required",
            "Please run this application as Administrator.",
        )
        root.destroy()
        return 1

    configure_logging()
    logging.info("Classroom Network Policy Watchdog started.")

    root = tk.Tk()
    PolicyWatchdogApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
