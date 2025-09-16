#!/usr/bin/env python3
# scanner.py  (Linux/Kali/Ubuntu) Hybrid mode: airmon-ng preferred, iw fallback
import os
import re
import glob
import time
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple

# Reuse stable paths from utils.py
try:
    from utils import LOGS_DIR, guess_csv_path
except Exception:
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    LOGS_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "logs"))
    os.makedirs(LOGS_DIR, exist_ok=True)
    def guess_csv_path(out_prefix: str) -> str:
        return f"{out_prefix}-01.csv"

# ---------------------------
# Safety / environment checks
# ---------------------------
def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("This action requires root. Run with sudo (e.g., sudo python3 main.py).")

def _ensure_tools(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise RuntimeError(f"Missing tools: {', '.join(missing)}. Install them (e.g., sudo apt install aircrack-ng iw iproute2).")

# ---------------------------
# Interface discovery helpers
# ---------------------------
def list_interfaces() -> List[Tuple[str, str]]:
    """Returns a list of (iface, type) from `iw dev`."""
    _ensure_tools("iw")
    out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
    ifaces: List[Tuple[str, str]] = []
    cur = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            if cur:
                ifaces.append((cur.get("name",""), cur.get("type","managed")))
                cur = {}
            cur["name"] = line.split()[-1]
        elif line.startswith("type"):
            cur["type"] = line.split()[-1]
    if cur:
        ifaces.append((cur.get("name",""), cur.get("type","managed")))
    return ifaces

def _troubleshoot_banner() -> None:
    print("\n[!] No wireless interfaces found.")
    print("    • Plug in / enable your Wi-Fi adapter")
    print("    • If in a VM, attach the USB Wi-Fi to the guest (VM menu)")
    print("    • Unblock with:   sudo rfkill unblock all")
    print("    • See devices:    ifconfig | iwconfig | lspci | iw dev")
    print("    • Then press [R] to refresh, or [Q] to quit.\n")

def pick_interface(interactive: bool = True, auto_refresh: bool = True, refresh_interval: float = 2.0) -> str:
    """Interactive interface selection."""
    while True:
        ifaces = list_interfaces()
        if ifaces:
            break
        if not interactive:
            raise RuntimeError("No wireless interfaces found. Plug in a Wi-Fi adapter or enable the internal card.")
        _troubleshoot_banner()
        choice = input("[R]efresh / [Q]uit: ").strip().lower()
        if choice == "q":
            sys.exit(99)   # special exit code for user-quit
        if choice == "r" and auto_refresh:
            print("Waiting for adapter… (Ctrl+C to cancel)")
            for _ in range(int(max(1, 5 / refresh_interval))):
                time.sleep(refresh_interval)
                if list_interfaces():
                    break

    if len(ifaces) == 1 or not interactive:
        return ifaces[0][0]

    print("\nAvailable wireless interfaces:")
    for i,(name, itype) in enumerate(ifaces, 1):
        print(f"  {i}) {name}  ({itype})")
    while True:
        sel = input("Select interface number: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(ifaces):
            return ifaces[int(sel)-1][0]
        print("Invalid selection. Try again.")

# ---------------------------
# Monitor mode (Hybrid)
# ---------------------------
def set_monitor_mode_airmon(iface: str) -> Optional[str]:
    """Try airmon-ng first."""
    if shutil.which("airmon-ng") is None:
        return None
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["airmon-ng", "start", iface], check=True)
        # Detect renamed iface
        for name, itype in list_interfaces():
            if itype == "monitor":
                return name
    except subprocess.CalledProcessError:
        return None
    return None

def set_monitor_mode_iw(iface: str) -> str:
    """Fallback using iw (original logic)."""
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        time.sleep(0.5)
        return iface
    except subprocess.CalledProcessError:
        # Fallback: create monX
        out = subprocess.check_output(["iw", "dev"], text=True)
        phy = None
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith("Interface") and line.strip().endswith(iface):
                for j in range(i, -1, -1):
                    m = re.match(r"^\s*phy#(\d+)", lines[j].strip())
                    if m:
                        phy = m.group(1)
                        break
                break
        if not phy:
            raise RuntimeError(f"Could not determine PHY for {iface}.")
        mon_name = "mon0"
        existing = {n for (n, _) in list_interfaces()}
        idx = 0
        while mon_name in existing:
            idx += 1
            mon_name = f"mon{idx}"
        subprocess.run(["iw", f"phy#{phy}", "interface", "add", mon_name, "type", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", mon_name, "up"], check=True)
        time.sleep(0.5)
        return mon_name

def set_managed_mode_airmon(iface: str) -> None:
    if shutil.which("airmon-ng") is None:
        return
    try:
        subprocess.run(["airmon-ng", "stop", iface], check=True)
    except subprocess.CalledProcessError:
        pass

def set_managed_mode_iw(iface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)
    except subprocess.CalledProcessError:
        pass

def ensure_monitor_prompt(iface: str) -> str:
    """Ask user and try airmon-ng first, fallback to iw."""
    modes = dict(list_interfaces())
    cur_mode = modes.get(iface, "managed")
    if cur_mode == "monitor":
        print(f"[*] {iface} is already in monitor mode.")
        return iface

    print(f"[!] {iface} is currently in {cur_mode} mode.")
    choice = input("Switch to monitor mode? [y/N]: ").strip().lower()
    if choice == "y":
        print("[*] Trying airmon-ng...")
        mon_iface = set_monitor_mode_airmon(iface)
        if mon_iface:
            print(f"[*] Monitor mode enabled via airmon-ng: {mon_iface}")
            return mon_iface
        print("[!] airmon-ng failed, falling back to iw...")
        return set_monitor_mode_iw(iface)
    else:
        # NEW BEHAVIOR: retry goes straight to enabling monitor mode
        print("[!] Monitor mode is required for WiFiGuard to function.")
        retry = input("Do you want to retry? [Y/n]: ").strip().lower()
        if retry in ("y", "yes", ""):
            print("[*] Forcing monitor mode...")
            mon_iface = set_monitor_mode_airmon(iface)
            if mon_iface:
                print(f"[*] Monitor mode enabled via airmon-ng: {mon_iface}")
                return mon_iface
            print("[!] airmon-ng failed, falling back to iw...")
            return set_monitor_mode_iw(iface)
        else:
            print("[*] Exiting WiFiGuard. Stay safe.")
            sys.exit(99)   # special exit code handled by Main.py


# ---------------------------
# CSV helpers
# ---------------------------
def list_csv_series(out_prefix: str):
    paths = glob.glob(f"{out_prefix}-*.csv")
    items = []
    for p in paths:
        m = re.search(r"-(\d+)\.csv$", p)
        if m:
            try:
                items.append((int(m.group(1)), p))
            except ValueError:
                pass
    return sorted(items, key=lambda x: x[0])

def latest_csv_path(out_prefix: str) -> Optional[str]:
    items = list_csv_series(out_prefix)
    return items[-1][1] if items else None

# ---------------------------
# Airodump-ng
# ---------------------------
def start_airodump(
    iface: str,
    out_prefix: Optional[str] = None,
    channels: Optional[List[int]] = None,
    bssid: Optional[str] = None,
    essid: Optional[str] = None
) -> Tuple[subprocess.Popen, str, str]:
    _require_root()
    _ensure_tools("airodump-ng")

    if not out_prefix:
        out_prefix = os.path.join(LOGS_DIR, "scan")
    else:
        if not os.path.isabs(out_prefix):
            out_prefix = os.path.join(LOGS_DIR, os.path.basename(out_prefix))
    os.makedirs(os.path.dirname(out_prefix), exist_ok=True)

    prev_last = latest_csv_path(out_prefix)

    cmd = ["airodump-ng", "--band", "abg", "--output-format", "csv", "-w", out_prefix]
    if channels:
        cmd = ["airodump-ng", "--output-format", "csv", "-w", out_prefix,
               "-c", ",".join(str(c) for c in channels)]
    if bssid:
        cmd += ["--bssid", bssid]
    if essid:
        cmd += ["--essid", essid]
    cmd.append(iface)

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    csv_path = None
    for _ in range(60):
        now_last = latest_csv_path(out_prefix)
        if now_last and now_last != prev_last and os.path.getsize(now_last) > 0:
            csv_path = now_last
            break
        time.sleep(0.1)
    if not csv_path:
        csv_path = latest_csv_path(out_prefix) or guess_csv_path(out_prefix)

    return proc, csv_path, iface

def stop_airodump(proc: Optional[subprocess.Popen], restore_iface: Optional[str] = None, restore_managed: bool = False) -> None:
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    if restore_managed and restore_iface:
        if shutil.which("airmon-ng"):
            set_managed_mode_airmon(restore_iface)
        else:
            set_managed_mode_iw(restore_iface)

# ---------------------------
# CLI Test
# ---------------------------
if __name__ == "__main__":
    import sys
    try:
        _require_root()
        _ensure_tools("airodump-ng", "iw")

        if len(sys.argv) > 1:
            iface = sys.argv[1]
        else:
            iface = pick_interface(interactive=True, auto_refresh=True)

        chans = None
        if len(sys.argv) > 2:
            chans = [int(x) for x in sys.argv[2].split(",") if x.strip().isdigit()]

        actual_iface = ensure_monitor_prompt(iface)

        print(f"[*] Using interface: {actual_iface}")
        proc, csv, actual = start_airodump(actual_iface, out_prefix=os.path.join(LOGS_DIR, "scan"), channels=chans)
        print(f"[+] airodump-ng started on {actual}, writing: {csv}")
        try:
            for i in range(60, 0, -1):   # <<< changed from 30 to 60
                print(f"  capturing... {i:02d}s", end="\r", flush=True)
                time.sleep(1)
            print()
        finally:
            stop_airodump(proc, restore_iface=actual_iface, restore_managed=True)
            print("[✓] Stopped and restored managed mode")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        msg = str(e)
        if "No wireless interfaces found" in msg or "requires root" in msg or "Missing tools" in msg:
            print(f"[ERROR] {msg}")
            if "No wireless interfaces found" in msg:
                _troubleshoot_banner()
        else:
            print(f"[ERROR] {msg}")
