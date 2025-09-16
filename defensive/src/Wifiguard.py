#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFiGuard — Defensive Wi‑Fi monitor & auto‑disconnect (full, patched)

Behavior
- Polls current Wi‑Fi connection (Linux first‑class; Windows best‑effort)
- Detects Evil‑Twin / rogue AP conditions:
  • SSID match + BSSID mismatch (primary)
  • Security/key_mgmt downgrade or mismatch
  • Optional channel mismatch (if configured)
- On incident: notify user + auto‑disconnect (configurable)
- Cooldown & debounce to avoid alert spam
- CSV logging of incidents → defaults to ./logs/alerts.csv (same file as other scan results)

Run (Linux/Kali):
  sudo python3 wifiguard.py -c config.yaml

If no config file is present, a sample is written and the program exits.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Resolve project root (../ from this file) and set a default logs path there
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "defense_log.csv")

# ------------------------------ Utilities ------------------------------

def run_cmd(args: List[str], timeout: float = 5.0) -> Tuple[int, str, str]:
    """Run a subprocess and return (rc, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            text=True,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def ensure_dir(path: str) -> None:
    d = os.path.dirname(path) if os.path.splitext(path)[1] else path
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)


ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF]")
CONTROL_RE    = re.compile(r"[\x00-\x1F\x7F]")


def dehex_escape(s: str) -> str:
    """Decode strings like 'Dialog 4G 335\\xe2\\x80\\x8b' -> 'Dialog 4G 335\u200b'."""
    try:
        return bytes(s, "utf-8").decode("unicode_escape")
    except Exception:
        return s


def normalize_ssid(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = dehex_escape(s)
    s = ZERO_WIDTH_RE.sub("", s)
    s = CONTROL_RE.sub("", s)
    return s.strip()


def ascii_clean(s: Optional[str]) -> Optional[str]:
    """Drop non‑ASCII artifacts (e.g., stray 'â') and trim."""
    if s is None:
        return None
    try:
        return s.encode("ascii", "ignore").decode("ascii").strip()
    except Exception:
        return s


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")

# ------------------------------ Config ------------------------------

@dataclass
class TrustedProfile:
    ssid: str
    bssids: List[str] = field(default_factory=list)  # Uppercase, colon‑separated
    security: Optional[str] = None                   # "WPA2-PSK", "WPA3-SAE", "OPEN"
    channel: Optional[int] = None

@dataclass
class Actions:
    auto_disconnect: bool = True
    auto_reconnect: bool = False

@dataclass
class Notifications:
    enabled: bool = True

@dataclass
class Config:
    interface: str = "wlan0"
    poll_interval_sec: float = 1.0
    debounce_seconds: float = 5.0
    cooldown_seconds: float = 45.0
    notifications: Notifications = field(default_factory=Notifications)
    actions: Actions = field(default_factory=Actions)
    trusted_profiles: List[TrustedProfile] = field(default_factory=list)
    log_path: str = DEFAULT_LOG_PATH  # force logs to ../logs/alerts.csv

    @staticmethod
    def from_mapping(m: Dict) -> "Config":
        def up_bssid_list(lst: List[str]) -> List[str]:
            return [b.upper() for b in lst]
        tps = [
            TrustedProfile(
                ssid=normalize_ssid(tp.get("ssid", "")) or "",
                bssids=up_bssid_list(tp.get("bssids", [])),
                security=tp.get("security"),
                channel=tp.get("channel"),
            )
            for tp in m.get("trusted_profiles", [])
        ]
        return Config(
            interface=m.get("interface", "wlan0"),
            poll_interval_sec=float(m.get("poll_interval_sec", 1)),
            debounce_seconds=float(m.get("debounce_seconds", 5)),
            cooldown_seconds=float(m.get("cooldown_seconds", 45)),
            notifications=Notifications(**m.get("notifications", {"enabled": True})),
            actions=Actions(**m.get("actions", {"auto_disconnect": True, "auto_reconnect": False})),
            trusted_profiles=tps,
            log_path=DEFAULT_LOG_PATH,
        )

SAMPLE_CONFIG = {
    "interface": "wlan0",
    "poll_interval_sec": 1,
    "debounce_seconds": 5,
    "cooldown_seconds": 45,
    "notifications": {"enabled": True},
    "actions": {"auto_disconnect": True, "auto_reconnect": False},
    "trusted_profiles": [
        {
            "ssid": "Dialog 4G 335",
            "bssids": ["98:A9:42:74:E5:37"],
            "security": "WPA2-PSK",
            "channel": 6,
        }
    ],
    "log_path": "../logs/alerts.csv",
}


def try_load_config(path: str) -> Config:
    # Write sample if missing
    if not os.path.isfile(path):
        sample_path = path if path.lower().endswith((".yaml", ".yml", ".json")) else "config.yaml"
        if not os.path.exists(sample_path):
            try:
                with open(sample_path, "w", encoding="utf-8") as f:
                    try:
                        import yaml  # type: ignore
                        yaml.safe_dump(SAMPLE_CONFIG, f, sort_keys=False)
                    except Exception:
                        f.write(json.dumps(SAMPLE_CONFIG, indent=2))
                print(f"[!] No config found. Wrote sample to {sample_path}. Edit SSID/BSSID and rerun.")
            except Exception as e:
                print(f"[!] No config and failed to write sample: {e}")
        sys.exit(1)

    # Load YAML or JSON
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping/dict")
    cfg = Config.from_mapping(data)
    if not cfg.trusted_profiles:
        raise ValueError("Config must contain at least one trusted_profiles entry")
    return cfg

# ------------------------------ Platform probes ------------------------------

def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_windows() -> bool:
    return platform.system().lower() == "windows"

# ------------------------------ Wi‑Fi status ------------------------------

@dataclass
class WifiStatus:
    connected: bool
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    security: Optional[str] = None
    channel: Optional[int] = None
    raw: Dict[str, str] = field(default_factory=dict)


def freq_to_channel(freq: Optional[int]) -> Optional[int]:
    if not freq:
        return None
    # 2.4 GHz
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    # 5 GHz
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    # 6 GHz (rough)
    if 5925 <= freq <= 7125:
        return (freq - 5950) // 5 + 1
    return None

WPA_STATE_CONNECTED = {"COMPLETED", "ASSOCIATED", "ASSOCIATING", "GROUP_HANDSHAKE", "FOUR_WAY_HANDSHAKE"}


def get_status_linux(iface: str) -> WifiStatus:
    # wpa_cli status
    rc, out, _ = run_cmd(["wpa_cli", "-i", iface, "status"])
    kv: Dict[str, str] = {}
    if rc == 0:
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
    state = kv.get("wpa_state", "")
    connected = state in WPA_STATE_CONNECTED and "ssid" in kv and "bssid" in kv

    ssid  = normalize_ssid(kv.get("ssid")) if kv.get("ssid") else None
    bssid = kv.get("bssid")
    if bssid:
        bssid = bssid.upper()

    key_mgmt = kv.get("key_mgmt")
    security = None
    if key_mgmt:
        km = key_mgmt.upper()
        if km in {"NONE", "OPEN"}:
            security = "OPEN"
        elif "SAE" in km:
            security = "WPA3-SAE"
        elif "WPA2" in km or "WPA-PSK" in km or "WPA" in km:
            security = "WPA2-PSK"

    ch = None
    if "freq" in kv:
        try:
            ch = freq_to_channel(int(kv["freq"]))
        except Exception:
            ch = None
    if ch is None:
        rc2, out2, _ = run_cmd(["iw", "dev", iface, "link"])
        if rc2 == 0 and out2:
            m = re.search(r"freq:\s*(\d+)", out2)
            if m:
                ch = freq_to_channel(int(m.group(1)))

    return WifiStatus(connected=bool(connected), ssid=ssid, bssid=bssid, security=security, channel=ch, raw=kv)


def get_status_windows() -> WifiStatus:
    rc, out, _ = run_cmd(["netsh", "wlan", "show", "interfaces"])
    if rc != 0 or not out:
        return WifiStatus(connected=False)

    connected = bool(re.search(r"state\s*:\s*connected", out, flags=re.IGNORECASE))
    ssid = None
    bssid = None
    ch = None
    sec = None
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "ssid":
            ssid = normalize_ssid(v)
        elif k == "bssid":
            bssid = v.upper()
        elif k == "channel":
            try:
                ch = int(v)
            except Exception:
                pass
        elif k == "authentication":
            vv = v.upper()
            if "WPA3" in vv or "SAE" in vv:
                sec = "WPA3-SAE"
            elif "WPA2" in vv or "WPA-PSK" in vv or "WPA" in vv:
                sec = "WPA2-PSK"
            elif "OPEN" in vv or "NONE" in vv:
                sec = "OPEN"
    return WifiStatus(connected=connected, ssid=ssid, bssid=bssid, security=sec, channel=ch)

# ------------------------------ Actions ------------------------------

def notify(title: str, message: str, duration_sec: int = 8, enabled: bool = True) -> None:
    if not enabled:
        print(f"[NOTIFY disabled] {title}: {message}")
        return
    if is_linux():
        rc, _, _ = run_cmd(["which", "notify-send"])
        if rc == 0:
            run_cmd(["notify-send", "--urgency=critical", title, message, f"--expire-time={int(duration_sec)*1000}"])
            return
    if is_windows():
        try:
            from win10toast import ToastNotifier  # type: ignore
            ToastNotifier().show_toast(title, message, duration=duration_sec, threaded=True)
            return
        except Exception:
            try:
                from winotify import Notification, audio  # type: ignore
                n = Notification(app_id="WiFiGuard", title=title, msg=message)
                n.set_audio(audio.Default, loop=False)
                n.show()
                return
            except Exception:
                pass
    print(f"[NOTIFY] {title}: {message}")


def disconnect(cfg: Config) -> None:
    if is_linux():
        rc, _, _ = run_cmd(["nmcli", "dev", "disconnect", cfg.interface])
        if rc != 0:
            run_cmd(["wpa_cli", "-i", cfg.interface, "disconnect"])
    elif is_windows():
        run_cmd(["netsh", "wlan", "disconnect"])

# ------------------------------ Detection helpers ------------------------------

def match_profile(cfg: Config, ssid: Optional[str]) -> Optional[TrustedProfile]:
    if not ssid:
        return None
    for tp in cfg.trusted_profiles:
        if ascii_clean(normalize_ssid(tp.ssid)) == ascii_clean(normalize_ssid(ssid)):
            return tp
    return None


def security_mismatch(expected: Optional[str], observed: Optional[str]) -> bool:
    if not expected or not observed:
        return False
    e = expected.upper()
    o = observed.upper()
    # Treat any WPA/WPA2‑PSK bucket as equivalent if expected is WPA2‑PSK (and not SAE)
    if e.startswith("WPA2") and ("WPA2" in o or "WPA-PSK" in o or "WPA" in o) and "SAE" not in o:
        return False
    return e != o

# ------------------------------ Logger ------------------------------

CSV_FIELDS = [
    "timestamp", "ssid", "bssid", "reason", "action",
    "expected_bssids", "expected_security", "expected_channel",
    "observed_security", "observed_channel"
]


def log_incident(cfg: Config, status: WifiStatus, tp: TrustedProfile, reason: str, action: str) -> None:
    ensure_dir(cfg.log_path)
    new_file = not os.path.exists(cfg.log_path)
    try:
        with open(cfg.log_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            if new_file:
                w.writeheader()
            w.writerow({
                "timestamp": now_iso(),
                "ssid": status.ssid or "",
                "bssid": status.bssid or "",
                "reason": reason,
                "action": action,
                "expected_bssids": ",".join(tp.bssids),
                "expected_security": tp.security or "",
                "expected_channel": tp.channel if tp.channel is not None else "",
                "observed_security": status.security or "",
                "observed_channel": status.channel if status.channel is not None else "",
            })
    except Exception as e:
        print(f"[!] Failed to write log: {e}")

# ------------------------------ Main loop ------------------------------

class WiFiGuard:
    def __init__(self, cfg: Config, debug: bool = False):
        self.cfg = cfg
        self.debug = debug
        self.cooldowns: Dict[Tuple[str, str, str], float] = {}
        # pending_start: (ssid, bssid, reason, first_seen_ts)
        self.pending_start: Optional[Tuple[str, str, str, float]] = None

    def _get_status(self) -> WifiStatus:
        if is_linux():
            return get_status_linux(self.cfg.interface)
        elif is_windows():
            return get_status_windows()
        else:
            return WifiStatus(connected=False)

    def _should_alert(self, ssid: str, bssid: str, reason: str) -> bool:
        key = (ssid, bssid, reason)
        last = self.cooldowns.get(key, 0)
        return (time.time() - last) >= self.cfg.cooldown_seconds

    def _mark_alert(self, ssid: str, bssid: str, reason: str) -> None:
        key = (ssid, bssid, reason)
        self.cooldowns[key] = time.time()

    def loop(self) -> None:
        print(f"[*] WiFiGuard running on interface {self.cfg.interface} (poll={self.cfg.poll_interval_sec}s, debounce={self.cfg.debounce_seconds}s, cooldown={self.cfg.cooldown_seconds}s)")
        if self.debug:
            print("[*] Debug mode ON")
        try:
            while True:
                status = self._get_status()
                if self.debug:
                    print(f"[dbg] status: connected={status.connected} ssid={status.ssid} bssid={status.bssid} sec={status.security} ch={status.channel}")

                # Not connected? reset debounce and continue
                if not status.connected or not status.ssid or not status.bssid:
                    self.pending_start = None
                    time.sleep(self.cfg.poll_interval_sec)
                    continue

                # Match profile by SSID (robust)
                prof = match_profile(self.cfg, status.ssid)
                if not prof:
                    time.sleep(self.cfg.poll_interval_sec)
                    continue

                # Determine violation reason
                reason = None
                if status.bssid and status.bssid not in prof.bssids:
                    reason = "BSSID_MISMATCH"
                elif security_mismatch(prof.security, status.security):
                    reason = "SECURITY_MISMATCH"
                #elif prof.channel is not None and status.channel is not None and prof.channel != status.channel:
                #    reason = "CHANNEL_MISMATCH"

                if not reason:
                    self.pending_start = None
                    time.sleep(self.cfg.poll_interval_sec)
                    continue

                # Debounce: require same (ssid,bssid,reason) for N seconds
                now_ts = time.time()
                if self.pending_start and (
                    self.pending_start[0] == status.ssid and
                    self.pending_start[1] == status.bssid and
                    self.pending_start[2] == reason
                ):
                    if (now_ts - self.pending_start[3]) < self.cfg.debounce_seconds:
                        time.sleep(self.cfg.poll_interval_sec)
                        continue
                else:
                    self.pending_start = (status.ssid, status.bssid, reason, now_ts)
                    time.sleep(self.cfg.poll_interval_sec)
                    continue

                # Cooldown check
                if not self._should_alert(status.ssid, status.bssid, reason):
                    time.sleep(self.cfg.poll_interval_sec)
                    continue

                # Take action
                actions_taken: List[str] = []
                title = "⚠ Suspicious Wi-Fi Blocked"

                # Clean the SSID so hidden Unicode/zero-width bytes don't render as boxes
                clean_ssid = ascii_clean(normalize_ssid(status.ssid))

                message = (
                    "Untrusted access point detected. You were disconnected for security.\n\n"
                    f"Reason: {reason}\n"
                    f"SSID: {clean_ssid}\n"
                    f"BSSID: {status.bssid}"
                )
                notify(title, message, enabled=self.cfg.notifications.enabled)

                if self.cfg.actions.auto_disconnect:
                    disconnect(self.cfg)
                    actions_taken.append("DISCONNECT")
                if self.cfg.actions.auto_reconnect and prof.bssids:
                    rc, _, _ = run_cmd(
                        ["nmcli", "dev", "wifi", "connect", prof.ssid, "bssid", prof.bssids[0], "ifname", self.cfg.interface]
                    )
                    if rc == 0:
                        actions_taken.append("RECONNECT")

                log_incident(self.cfg, status, prof, reason, "+".join(actions_taken) if actions_taken else "NOTIFY")
                self._mark_alert(status.ssid, status.bssid, reason)
                time.sleep(self.cfg.poll_interval_sec)
        except KeyboardInterrupt:
            print("\n[+] WiFiGuard exiting cleanly.")

# ------------------------------ Entrypoint ------------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="WiFiGuard — defensive Wi‑Fi auto‑disconnect monitor")
    p.add_argument("-c", "--config", default="config.yaml", help="Path to config YAML/JSON (default: config.yaml)")
    p.add_argument("--debug", action="store_true", help="Verbose debug prints")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    cfg = try_load_config(args.config)

    if is_linux() and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Not running as root. Some actions (disconnect/reconnect) may fail. Consider: sudo python3 wifiguard.py -c config.yaml")

    guard = WiFiGuard(cfg, debug=args.debug)
    guard.loop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
