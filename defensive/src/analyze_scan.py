#!/usr/bin/env python3
"""
analyze_scan.py — one-shot (≤60s) CSV analyzer (quiet output)
- Directory: ~/Desktop/Applied project/defensive/logs
- Picks the latest numbered CSV: *-01.csv, *-02.csv, ...
- Skips alerts.csv and any non -NN.csv files

RULES:
  Global (any SSID):
    • Alert when high packet count per BSSID (sum of client #Packets) ≥ PACKET_THRESHOLD
      - If that BSSID’s ESSID is also duplicated across multiple BSSIDs, append "duplicate ESSID observed".
    • Duplicate ESSID alone is ignored (prevents campus/enterprise false positives)

  Targeted (only this network):
    • SSID = "Dialog 4G 335" AND BSSID != "98:A9:42:74:E5:37"  -> Evil Twin (alerts even without packet spike)
    • SSID = "Dialog 4G 335" AND privacy = OPN                -> Evil Twin (alerts even without packet spike)

Outputs:
- Prints only:
    [*] Monitoring logs in: ...
    [*] Using CSV: ...
  then either a single table of findings or the single line:
    [✓] No suspicious networks or activity detected.
- Desktop notification
- Appends to alerts.csv (in logs dir)
"""

import csv, os, re, time, shutil, subprocess, unicodedata
from collections import defaultdict, namedtuple
from typing import Dict, List, Optional, Tuple

# ========= Colors =========
RESET = "\033[0m"
BLUE  = "\033[38;5;39m"    # blue for important messages
GREEN = "\033[38;5;48m"    # green for general good messages
RED   = "\033[91m"         # red for errors/warnings

# ========= Config =========
LOGS_DIR = os.path.expanduser("~/Desktop/Applied project/defensive/logs")
ALERTS_LOG = os.path.join(LOGS_DIR, "alerts.csv")

PACKET_THRESHOLD = 1000     # suspicious when ≥ this many packets per BSSID (sum of client #Packets)
MAX_WAIT_SECONDS = 60       # give CSV time to collect non-zero packet counts
POLL_SECONDS = 1            # how often to poll for updates

# Output controls
DEBUG = False               # set True only when you want to see parsed APs/stations
QUIET_PROGRESS = True       # hide the repetitive "Scanning in process..." spinner

# Targeted rules — your trusted network
TRUSTED_SSID = "Dialog 4G 335"
TRUSTED_BSSID = "98:A9:42:74:E5:37"
TRUSTED_ENCRYPTION = "WPA2"  # for messages; we check privacy == "OPN"

AP = namedtuple("AP", [
    "bssid","first_seen","last_seen","channel","speed","privacy","cipher",
    "auth","power","beacons","iv","lan_ip","id_len","essid","key"
])

ST = namedtuple("ST", [
    "station_mac","first_seen","last_seen","power","packets","bssid","probed_essids"
])

# ========= Normalizers (fix hidden spaces / case / zero-width chars) =========
def norm_ssid(s: Optional[str]) -> str:
    s = (s or "")
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if not unicodedata.category(ch).startswith("C"))
    s = s.replace("\u00a0", " ")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s

def norm_bssid(s: Optional[str]) -> str:
    return (s or "").strip().upper()

TRUSTED_SSID_N = norm_ssid(TRUSTED_SSID)
TRUSTED_BSSID_N = norm_bssid(TRUSTED_BSSID)

# ========= Notifications =========
def notify(title: str, message: str, duration_sec: int = 8) -> None:
    if shutil.which("notify-send"):
        try:
            subprocess.Popen([
                "notify-send", title, message,
                "--hint=string:desktop-entry:WiFiGuardian",
                f"--expire-time={int(duration_sec)*1000}"
            ])
            return
        except Exception:
            pass
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(title, message, duration=duration_sec, threaded=True)
        return
    except Exception:
        pass
    try:
        from winotify import Notification, audio
        n = Notification(app_id="WiFiGuardian", title=title, msg=message)
        n.set_audio(audio.Default, loop=False); n.show(); return
    except Exception:
        pass
    print(f"[NOTIFY] {title}: {message}")

# ========= Helpers =========
def _print_table(headers: List[str], rows: List[List[str]]) -> None:
    try:
        from tabulate import tabulate
        print(tabulate(rows, headers=headers, tablefmt="github"))
    except Exception:
        widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
        def fmt(r): return " | ".join(str(c).ljust(w) for c, w in zip(r, widths))
        print(fmt(headers)); print("-+-".join("-"*w for w in widths))
        for r in rows: print(fmt(r))

def find_latest_csv() -> Optional[str]:
    """Pick the newest numbered airodump CSV (e.g., scan-01.csv, scan-02.csv), skip alerts.csv."""
    if not os.path.isdir(LOGS_DIR):
        return None
    candidates = []
    for f in os.listdir(LOGS_DIR):
        if f == os.path.basename(ALERTS_LOG):
            continue
        if re.search(r"-\d+\.csv$", f):  # ends with -NN.csv
            candidates.append(os.path.join(LOGS_DIR, f))
    return max(candidates, key=os.path.getmtime) if candidates else None

def to_int(s, default=0):
    try: return int(s)
    except Exception:
        try: return int(float(s))
        except Exception: return default

# ========= Parsing =========
def parse_airodump_csv(csv_path: str) -> Tuple[List[AP], List[ST]]:
    with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
        rows = list(csv.reader(f))

    # Find AP header (BSSID ...)
    ap_hdr_idx = None
    for i, row in enumerate(rows[:40]):
        if row and row[0].strip().lower().startswith("bssid"):
            ap_hdr_idx = i; break
    if ap_hdr_idx is None:
        return [], []

    # Collect AP rows until blank line or Stations header
    ap_rows = []
    st_hdr_idx = None
    for j, r in enumerate(rows[ap_hdr_idx+1:], start=ap_hdr_idx+1):
        if not r:
            continue
        first = r[0].strip().lower()
        if first.startswith("station mac"):
            st_hdr_idx = j
            break
        ap_rows.append(r)

    aps: List[AP] = []
    for r in ap_rows:
        if len(r) < 15:
            continue
        try:
            aps.append(AP(*[c.strip() for c in r[:15]]))
        except Exception:
            continue

    stations: List[ST] = []
    if st_hdr_idx is not None:
        st_rows = rows[st_hdr_idx+1:]
        for r in st_rows:
            if not r or len(r) < 7:
                continue
            try:
                stations.append(ST(
                    station_mac=r[0].strip(),
                    first_seen=r[1].strip(),
                    last_seen=r[2].strip(),
                    power=r[3].strip(),
                    packets=r[4].strip(),
                    bssid=r[5].strip(),
                    probed_essids=r[6].strip()
                ))
            except Exception:
                continue

    return aps, stations

# ========= Analysis =========
def analyze(aps: List[AP], stations: List[ST]) -> List[dict]:
    findings_by_bssid: Dict[str, dict] = {}

    # Map ESSID <-> AP info
    essid_to_aps: Dict[str, List[AP]] = defaultdict(list)
    bssid_to_ap: Dict[str, AP] = {}
    for ap in aps:
        essid_to_aps[ap.essid].append(ap)
        bssid_to_ap[ap.bssid] = ap

    # Targeted rules for your trusted network (emit even without packet spikes)
    for ap in aps:
        if norm_ssid(ap.essid) != TRUSTED_SSID_N:
            continue
        ap_bssid_n = norm_bssid(ap.bssid)
        ap_priv_u = (ap.privacy or "").strip().upper()

        if ap_bssid_n != TRUSTED_BSSID_N:
            d = findings_by_bssid.get(ap.bssid, {
                "essid": ap.essid or "<hidden>",
                "bssid": ap.bssid,
                "chan": ap.channel,
                "packets": "",
                "power": ap.power,
                "privacy": ap.privacy,
                "reason": []
            })
            d["reason"].append(f"Evil Twin: {TRUSTED_SSID} seen from rogue BSSID (expected {TRUSTED_BSSID})")
            findings_by_bssid[ap.bssid] = d

        if ap_priv_u.startswith("OPN"):
            d = findings_by_bssid.get(ap.bssid, {
                "essid": ap.essid or "<hidden>",
                "bssid": ap.bssid,
                "chan": ap.channel,
                "packets": "",
                "power": ap.power,
                "privacy": ap.privacy,
                "reason": []
            })
            d["reason"].append(f"Evil Twin: {TRUSTED_SSID} advertised as OPEN (expected {TRUSTED_ENCRYPTION})")
            findings_by_bssid[ap.bssid] = d

    # Global packet spike rule (sum station #Packets per BSSID)
    packets_per_bssid: Dict[str, int] = defaultdict(int)
    for st in stations:
        b = norm_bssid(st.bssid)
        if not b or b.lower().startswith("(not associated)"):
            continue
        packets_per_bssid[b] += to_int(st.packets, 0)

    for bssid, total in packets_per_bssid.items():
        if total >= PACKET_THRESHOLD:
            ap = bssid_to_ap.get(bssid) or bssid_to_ap.get(bssid.upper()) or bssid_to_ap.get(bssid.lower())
            essid = ap.essid if ap else "<unknown>"
            chan = ap.channel if ap else ""
            power = ap.power if ap else ""
            privacy = ap.privacy if ap else ""

            # Is this ESSID duplicated?
            is_dup = False
            if essid:
                bssids_for_essid = {a.bssid for a in essid_to_aps.get(essid, [])}
                is_dup = len(bssids_for_essid) > 1

            d = findings_by_bssid.get(bssid, {
                "essid": essid or "<hidden>",
                "bssid": bssid,
                "chan": chan,
                "packets": "",
                "power": power,
                "privacy": privacy,
                "reason": []
            })
            d["packets"] = str(total)
            base = f"High packet count detected (≥{PACKET_THRESHOLD}) — suspicious activity"
            if base not in d["reason"]:
                d["reason"].append(base)
            if is_dup and "duplicate ESSID observed" not in d["reason"]:
                d["reason"].append("duplicate ESSID observed")
            findings_by_bssid[bssid] = d

    # Flatten and sort
    findings: List[dict] = []
    for d in findings_by_bssid.values():
        findings.append({
            "essid": d["essid"],
            "bssid": d["bssid"],
            "chan": d["chan"],
            "packets": d.get("packets",""),
            "power": d.get("power",""),
            "privacy": d.get("privacy",""),
            "reason": "; ".join(d["reason"])
        })

    def pkt_int(x): return to_int(x.get("packets","0"), 0)
    def pwr_int(x): return to_int(x.get("power","-100"), -100)
    findings.sort(key=lambda x: (pkt_int(x), pwr_int(x)), reverse=True)
    return findings

# ========= Logging =========
def log_findings(findings: List[dict]) -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    new_file = not os.path.exists(ALERTS_LOG)
    with open(ALERTS_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["Timestamp","ESSID","BSSID","Channel","Packets","Power","Privacy","Reason"])
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        for d in findings:
            w.writerow([
                ts, d.get("essid",""), d.get("bssid",""), d.get("chan",""),
                d.get("packets",""), d.get("power",""), d.get("privacy",""), d.get("reason","")
            ])

# ========= Main (one-shot) =========
def main():
    print(f"[*] Monitoring logs in: {LOGS_DIR}")
    csv_path = find_latest_csv()
    if not csv_path:
        print("[!] No CSV found in logs; start airodump-ng and try again.")
        return 2

    print(f"[*] Using CSV: {os.path.basename(csv_path)}")
    start = time.time()
    last_mtime = 0

    # (quiet) show progress only once, not spam
    if not QUIET_PROGRESS:
        print("[*] Scanning in process...", end="", flush=True)

    while time.time() - start < MAX_WAIT_SECONDS:
        try:
            m = os.path.getmtime(csv_path)
        except FileNotFoundError:
            m = 0
        if m != last_mtime:
            last_mtime = m
            aps, stations = parse_airodump_csv(csv_path)

            if DEBUG:
                print("\n[DEBUG] APs parsed:")
                for ap in aps:
                    print(f"  ESSID='{ap.essid}' | BSSID={ap.bssid} | PRIVACY='{ap.privacy}' | CH={ap.channel} | PWR={ap.power}")
                pkt_sum = defaultdict(int)
                for st in stations:
                    b = norm_bssid(st.bssid)
                    if b and not b.lower().startswith("(not associated)"):
                        pkt_sum[b] += to_int(st.packets, 0)
                if pkt_sum:
                    print("\n[DEBUG] Station packet totals per BSSID:")
                    for b, tot in pkt_sum.items():
                        print(f"  BSSID={b} -> packets={tot}")

            if aps or stations:  # we have real data → analyze once and exit
                findings = analyze(aps, stations)
                if findings:
                    notify("WiFiGuardian Alert", f"{len(findings)} finding(s)")
                    print(BLUE + "\n=== Suspicious Wi-Fi / Activity Detected ===" + RESET)
                    headers = ["ESSID","BSSID","Ch","#Packets","Power","Privacy","Reason"]
                    rows = [[
                        f.get("essid",""), f.get("bssid",""), f.get("chan",""),
                        f.get("packets",""), f.get("power",""), f.get("privacy",""), f.get("reason","")
                    ] for f in findings]
                    print(BLUE, end="")   # make the table blue
                    _print_table(headers, rows)
                    print(RESET, end="")
                    print(BLUE + "============================================" + RESET)
                    log_findings(findings)
                else:
                    print(BLUE + "[✓] No suspicious networks or activity detected." + RESET)
                return 0

        time.sleep(POLL_SECONDS)

    print("\n[!] No AP/Station data observed within 60s; ensure airodump-ng is running and the adapter is in monitor mode.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())

