#!/usr/bin/env python3
# Main.py — run 1) scanner.py -> 2) analyze_scan.py -> 3) Wifiguard.py (strict order)
# Adds a rescan loop with Y/n prompt (Enter defaults to YES).

import os, sys, subprocess, time
from pathlib import Path
import select  # for countdown key detection
import signal  # <-- add this

SRC_DIR      = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
LOGS_DIR     = PROJECT_ROOT / "logs"

# ── Colors (256-color for vivid tones) ─────────────────────────────────────────
RESET = "\033[0m"
BLOOD = "\033[38;5;196m"   # blood red
BLUE  = "\033[38;5;39m"    # blue for wordmark
GREEN = "\033[38;5;48m"    # all normal texts
RED   = "\033[91m"

def ok(msg: str):    print(GREEN + "[*] " + msg + RESET)
def warn(msg: str):  print(GREEN + "[*] " + msg + RESET)   # make warnings green too
def err(msg: str):   print(BLOOD + "[!] " + msg + RESET)   # errors red

# >>> keep future logs GREEN (name unchanged to avoid moving call site) <<<
def switch_to_blue():
    """No-op color switch: keep ok()/warn() GREEN for controller logs."""
    global ok, warn
    ok   = lambda msg: print(GREEN + "[*] " + msg + RESET)
    warn = lambda msg: print(GREEN + "[*] " + msg + RESET)
# ──────────────────────────────────────────────────────────────────────────────

# ── Banner helpers ────────────────────────────────────────────────────────────
def side_by_side(left: str, right: str, gap: int = 9,
                 left_color: str = BLOOD, right_color: str = BLUE) -> str:
    """Join two ASCII blocks horizontally with per-line coloring and hard resets."""
    L = [ln.rstrip() for ln in left.splitlines()]
    R = [rn.rstrip() for rn in right.splitlines()]
    w = max((len(s) for s in L), default=0)
    h = max(len(L), len(R))
    rows = []
    for i in range(h):
        l = L[i] if i < len(L) else ""
        r = R[i] if i < len(R) else ""
        rows.append(f"{left_color}{l.ljust(w)}{RESET}" + " " * gap + f"{right_color}{r}{RESET}")
    return "\n".join(rows)


SPARTAN_ASCII = r"""                              
                                                  
                       ░▒▓█▓▓▒▒░                  
                     ░███████████▓░               
                    ▒▒████▓░▒▓█▓▓███▒░            
                    █▓████▒▒░▒▓▓██▓▒▓███▒░        
              ░▒███▒▓█████▓▓▒░██▒▓████░░          
            ▓█████▓▒████████░ ▒███▓▒▓████▒▒░      
         ░▓████▒    ▓███████░ ░▓████████▓▒▒░      
        ▒████     ▒███████████▓░▒████████████░    
       ▓███░   ░▓████▓▒▒▒▒░░░▒▓█▓░ ░░░▒▓▓▒▒▒▓█▒   
      ▒██▓     █████▓▒▒░░░     ░▒█░   ░▓██▒   ▒░  
     ░██▓░    ▓██████▓▒░░        ░▒     ▓██░      
     ▓██░     ▒█████████▒        ░░     ░██▓      
    ░██▓      ▓█████████▒   ░░▒███▒      ▒█▓░     
    ░██░      ▓█▒▓████▒▒░░▓████▓░█▒      ▒██░     
    ░██░      ██▓░  ░▒█████▓░░ ░██▓      ▒██░     
     ██▒      ████▓░   ███░  ░▓█▓░▓      ▒█▓      
     ▒██      ███████░ ▒█▓ ░██▓░ ░█     ░▓█░      
     ░▓█▒     ▓██████▒ ▓██░▒█▒   ▒█     ▒█▒       
      ░██░    ▓██████▓  ░  ▓█░ ▒▒██    ░█▒        
        ▒█▒    ▒██████░   ░█▓░▒██▒    ▒█▒         
         ░█▓░    ▒████▒   ▒█▓██▒    ░▓▓░          
           ░█▓░    ▒██▓   ▓██▓    ░▓▓░            
             ░▒█▓░  ░▓█░ ░█▓░  ░▓▓░               
                 ░▒▒▒▒░░ ░▒▒▒▒░░                                                                           
                                                                 
"""

WIFIGUARD_BANNER = r"""







__      __.__  _____.__              ________                       .___  
/  \    /  \__|/ ____\__|            /  _____/ __ _______ _______  __| _/  
\   \/\/   /  \   __\|  |   ______  /   \  ___|  |  \__  \\_  __ \/ __ |   
 \        /|  ||  |  |  |  /_____/  \    \_\  \  |  // __ \|  | \/ /_/ |   
  \__/\  / |__||__|  |__|            \______  /____/(____  /__|  \____ |   
       \/                                   \/           \/           \/    


"""

def print_banner():
    # Right side: blue wordmark + green tagline. Left side: blood-red Spartan.
    right_block = (
        BLUE  + WIFIGUARD_BANNER + RESET +
        GREEN + "        *- -- WiFiGuard – Defensive Auto-Disconnect Monitor -- -*" + RESET
    )
    left_block  = BLOOD + SPARTAN_ASCII + RESET
    print(side_by_side(left_block, right_block, gap=9))
    print()  # spacing after banner
# ──────────────────────────────────────────────────────────────────────────────

def require_root():
    if os.geteuid() != 0:
        err("Run with sudo: sudo python3 Main.py")
        sys.exit(1)

def child_env():
    env = os.environ.copy()
    su = env.get("SUDO_USER")
    if su and su != "root":
        home = Path("/home") / su
        if home.exists():
            env["HOME"] = str(home)
    env["PYTHONUNBUFFERED"] = "1"
    return env

def run_blocking(pyfile, args=None):
    args = args or []
    cmd = ["python3", str(SRC_DIR / pyfile), *args]
    ok(f"Running {pyfile} …")

    # Ensure the child process does NOT inherit SIGINT=IGNORE from the parent.
    # This makes Ctrl+C work inside Wifiguard.py, while the parent still ignores it.
    def _child_reset_sigint():
        import signal
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    rc = subprocess.call(
        cmd,
        cwd=str(SRC_DIR),
        env=child_env(),
        preexec_fn=_child_reset_sigint,   # <<< add this line
    )
    if rc != 0 and rc != 99:
        err(f"{pyfile} exited with code {rc}")
    return rc

def get_iw_ifaces():
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    ifaces, cur = [], {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            if cur: ifaces.append(cur); cur = {}
            cur["name"] = line.split()[-1]
        elif line.startswith("type"):
            cur["type"] = line.split()[-1]
    if cur: ifaces.append(cur)
    return ifaces

# >>> ADDED: make 'nmcli radio on' compatible and quiet <<<
def _nmcli_radio_on():
    # Try modern and legacy forms; ignore output/errors.
    candidates = [
        ["radio", "wifi", "on"],  # common on newer nmcli
        ["radio", "all", "on"],   # alternate form
        ["radio", "on"],          # older form
    ]
    for args in candidates:
        try:
            subprocess.run(["nmcli", *args],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)
            break
        except FileNotFoundError:
            break

def ensure_managed_mode():
    """After scanner.py exits, ensure we’re back in managed mode."""
    ifaces = get_iw_ifaces()
    mons = [i["name"] for i in ifaces if i.get("type") == "monitor"]
    for mon in mons:
        subprocess.run(["airmon-ng", "stop", mon], check=False)
        subprocess.run(["iw", "dev", mon, "del"], check=False)

    ifaces = get_iw_ifaces()
    managed = [i["name"] for i in ifaces if i.get("type") == "managed"]
    candidates = managed or ["wlan0"]

    for iface in candidates:
        subprocess.run(["ip", "link", "set", iface, "down"], check=False)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False)
        subprocess.run(["ip", "link", "set", iface, "up"], check=False)

    subprocess.run(["rfkill", "unblock", "all"], check=False)
    subprocess.run(["systemctl", "restart", "NetworkManager"], check=False)
    _nmcli_radio_on()  # <<< replaced 'nmcli radio on' to avoid the warning

    managed_ok = False                 # <<< renamed (was 'ok' = False)
    for _ in range(10):
        time.sleep(0.7)
        if any(i.get("type") == "managed" for i in get_iw_ifaces()):
            managed_ok = True
            break
    if managed_ok:
        names = ", ".join(i["name"] for i in get_iw_ifaces() if i.get("type") == "managed")
        ok(f"Interface back in managed mode ({names})")
    else:
        warn("Could not verify managed mode; continue anyway. (You can still select Wi-Fi manually.)")

def prompt_yes_no(prompt: str, default_yes: bool = True) -> bool:
    
    """
    Ask a yes/no question via input() and return True/False.
    default_yes=True -> Enter = yes (shows as 'Y/n')
    default_yes=False -> Enter = no  (shows as 'y/N')
    """
    label = "Y/n" if default_yes else "y/N"
    while True:
        try:
            ans = input(GREEN + f"{prompt} ({label}): " + RESET).strip().lower()
        except EOFError:
            return default_yes
        if ans == "":             return default_yes
        if ans in {"y", "yes"}:   return True
        if ans in {"n", "no"}:    return False
        warn("Please type 'y' or 'n'.")

def confirm_exit_ctrl_c() -> bool:
    """
    Airgeddon-style Ctrl+C confirm:
    - Hides '^C' echo in the terminal while prompting
    - Reprints the same 'Do you really want to exit? (Y/n)' each time Ctrl+C is pressed
    - Restores terminal settings afterwards
    """
    saved_stty = None
    try:
        # Hide '^C' echo only if we're attached to a TTY
        if sys.stdin.isatty():
            try:
                saved_stty = subprocess.check_output(["stty", "-g"], text=True).strip()
                subprocess.run(["stty", "-echoctl"], check=False)
            except Exception:
                saved_stty = None

        while True:
            try:
                ans = input(RED + "Ctrl+C detected. Do you really want to exit? (Y/n): " + RESET).strip().lower()
            except KeyboardInterrupt:
                # User hit Ctrl+C again while at the prompt -> print a clean new prompt line
                print()  # move to a fresh line
                continue
            except EOFError:
                # No stdin available -> default to 'yes'
                ans = "y"

            if ans in ("", "y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
            warn("Please type 'y' or 'n'.")
    finally:
        # Always restore terminal settings if we changed them
        if saved_stty:
            try:
                subprocess.run(["stty", saved_stty], check=False)
            except Exception:
                pass


# >>> 30s restart countdown helper (non-blocking) <<<
def countdown_restart(seconds=30) -> bool:
    """
    Show a countdown. Y/yes (or Enter) => restart immediately.
    N/no => exit. Timeout => auto-restart. Returns True to restart, False to exit.
    Robust to Ctrl+C and to non-selectable stdin.
    """
    print(BLUE + f"\nRestart scan in {seconds}s. Press Y to restart now, N to exit." + RESET, flush=True)
    remaining = seconds
    while remaining > 0:
        try:
            msg = f"\r⏳ Restarting in {remaining:02d}s … (Y/n)? "
            print(BLUE + msg + RESET, end="", flush=True)
            try:
                r, _, _ = select.select([sys.stdin], [], [], 1)
                if r:
                    ans = sys.stdin.readline().strip().lower()
                    print()  # newline after user's entry
                    if ans in ("", "y", "yes"):
                        return True
                    if ans in ("n", "no"):
                        return False
            except Exception:
                # If select() isn't supported on this stdin, just sleep
                time.sleep(1)
            remaining -= 1
        except KeyboardInterrupt:
            if confirm_exit_ctrl_c():
                return False
            # else continue countdown
    print()  # newline after timeout
    return True


def main():
    require_root()

    # Banner (Spartan blood-red, wordmark blue, tagline green)
    print_banner()

    while True:
        try:
            ok("Running orchestrator")
            ok(f"Source dir : {SRC_DIR}")
            ok(f"Logs dir   : {LOGS_DIR}")

            # 1) SCAN ───────────────────────────────────────────────────────────
            rc = run_blocking("scanner.py")

            if rc == 99:  # user pressed Q
                ok("Thanks for using WiFiGuard. Stay safe.")
                break
            elif rc != 0:
                print(f"\n[!] Scanner exited unexpectedly (rc={rc}).")
                break

            # keep subsequent controller logs GREEN
            switch_to_blue()

            # 1b) Make sure we’re back in managed mode
            ensure_managed_mode()

            # 2) ANALYZE (one-shot) ────────────────────────────────────────────
            run_blocking("analyze_scan.py")

            # 3) WIFI GUARD (continuous) ───────────────────────────────────────
            print()
            ok("Starting WiFiGuard. You can now click the suspect Wi-Fi in your network menu;")
            ok("WiFiGuard will disconnect you if it’s rogue.\n")

            _prev = signal.getsignal(signal.SIGINT)
            try:
                # Parent ignores Ctrl+C; only Wifiguard.py handles it and exits cleanly.
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                run_blocking("Wifiguard.py", ["-c", "config.yaml"])
            finally:
                # Restore parent Ctrl+C handling so we can show the countdown and prompts.
                signal.signal(signal.SIGINT, _prev)

            ok("Orchestration run complete.")

            # Countdown restart
            if not countdown_restart(30):
                ok("Thanks for using WiFiGuard. Stay safe.")
                break

            time.sleep(0.6)
            try:
                os.system("clear")
            except Exception:
                pass

        except KeyboardInterrupt:
            print()  # newline after ^C
            if confirm_exit_ctrl_c():
                ok("Thanks for using WiFiGuard. Goodbye.")
                return 0
            else:
                ok("Continuing…")
                continue
    return 0

if __name__ == "__main__":
    sys.exit(main())

