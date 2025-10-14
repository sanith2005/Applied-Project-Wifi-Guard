## WIFIGuard

<p align="center">
  <img src="https://github.com/user-attachments/assets/95240ddf-e109-4a84-b89b-92b516f9b295" alt="WiFiGuard Hero" width="300"/>
</p>



> WiFiGuard is a defensive security toolkit designed to protect users against one of the most common Wi-Fi threats: the Evil Twin attack. By continuously scanning the wireless environment using airodump-ng,         WiFiGuard analyzes live network data to identify duplicate SSIDs, mismatched BSSIDs, abnormal beacon activity, and sudden client deauthentications — all strong indicators of a rogue access point or                deauthentication flood in progress. When a threat is detected, the system alerts the user instantly through on-screen notifications and logs the event for analysis. In addition to detection, WiFiGuard provides    active defense features, such as automatically disconnecting clients from suspicious APs and triggering router channel changes to evade sustained attacks. The toolkit is written in Python, modular in design,      and tailored for Linux environments (with Kali Linux as the primary testbed). It is intended strictly for research, academic demonstration, and educational use, helping cybersecurity learners and professionals    understand how modern wireless intrusions can be detected and mitigated in real time.

---

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#Usage)
- [Support](#Support)

---

## Features
- Real-time scanning using `airodump-ng` CSV output
- Analysis engine to detect duplicate SSIDs / BSSID mismatch (Evil Twin)
- Toast notifications + structured log output
- Optional auto-disconnect (nmcli/netsh) and router channel switching hooks
- Clean CLI UX and modular Python code (`scanner.py`, `analyze_scan.py`, `WiFiGuard.py`, `Main.py`)

## Requirements
- Linux (Kali recommended)
- Python 3.11+
- `aircrack-ng` (airodump-ng)
- `nmcli` (NetworkManager) for disconnects
- Optional: `winotify` / `libnotify` for notifications

---

## Installation
- Clone the repo :
```bash
git clone https://github.com/sanith2005/Applied-Project.git
```
- Install dependencies if not available :
```bash
sudo apt update && sudo apt install -y \
  python3 python3-pip \
  aircrack-ng iw iproute2 wireless-tools \
  network-manager libnotify-bin macchanger \
  tcpdump tshark dnsmasq hostapd
```

## Usage
- Head to the cloned Directory and run the Main.py 
```bash
$ cd ~/Desktop/Applied\ project/defensive/src
$ sudo python3 Main.py
```

## 🛠 Support
If you encounter issues or need technical assistance, please contact the development team at:
📧 **wifiguardhelp@gmail.com**
Alternatively, you can [open a new issue](https://github.com/sanith2005/Applied-Project/issues) on GitHub.





