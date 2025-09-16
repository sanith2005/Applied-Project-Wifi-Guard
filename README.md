<p align="center">
  <img src="https://github.com/user-attachments/assets/95240ddf-e109-4a84-b89b-92b516f9b295" alt="WiFiGuard Hero" width="300"/>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-BSD--3--Clause-blue" />
  <img alt="Build Status" src="https://github.com/sanith2005/Applied-Project/actions/workflows/ci.yml/badge.svg" />
  <img alt="Release" src="https://img.shields.io/github/v/release/sanith2005/Applied-Project" />
  <img alt="Stars" src="https://img.shields.io/github/stars/sanith2005/Applied-Project?style=social" />
</p>


> WiFiGuard detects rogue APs (Evil Twin), deauth floods, and optionally auto-mitigates by disconnecting clients or switching channels. Designed for Linux (Kali) — research & educational use only.

---

## Table of Contents
- [Features](#features)
- [Demo / Screenshots](#demo--screenshots)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

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

## Install
Clone repo :
```bash
git clone https://github.com/sanith2005/Applied-Project.git
cd Applied-Project/defensive/src
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


