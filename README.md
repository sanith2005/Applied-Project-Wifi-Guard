<p align="center">
  <img src="https://github.com/user-attachments/assets/95240ddf-e109-4a84-b89b-92b516f9b295" alt="WiFiGuard Hero" width="300"/>
</p>

# WiFiGuard — Defensive System Against Evil Twin Wi-Fi Attacks

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)]()
[![Build Status](https://github.com/YOUR-USER/Applied-Project/actions/workflows/ci.yml/badge.svg)]()
[![Release](https://img.shields.io/github/v/release/YOUR-USER/Applied-Project)]()
[![Stars](https://img.shields.io/github/stars/YOUR-USER/Applied-Project?style=social)]()

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


