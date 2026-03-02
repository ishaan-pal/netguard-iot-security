# NetGuard — IoT Security Appliance

> AI-powered home network security that continuously monitors, profiles, and analyzes every device on your network using real nmap scanning and Groq LLaMA 3 70B.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![Groq](https://img.shields.io/badge/AI-Groq%20LLaMA%203%2070B-orange)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Risk Scoring](#risk-scoring)
- [Project Structure](#project-structure)
- [Security Notes](#security-notes)

---

## Overview

NetGuard is a self-hosted network security appliance for home and small office environments. It automatically discovers every device on your network, fingerprints them, and runs continuous AI-driven risk assessments — surfacing vulnerabilities before they become incidents.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Real-time Discovery** | Finds every device via ARP + port scanning |
| 🧠 **AI Risk Analysis** | Groq LLaMA 3 70B analyzes each device for security risks |
| 📊 **Risk Scoring** | 0–100 blended score (60% AI / 40% rule-based) |
| 🖥️ **Live Dashboard** | WebSocket-powered UI with network topology map |
| 🚨 **Alert System** | Automatic alerts for critical findings |
| 📜 **Device History** | Track risk score changes over time |
| 🔎 **Deep Profiling** | OS detection, open ports, services, firmware versions |
| 🔒 **Vulnerability Detection** | Flags outdated software, dangerous ports, and weak configs |

---

## Architecture
```
┌─────────────────────────────────────────────────────┐
│                   Browser / Dashboard                │
│              (Real-time WebSocket UI)                │
└─────────────────────┬───────────────────────────────┘
                      │ WS + REST
┌─────────────────────▼───────────────────────────────┐
│              FastAPI Backend (main.py)               │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌───────┐  │
│  │ Scanner  │  │ Profiler │  │Groq AI│  │  DB   │  │
│  │ (nmap)   │→ │(ports,   │→ │ Agent │→ │SQLite │  │
│  │          │  │ banners) │  │LLaMA3 │  │       │  │
│  └──────────┘  └──────────┘  └───────┘  └───────┘  │
└─────────────────────────────────────────────────────┘
                      │
              ┌───────▼────────┐
              │  Home Network  │
              │  192.168.x.0/24│
              └────────────────┘
```

---

## Quick Start

### Prerequisites
```bash
# Ubuntu / Debian
sudo apt install nmap python3 python3-pip python3-venv

# macOS
brew install nmap python3
```

### Installation
```bash
git clone <repo-url>
cd iot-security-appliance
cp .env.example .env
```

### Run
```bash
# Standard mode
bash start.sh

# Full capabilities — enables OS detection and SYN scanning (recommended)
sudo bash start.sh
```

Open http://localhost:8000 in your browser.

---

## Configuration

Edit `.env` after copying from `.env.example`:
```env
GROQ_API_KEY=gsk_your_key_here      # Required — get a free key at console.groq.com
NETWORK_RANGE=auto                   # Or specify manually: 192.168.1.0/24
SCAN_INTERVAL_SECONDS=120            # Background scan frequency in seconds
```

> **Note:** Groq's free tier allows ~30 requests/minute and 14,400/day — sufficient for most home networks. The agent batches devices (10 per request) with built-in rate limiting. If the Groq API is unavailable, the system falls back to rule-based analysis automatically.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/devices` | List all discovered devices |
| `GET` | `/api/devices/{ip}` | Device detail and scan history |
| `POST` | `/api/scan` | Trigger a manual network scan |
| `GET` | `/api/alerts` | Retrieve active alerts |
| `POST` | `/api/alerts/ack` | Acknowledge an alert |
| `POST` | `/api/devices/action` | Run action: `isolate`, `analyze`, or `ignore` |
| `GET` | `/api/stats` | Dashboard summary statistics |
| `WS` | `/ws` | Real-time event stream |

Full interactive docs: http://localhost:8000/docs

---

## Risk Scoring

Each device receives a score from **0–100**, calculated as:

- **60%** — AI analysis (Groq LLaMA 3 70B)
- **40%** — Rule-based heuristics

### Score Levels

| Level | Range | Action |
|---|---|---|
| 🔴 Critical | 70–100 | Immediate action required |
| 🟠 High | 50–69 | Serious risks present |
| 🟡 Medium | 25–49 | Moderate risks |
| 🟢 Low | 0–24 | Minimal risk |

### Factors Evaluated

- Open dangerous ports (Telnet, RDP, VNC, FTP)
- Outdated firmware or OS versions
- Unencrypted protocols (HTTP, MQTT, Telnet)
- Default credential risk by device type
- Known CVE indicators in service banners
- Attack surface (total number of open ports)
- Device type baseline risk profile

---

## Project Structure
```
iot-security-appliance/
├── backend/
│   ├── main.py          # FastAPI app, WebSocket handler, scan loop
│   ├── scanner.py       # nmap-based network discovery
│   ├── profiler.py      # Deep device profiling
│   ├── ai_agent.py      # Groq LLaMA 3 AI analysis agent
│   ├── risk_engine.py   # Risk scoring and alert generation
│   └── database.py      # Async SQLite persistence layer
├── frontend/
│   └── index.html       # Single-file dashboard
├── requirements.txt
├── .env.example
├── start.sh
└── README.md
```

---

## Security Notes

> ⚠️ **Read before deploying.**

- **Root access** is required for full nmap SYN scanning and OS detection.
- `iot_security.db` contains your full network topology — store it securely.
- The dashboard has **no authentication by default** — bind to `127.0.0.1` in `.env` on shared machines.
- For remote access, put NetGuard behind a reverse proxy with auth (e.g., nginx + basic auth or Authelia).
