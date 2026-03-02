# NetGuard — IoT Security Appliance

An AI-powered, production-ready home network security appliance that continuously monitors, profiles, and analyzes every device on your network using real nmap scanning + Groq LLaMA 3 70B intelligence.

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

## Features

- **Real-time discovery**: Finds every device on your network using ARP + port scanning
- **Deep profiling**: Detects OS, open ports, running services, firmware versions
- **AI risk analysis**: Groq LLaMA 3 70B analyzes each device for security risks
- **Vulnerability detection**: Identifies outdated software, dangerous ports, weak configs
- **Risk scoring**: 0-100 risk score blending rule-based + AI analysis (60/40)
- **Live dashboard**: WebSocket-powered real-time updates, network topology map
- **Alert system**: Automatic alerts for critical findings
- **Device history**: Track risk changes over time
- **Deep AI analysis**: On-demand comprehensive security audit per device

---

## Quick Start

### 1. Prerequisites

```bash
# Ubuntu/Debian
sudo apt install nmap python3 python3-pip python3-venv

# macOS
brew install nmap python3
```

### 2. Clone and Configure

```bash
git clone <repo>
cd iot-security-appliance
cp .env.example .env
```

Edit `.env`:
```env
GROQ_API_KEY=gsk_your_key_here     # Required — get free at console.groq.com
NETWORK_RANGE=auto                  # Or: 192.168.1.0/24
SCAN_INTERVAL_SECONDS=120           # Background scan frequency
```

### 3. Run

```bash
# Standard mode
bash start.sh

# Full capabilities (OS detection, SYN scan)
sudo bash start.sh
```

Open **http://localhost:8000** in your browser.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all devices |
| GET | `/api/devices/{ip}` | Device detail + history |
| POST | `/api/scan` | Trigger manual scan |
| GET | `/api/alerts` | Get alerts |
| POST | `/api/alerts/ack` | Acknowledge alert |
| POST | `/api/devices/action` | isolate / analyze / ignore |
| GET | `/api/stats` | Dashboard statistics |
| WS | `/ws` | Real-time event stream |

Full API docs: http://localhost:8000/docs

---

## Risk Scoring

Risk scores (0–100) are computed as:
- **60%** — AI analysis (Groq LLaMA 3 70B)
- **40%** — Rule-based analysis

| Level | Score | Meaning |
|-------|-------|---------|
| Critical | 70–100 | Immediate action required |
| High | 50–69 | Serious risks present |
| Medium | 25–49 | Moderate risks |
| Low | 0–24 | Minimal risk |

**Factors considered:**
- Open dangerous ports (Telnet, RDP, VNC, FTP)
- Outdated firmware/OS
- Unencrypted protocols (HTTP, MQTT, Telnet)
- Default credential risk by device type
- Known CVE indicators in service banners
- Attack surface (number of open ports)
- Device type baseline risk

---

## Project Structure

```
iot-security-appliance/
├── backend/
│   ├── main.py          # FastAPI app, WebSocket, scan loop
│   ├── scanner.py       # nmap network discovery
│   ├── profiler.py      # Deep device profiling
│   ├── ai_agent.py      # Groq LLaMA 3 AI analysis
│   ├── risk_engine.py   # Risk scoring & alert generation
│   └── database.py      # Async SQLite persistence
├── frontend/
│   └── index.html       # Full dashboard (single-file)
├── requirements.txt
├── .env.example
├── start.sh
└── README.md
```

---

## Groq Free Tier Limits

Groq's free tier allows ~30 requests/minute and 14,400/day — more than sufficient for home network scanning. The agent automatically batches devices (10 per request) and includes built-in rate limiting.

If Groq API is unavailable, the system **falls back to rule-based analysis** automatically — the dashboard remains fully functional.

---

## Security Notes

- **Run as root** for full nmap SYN scan + OS detection capabilities
- The database (`iot_security.db`) stores your network topology — protect it
- The dashboard has no authentication by default — bind to `127.0.0.1` in `.env` if on a shared machine
- For remote access, put behind a reverse proxy with authentication (nginx + basic auth)
