#!/usr/bin/env bash
# ─────────────────────────────────────────────
# NetGuard IoT Security Appliance - Startup Script
# ─────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════════╗"
echo "║   NETGUARD IoT Security Appliance v1.0   ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
  echo "⚠  .env not found — copying from .env.example"
  cp .env.example .env
  echo "   → Please edit .env and set your GROQ_API_KEY"
  echo ""
fi

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌ Python 3 not found. Install from https://python.org"
  exit 1
fi

# Check nmap
if ! command -v nmap &>/dev/null; then
  echo "⚠  nmap not found. Network scanning will be limited."
  echo "   Install: sudo apt install nmap  (Linux)"
  echo "   Install: brew install nmap      (macOS)"
  echo ""
fi

# Check venv
if [ ! -d "venv" ]; then
  echo "🔧 Creating Python virtual environment..."
  python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt -q

echo ""
echo "🚀 Starting NetGuard server..."
echo "   Dashboard: http://localhost:8000"
echo "   API docs:  http://localhost:8000/docs"
echo "   Press Ctrl+C to stop"
echo ""

# Run from backend directory
cd backend

# Use sudo for full nmap capabilities if available
if command -v sudo &>/dev/null && [ "$EUID" -ne 0 ]; then
  echo "💡 Tip: Run with 'sudo bash start.sh' for full OS detection capabilities"
  echo ""
fi

python3 main.py
