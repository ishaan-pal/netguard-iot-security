# NetGuard IoT Security Appliance - Windows Startup Script
# Run this from PowerShell: .\start.ps1

Write-Host ""
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   NETGUARD IoT Security Appliance v1.0   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check .env
if (-Not (Test-Path ".env")) {
    Write-Host "⚠  .env not found — copying from .env.example" -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "   → Please edit .env and set your GROQ_API_KEY" -ForegroundColor Yellow
    Write-Host ""
}

# Check Python
if (-Not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python not found. Download from https://python.org" -ForegroundColor Red
    exit 1
}

# Check nmap
if (-Not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "⚠  nmap not found. Download from https://nmap.org/download.html" -ForegroundColor Yellow
    Write-Host "   Install nmap, then re-run this script." -ForegroundColor Yellow
    Write-Host ""
}

# Create venv if needed
if (-Not (Test-Path "venv")) {
    Write-Host "🔧 Creating virtual environment..." -ForegroundColor Cyan
    python -m venv venv
}

# Activate venv
Write-Host "⚡ Activating virtual environment..." -ForegroundColor Cyan
& ".\venv\Scripts\Activate.ps1"

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt -q

Write-Host ""
Write-Host "🚀 Starting NetGuard server..." -ForegroundColor Green
Write-Host "   Dashboard: http://localhost:8000" -ForegroundColor White
Write-Host "   API docs:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "   Press Ctrl+C to stop" -ForegroundColor White
Write-Host ""

# Run from backend directory
Set-Location backend
python main.py
