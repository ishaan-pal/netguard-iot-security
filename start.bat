@echo off
echo.
echo  NetGuard IoT Security Appliance - Windows
echo  ==========================================
echo.

:: Check .env
if not exist ".env" (
    echo  Copying .env.example to .env...
    copy ".env.example" ".env" >nul
    echo  Please edit .env and set your GROQ_API_KEY
    echo.
)

:: Create venv
if not exist "venv" (
    echo  Creating virtual environment...
    python -m venv venv
)

:: Activate and install
call venv\Scripts\activate.bat
echo  Installing dependencies...
pip install -r requirements.txt -q

echo.
echo  Starting NetGuard...
echo  Dashboard: http://localhost:8000
echo  Press Ctrl+C to stop
echo.

cd backend
python main.py
