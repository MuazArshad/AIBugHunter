@echo off
title BugHunterAI — Starting...
echo.
echo  ██████╗ ██╗   ██╗ ██████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
echo  ██╔══██╗██║   ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
echo  ██████╔╝██║   ██║██║  ███╗   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
echo  ██╔══██╗██║   ██║██║   ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
echo  ██████╔╝╚██████╔╝╚██████╔╝   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
echo  ╚═════╝  ╚═════╝  ╚═════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
echo.
echo  AI-Powered Bug Bounty Hunting Agent v1.0
echo  ─────────────────────────────────────────
echo.

REM Check if .env exists
if not exist ".env" (
  echo  [WARNING] .env file not found. Copying .env.example...
  copy .env.example .env
  echo  [INFO] Edit .env and add your API keys before scanning.
  echo.
)

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
  echo  [ERROR] Python not found. Please install Python 3.10+
  pause
  exit /b 1
)

REM Install dependencies if needed
echo  [INFO] Checking dependencies...
cd backend
pip install -r requirements.txt -q
cd ..

echo.
echo  [INFO] Starting server on http://localhost:8000
echo  [INFO] Open your browser and navigate to http://localhost:8000
echo.

cd backend
python main.py

pause
