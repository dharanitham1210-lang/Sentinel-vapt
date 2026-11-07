@echo off
echo ============================================
echo  VulnPilot AI - starting backend + frontend
echo ============================================
start "VulnPilot backend (8000)" cmd /c "cd /d %~dp0backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
timeout /t 3 >nul
start "VulnPilot frontend (5173)" cmd /c "cd /d %~dp0frontend && npm run dev"
echo.
echo Backend : http://127.0.0.1:8000/docs
echo Frontend: http://localhost:5173
echo Press Ctrl+C in each window to stop servers.
