# VulnPilot AI - Windows PowerShell launcher
Write-Host "============================================"
Write-Host " VulnPilot AI - starting backend + frontend"
Write-Host "============================================"
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$PSScriptRoot\backend'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000" -WindowStyle Normal
Start-Sleep -Seconds 3
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$PSScriptRoot\frontend'; npm run dev" -WindowStyle Normal
Write-Host "Backend : http://127.0.0.1:8000/docs"
Write-Host "Frontend: http://localhost:5173"
