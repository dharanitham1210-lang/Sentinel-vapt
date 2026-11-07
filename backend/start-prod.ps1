# VulnPilot AI — single-process production start (API + website on one port)
# 1) Build the frontend once:   cd frontend && npm run build
# 2) This script:                python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# Then open http://127.0.0.1:8000 — the SPA is served by FastAPI itself.
Write-Host "============================================"
Write-Host " VulnPilot AI - single-origin production mode"
Write-Host " API + website: http://127.0.0.1:8000"
Write-Host "============================================"
if (-not (Test-Path "$PSScriptRoot\..\frontend\dist\index.html")) {
    Write-Host "frontend/dist missing - building first..." -ForegroundColor Yellow
    Push-Location "$PSScriptRoot\..\frontend"
    npm run build
    Pop-Location
}
Set-Location "$PSScriptRoot"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
