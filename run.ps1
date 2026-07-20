# Serve the web UI locally (no-cache) and open it in the browser.
# Usage:  ./run.ps1   (Ctrl+C to stop)
$ErrorActionPreference = "Stop"
$port = 8765
Start-Process "http://127.0.0.1:$port/"
Write-Host "Serving web/ at http://127.0.0.1:$port/  (no-cache, Ctrl+C to stop)" -ForegroundColor Cyan
# serve.py sends Cache-Control: no-store so edited JS/HTML never serves stale.
python (Join-Path $PSScriptRoot "serve.py") $port (Join-Path $PSScriptRoot "web")
