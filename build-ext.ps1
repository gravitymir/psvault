# Assemble the loadable Chrome extension in ./extension.
#
# The UI (index.html, style.css, app.js, pkg/) is authored once in ./web and
# synced here. manifest.json, background.js and icons/ live in ./extension and
# are NOT overwritten.
#
# Usage:  ./build-ext.ps1   then load ./extension via chrome://extensions (Load unpacked)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$web = Join-Path $root "web"
$ext = Join-Path $root "extension"

# Rebuild WASM so extension ships the latest crypto core.
# wasm-pack logs INFO to stderr; in PowerShell 5.1 that trips $ErrorActionPreference,
# so relax it here and gate on the real exit code instead.
$ErrorActionPreference = "Continue"
wasm-pack build "$root/crates/vault-wasm" --target web --out-dir "$web/pkg"
if ($LASTEXITCODE -ne 0) { throw "wasm-pack failed (exit $LASTEXITCODE)" }
$ErrorActionPreference = "Stop"

# Sync UI files into the extension folder.
Copy-Item (Join-Path $web "index.html") $ext -Force
Copy-Item (Join-Path $web "style.css")  $ext -Force
Copy-Item (Join-Path $web "app.js")     $ext -Force
$extPkg = Join-Path $ext "pkg"
if (Test-Path $extPkg) { Remove-Item $extPkg -Recurse -Force }
Copy-Item (Join-Path $web "pkg") $extPkg -Recurse -Force

Write-Host "OK. Load '$ext' via chrome://extensions -> Developer mode -> Load unpacked" -ForegroundColor Green
