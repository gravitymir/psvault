# Rebuild the WASM package into web/pkg.
# Usage:  ./build.ps1
$root = $PSScriptRoot
# wasm-pack logs INFO to stderr; gate on the exit code, not stderr.
wasm-pack build "$root/crates/vault-wasm" --target web --out-dir "$root/web/pkg"
if ($LASTEXITCODE -ne 0) { throw "wasm-pack failed (exit $LASTEXITCODE)" }
Write-Host "OK. WASM built into web/pkg" -ForegroundColor Green
