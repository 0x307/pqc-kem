# build.ps1 — Canonical WASM build script for pqc-kem
#
# Usage (from workspace root or pqc-kem/):
#   powershell -ExecutionPolicy Bypass -File pqc-kem/build.ps1
#
# Or from inside pqc-kem/:
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# Produces pqc-kem/dist/ containing:
#   pqc_kem_bg.wasm        — compiled WebAssembly binary
#   pqc_kem.js             — JS glue module (ESM)
#   pqc_kem.d.ts           — TypeScript type definitions
#   pqc_kem_bg.wasm.d.ts   — WASM TypeScript definitions
#   pqc-kem.wit            — WIT interface file
#   package.json           — npm package manifest

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve script directory so this works from any cwd
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[build] Building pqc-kem WASM artifacts..." -ForegroundColor Cyan

# ── Step 1: wasm-pack build ───────────────────────────────────────────────────
# CRA-1: the standalone cdylib artifact is built from the sibling
# pqc-kem-wasm/ crate now, not this crate directly -- pqc-kem itself is
# rlib-only (an ordinary library, importable into other builds) and can no
# longer be built as a cdylib on its own. --out-dir is relative to
# pqc-kem-wasm/, so it points back up to this repo's dist/ to keep the
# existing output location.
Write-Host "[build] Running wasm-pack (pqc-kem-wasm/)..." -ForegroundColor Cyan
Push-Location (Join-Path $ScriptDir "pqc-kem-wasm")
try {
    wasm-pack build --target web --out-dir ..\dist --release -- --no-default-features
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[build] wasm-pack failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

# ── Step 2: Copy WIT interface file ──────────────────────────────────────────
Write-Host "[build] Copying WIT interface file..." -ForegroundColor Cyan
$WitSrc  = Join-Path $ScriptDir "wit\pqc-kem.wit"
$WitDest = Join-Path $ScriptDir "dist\pqc-kem.wit"
Copy-Item -Path $WitSrc -Destination $WitDest -Force

# ── Step 3: Write dist/package.json ──────────────────────────────────────────
Write-Host "[build] Writing dist/package.json..." -ForegroundColor Cyan
$PackageJson = @'
{
  "name": "pqc-kem",
  "version": "0.3.0",
  "description": "Post-quantum Key Encapsulation Mechanisms: ML-KEM-768 (FIPS 203) and the X25519+ML-KEM-768 hybrid — standalone WASM",
  "type": "module",
  "main": "./pqc_kem.js",
  "types": "./pqc_kem.d.ts",
  "files": [
    "pqc_kem_bg.wasm",
    "pqc_kem.js",
    "pqc_kem.d.ts",
    "pqc_kem_bg.wasm.d.ts",
    "pqc-kem.wit"
  ],
  "keywords": ["post-quantum", "kem", "ml-kem", "wasm", "cryptography", "fips-203"],
  "license": "MIT OR Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/0x307/pqc-kem"
  },
  "exports": {
    ".": {
      "import": "./pqc_kem.js",
      "types": "./pqc_kem.d.ts"
    }
  }
}
'@
$PackageJsonPath = Join-Path $ScriptDir "dist\package.json"
Set-Content -Path $PackageJsonPath -Value $PackageJson -Encoding UTF8

# ── Step 4: Report ────────────────────────────────────────────────────────────
Write-Host "[build] Done. dist/ contents:" -ForegroundColor Green
Get-ChildItem (Join-Path $ScriptDir "dist") | Format-Table Name, Length -AutoSize
