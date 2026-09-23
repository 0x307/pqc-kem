# verify-gates.ps1 - Asserts the supported-feature-surface contract for pqc-kem.
#
# As of 0.3.0, the `bike` and `mceliece` features (each a permanent
# `compile_error!` stub -- neither was ever implemented) have been removed
# entirely, along with the `src/bike`/`src/mceliece` modules and the
# `pqcrypto-classicmceliece`/`pqcrypto-traits` dependencies (see
# CHANGELOG.md's 0.3.0 entry). There is therefore no more "must fail" gated-feature contract to
# assert here -- every documented feature combination, including
# `--all-features`, is expected to build and test cleanly.
#
# Contract asserted:
#   1. `cargo build` (default features) succeeds.
#   2. `cargo build --no-default-features` (no_std path) succeeds.
#   3. `cargo build --features hqc` succeeds (real implementation via `liboqs`).
#   4. `cargo build --all-features` succeeds.
#   5. `cargo test --all-features` succeeds.
#   6. `cargo build --features kat` succeeds (WP4/X-4/P1: deterministic
#      Known-Answer-Test entry points -- see
#      tests/vectors/README.md).
#   7. `cargo test --features kat` succeeds (runs tests/kat_ml_kem.rs and
#      tests/kat_x25519.rs against tests/vectors/**).
#   8. `cargo build --no-default-features --features kat` succeeds (kat is
#      no_std/alloc-compatible, additive only).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File verify-gates.ps1

Set-StrictMode -Version Latest
# Native commands (cargo) write normal progress to stderr; PowerShell 5.1
# wraps redirected stderr lines as NativeCommandError and sets $? = $false
# even on success. Use "Continue" so that doesn't abort the script, and rely
# on $LASTEXITCODE (checked explicitly below) for pass/fail, not $?.
$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $ScriptDir

$Failures = @()

try {
    # -- Default build must succeed --
    Write-Host "[verify-gates] cargo build (default features)..." -ForegroundColor Cyan
    $defaultOutput = cargo build 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "Default build FAILED (expected success):`n$defaultOutput"
    } else {
        Write-Host "[verify-gates]   OK - default build succeeded." -ForegroundColor Green
    }

    # -- no_std build (--no-default-features) must succeed --
    # This crate is rlib-only and never defines
    # #[global_allocator]/#[panic_handler] itself (see src/lib.rs) -- an
    # ordinary no_std library consumer needs nothing beyond
    # --no-default-features. (The standalone WASM cdylib artifact, which DOES
    # need those lang items, now lives in the sibling pqc-kem-wasm/ crate --
    # see its own verify/build steps, not this script.)
    Write-Host "[verify-gates] cargo build --no-default-features..." -ForegroundColor Cyan
    $noStdOutput = cargo build --no-default-features 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "no_std build (--no-default-features) FAILED (expected success):`n$noStdOutput"
    } else {
        Write-Host "[verify-gates]   OK - no_std build succeeded." -ForegroundColor Green
    }

    # -- hqc must succeed (real implementation, not a compile_error! stub) --
    Write-Host "[verify-gates] cargo build --features hqc..." -ForegroundColor Cyan
    $hqcOutput = cargo build --features hqc 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "hqc build (--features hqc) FAILED (expected success -- hqc is a real implementation, not gated):`n$hqcOutput"
    } else {
        Write-Host "[verify-gates]   OK - hqc build succeeded." -ForegroundColor Green
    }

    # -- --all-features must succeed (0.3.0: no more gated features) --
    Write-Host "[verify-gates] cargo build --all-features..." -ForegroundColor Cyan
    $allFeaturesOutput = cargo build --all-features 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "--all-features build FAILED (expected success as of 0.3.0 -- bike/mceliece were removed, not just gated):`n$allFeaturesOutput"
    } else {
        Write-Host "[verify-gates]   OK - --all-features build succeeded." -ForegroundColor Green
    }

    # -- --all-features tests must succeed --
    Write-Host "[verify-gates] cargo test --all-features..." -ForegroundColor Cyan
    $allFeaturesTestOutput = cargo test --all-features 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "--all-features test FAILED (expected success):`n$allFeaturesTestOutput"
    } else {
        Write-Host "[verify-gates]   OK - --all-features tests succeeded." -ForegroundColor Green
    }

    # -- kat must succeed (WP4/X-4/P1: Known-Answer Tests) --
    Write-Host "[verify-gates] cargo build --features kat..." -ForegroundColor Cyan
    $katBuildOutput = cargo build --features kat 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "kat build (--features kat) FAILED (expected success):`n$katBuildOutput"
    } else {
        Write-Host "[verify-gates]   OK - kat build succeeded." -ForegroundColor Green
    }

    Write-Host "[verify-gates] cargo test --features kat..." -ForegroundColor Cyan
    $katTestOutput = cargo test --features kat 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "kat test (--features kat) FAILED (expected success -- runs tests/kat_ml_kem.rs and tests/kat_x25519.rs against tests/vectors/**):`n$katTestOutput"
    } else {
        Write-Host "[verify-gates]   OK - kat tests succeeded." -ForegroundColor Green
    }

    Write-Host "[verify-gates] cargo build --no-default-features --features kat..." -ForegroundColor Cyan
    $katNoStdOutput = cargo build --no-default-features --features kat 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "kat no_std build (--no-default-features --features kat) FAILED (expected success -- kat is no_std/alloc-compatible):`n$katNoStdOutput"
    } else {
        Write-Host "[verify-gates]   OK - kat no_std build succeeded." -ForegroundColor Green
    }
} finally {
    Pop-Location
}

Write-Host ""
if ($Failures.Count -gt 0) {
    Write-Host "[verify-gates] FAILED:" -ForegroundColor Red
    foreach ($f in $Failures) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    exit 1
}

Write-Host "[verify-gates] All gate checks passed." -ForegroundColor Green
exit 0
