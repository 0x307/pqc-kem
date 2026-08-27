# verify-gates.ps1 - Asserts the gated-feature contract for pqc-kem.
#
# Consolidates the ad-hoc build-bike.ps1 probe into one check covering all
# gated (not-yet-implemented) features: bike, hqc, mceliece.
#
# Contract asserted:
#   1. `cargo build` (default features) succeeds.
#   2. `cargo build --no-default-features` (no_std path) succeeds.
#   3. `cargo build --features <gated>` FAILS for each gated feature, and the
#      error output names that feature and says "not yet implemented" -
#      confirming the compile_error! fires loudly rather than silently
#      miscompiling or panicking at runtime.
#   4. That failure is EXACTLY ONE error, not the intended compile_error!
#      buried under a pile of raw errors from the still-broken pqcrypto_*
#      calls elsewhere in the module. A compile_error! item doesn't exclude
#      the rest of the module from being type-checked in the same pass, so
#      this only holds if the broken struct/impl code is also excluded via
#      #[cfg(any())] -- this check guards against that regressing silently.
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

$GatedFeatures = @("bike", "hqc", "mceliece")
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
    Write-Host "[verify-gates] cargo build --no-default-features..." -ForegroundColor Cyan
    $noStdOutput = cargo build --no-default-features 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $Failures += "no_std build (--no-default-features) FAILED (expected success):`n$noStdOutput"
    } else {
        Write-Host "[verify-gates]   OK - no_std build succeeded." -ForegroundColor Green
    }

    # -- Each gated feature must fail, naming itself --
    foreach ($feature in $GatedFeatures) {
        Write-Host "[verify-gates] cargo build --features $feature (expect failure)..." -ForegroundColor Cyan
        $output = cargo build --features $feature 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            $Failures += "--features $feature succeeded but was expected to fail with compile_error!."
            continue
        }

        if ($output -notmatch [regex]::Escape($feature)) {
            $Failures += "--features $feature failed, but its compile_error! message does not name the feature '$feature'."
            continue
        }

        if ($output -notmatch "not yet implemented") {
            $Failures += "--features $feature failed, but the message does not say 'not yet implemented'."
            continue
        }

        # cargo's own summary line ("... due to N previous errors") is the
        # authoritative count of real errors, independent of how many
        # warnings or note/help sub-lines surround them.
        $summaryMatch = [regex]::Match($output, "due to (\d+) previous error")
        if (-not $summaryMatch.Success) {
            $Failures += "--features $feature failed, but no 'due to N previous error(s)' summary line was found to verify the error count."
            continue
        }
        $errorCount = [int]$summaryMatch.Groups[1].Value
        if ($errorCount -ne 1) {
            $Failures += "--features $feature produced $errorCount errors, not exactly 1. The compile_error! is likely buried under raw errors from the still-broken implementation -- check that the struct/impl code is gated #[cfg(any())], not just #[cfg(feature = `"$feature`")]."
            continue
        }

        Write-Host "[verify-gates]   OK - $feature failed loudly and named itself, with no other errors burying the message." -ForegroundColor Green
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
