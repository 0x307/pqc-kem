
$ErrorActionPreference = 'Stop'

# Writes $content to $path as UTF-8 *without* a BOM. PowerShell's
# `Set-Content -Encoding utf8` / `Out-File -Encoding utf8` both prepend a
# UTF-8 BOM, which `serde_json` (used by tests/kat_ml_kem.rs) does not skip,
# producing "expected value at line 1 column 1" parse errors.
function Write-Utf8NoBom([string]$path, [string]$content) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
}

$keygenSrc = 'C:\Users\kharper\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\oqs-sys-0.11.0+liboqs-0.13.0\liboqs\tests\ACVP_Vectors\ML-KEM-keyGen-FIPS203\internalProjection.json'
$encdecSrc = 'C:\Users\kharper\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\oqs-sys-0.11.0+liboqs-0.13.0\liboqs\tests\ACVP_Vectors\ML-KEM-encapDecap-FIPS203\internalProjection.json'

$keygenJson = Get-Content $keygenSrc -Raw | ConvertFrom-Json
$encdecJson = Get-Content $encdecSrc -Raw | ConvertFrom-Json

$paramMap = @{ 'ML-KEM-512' = '512'; 'ML-KEM-768' = '768'; 'ML-KEM-1024' = '1024' }

foreach ($tg in $keygenJson.testGroups) {
    $dir = $paramMap[$tg.parameterSet]
    if (-not $dir) { continue }
    $outDir = "tests/vectors/ml-kem/$dir"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $cases = $tg.tests | Select-Object -First 5 | ForEach-Object {
        [ordered]@{
            tcId = $_.tcId
            d    = $_.d
            z    = $_.z
            ek   = $_.ek
            dk   = $_.dk
        }
    }
    $out = [ordered]@{
        source      = "NIST ACVP-Server gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json (vsId $($keygenJson.vsId)), vendored via oqs-sys 0.11.0+liboqs-0.13.0 liboqs/tests/ACVP_Vectors/ML-KEM-keyGen-FIPS203/internalProjection.json"
        algorithm   = $keygenJson.algorithm
        mode        = $keygenJson.mode
        revision    = $keygenJson.revision
        parameterSet = $tg.parameterSet
        testType    = $tg.testType
        tgId        = $tg.tgId
        note        = "d, z are the FIPS 203 keyGen seed halves (32 bytes each). ek is the 'encapsulation key' (public key) bytes. dk here is the FULL EXPANDED decapsulation key in ML-KEM's deprecated legacy wire format (ml_kem::ExpandedKeyEncoding), NOT the 64-byte d||z seed -- ACVP keyGen vectors publish dk in this expanded form. This crate's normal public API only ever stores/loads the 64-byte seed form; the kat feature adds from_expanded_decapsulation_key_bytes()/to_expanded_decapsulation_key_bytes() specifically so KATs can check against this field."
        cases       = $cases
    }
    Write-Utf8NoBom "$outDir/keygen.json" ($out | ConvertTo-Json -Depth 6)
    Write-Output "wrote $outDir/keygen.json ($($cases.Count) cases)"
}

foreach ($tg in $encdecJson.testGroups) {
    $dir = $paramMap[$tg.parameterSet]
    if (-not $dir) { continue }
    $outDir = "tests/vectors/ml-kem/$dir"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    if ($tg.function -eq 'encapsulation') {
        $cases = $tg.tests | Select-Object -First 5 | ForEach-Object {
            [ordered]@{
                tcId = $_.tcId
                ek   = $_.ek
                m    = $_.m
                c    = $_.c
                k    = $_.k
            }
        }
        $out = [ordered]@{
            source      = "NIST ACVP-Server gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json (vsId $($encdecJson.vsId)), vendored via oqs-sys 0.11.0+liboqs-0.13.0 liboqs/tests/ACVP_Vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json"
            algorithm   = $encdecJson.algorithm
            mode        = $encdecJson.mode
            revision    = $encdecJson.revision
            parameterSet = $tg.parameterSet
            testType    = $tg.testType
            function    = $tg.function
            tgId        = $tg.tgId
            note        = "AFT (encapsulation) test group. ek is the recipient's encapsulation (public) key. m is the explicit randomness used by deterministic encapsulation (FIPS 203 Algorithm 17); this crate's kat-gated MlKem*Keypair::encapsulate_deterministic(pk, m) reproduces c and k exactly from ek and m."
            cases       = $cases
        }
        Write-Utf8NoBom "$outDir/encap.json" ($out | ConvertTo-Json -Depth 6)
        Write-Output "wrote $outDir/encap.json ($($cases.Count) cases)"
    } elseif ($tg.function -eq 'decapsulation') {
        $cases = $tg.tests | ForEach-Object {
            [ordered]@{
                tcId   = $_.tcId
                c      = $_.c
                k      = $_.k
                reason = $_.reason
            }
        }
        $out = [ordered]@{
            source      = "NIST ACVP-Server gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json (vsId $($encdecJson.vsId)), vendored via oqs-sys 0.11.0+liboqs-0.13.0 liboqs/tests/ACVP_Vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json"
            algorithm   = $encdecJson.algorithm
            mode        = $encdecJson.mode
            revision    = $encdecJson.revision
            parameterSet = $tg.parameterSet
            testType    = $tg.testType
            function    = $tg.function
            tgId        = $tg.tgId
            dk          = $tg.dk
            ek          = $tg.ek
            note        = "VAL (decapsulation) test group. dk (this file's top-level field, shared by every case below) is the FULL EXPANDED decapsulation key (ml_kem::ExpandedKeyEncoding legacy wire format) for this parameter set -- load it with the kat-gated MlKem*Keypair::from_expanded_decapsulation_key_bytes(). Each case's c is a ciphertext to decapsulate; k is the expected shared secret. reason='valid decapsulation' cases are ordinary round trips; reason='modified ciphertext' cases are FIPS 203's implicit-rejection path (c does not correspond to any valid encapsulation under dk) -- decapsulate() must still return the deterministic pseudorandom k listed here, not an error, per FIPS 203's constant-time design (see src/fips203/ml_kem_768.rs decapsulate())."
            cases       = $cases
        }
        Write-Utf8NoBom "$outDir/decap.json" ($out | ConvertTo-Json -Depth 6)
        Write-Output "wrote $outDir/decap.json ($($cases.Count) cases)"
    }
}
