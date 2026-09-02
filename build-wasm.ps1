powershell -Command "Push-Location pqc-kem-wasm; wasm-pack build --target web --out-dir ..\dist --release -- --no-default-features 2>&1; Pop-Location"
