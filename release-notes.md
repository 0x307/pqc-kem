## pqc-kem v0.1.0

First release of the standalone post-quantum KEM library.

### Algorithms
| Algorithm | Standard | Level | WASM Native |
|---|---|---|---|
| ML-KEM-512 | FIPS 203 | 1 | ✅ |
| ML-KEM-768 | FIPS 203 | 3 | ✅ (recommended) |
| ML-KEM-1024 | FIPS 203 | 5 | ✅ |
| X25519+ML-KEM-768 | Hybrid | 3 | ✅ (primary) |
| HQC-128/192/256 | NIST 2025 | 1/3/5 | ⚠️ feature-gated |
| BIKE | Round 4 alt | 1 | ⚠️ feature-gated |
| Classic McEliece | Round 4 alt | 1 | ⚠️ feature-gated |

### WASM Artifacts
Download `pqc-kem-v0.1.0-wasm.zip` for the deployable WASM package:
- `pqc_kem_bg.wasm` — 244 KB compiled WebAssembly binary
- `pqc_kem.js` — ESM JavaScript glue module
- `pqc_kem.d.ts` — TypeScript type definitions
- `pqc_kem_bg.wasm.d.ts` — TypeScript definitions for the WASM binary
- `pqc-kem.wit` — WIT Component Model interface (`0x307:pqc-kem@0.1.0`)
- `package.json` — npm package metadata
- `test.html` — browser smoke-test harness

### Quick Start (Browser)
```javascript
import init, { WasmHybridKemKeypair, hybrid_encapsulate } from './pqc_kem.js';
await init();
const keypair = new WasmHybridKemKeypair();
const { ciphertext, shared_secret } = JSON.parse(hybrid_encapsulate(keypair.public_key_json()));
const recovered = keypair.decapsulate(ciphertext);
```

### Test
```
cargo test  # 81 tests passing
```
