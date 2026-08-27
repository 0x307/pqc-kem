# pqc-kem

[![CI](https://github.com/0x307/pqc-kem/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/0x307/pqc-kem/actions/workflows/ci.yml)
[![cargo-deny: known-red](https://github.com/0x307/pqc-kem/actions/workflows/cargo-deny.yml/badge.svg?branch=main)](https://github.com/0x307/pqc-kem/actions/workflows/cargo-deny.yml)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)
![WASM: Compatible](https://img.shields.io/badge/WASM-Compatible-green.svg)
![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-orange.svg)

> **On the two badges above.** **CI** is the build gate — it must be green, and a red one is
> a real break. **cargo-deny** is expected to be red, and that is not a broken build: four
> `pqcrypto-*` crates carry `unmaintained` advisories because upstream PQClean is being
> archived. They are reachable only through the opt-in `hqc` / `mceliece` features (which do
> not currently compile at all), they are accepted rather than suppressed, and they are
> listed by RUSTSEC ID with rationale in
> [SECURITY.md](./SECURITY.md#known-and-accepted-advisories). It is left red on purpose so a
> genuinely new advisory can't hide behind an already-accepted one.

**Post-quantum Key Encapsulation Mechanisms for Rust and WebAssembly.**

`pqc-kem` is a standalone, `no_std`-compatible Rust library implementing post-quantum KEM algorithms including ML-KEM (NIST FIPS 203), a Hybrid X25519+ML-KEM-768 construction, HQC, BIKE, and Classic McEliece. It is designed to run natively in `wasm32-unknown-unknown` environments — shipping as `.wasm` + `.js` + `.d.ts` + `.wit` artifacts — with zero external C dependencies for the primary ML-KEM and Hybrid KEM paths. Secret key material is zeroized on drop via the `zeroize` crate, entropy is never hardcoded (callers supply RNG; WASM uses `window.crypto.getRandomValues()`), and all wire types serialize to compact base64url JSON suitable for DID Documents and JWK payloads.

## What runs today vs. what is designed

**Runs today:**

- ML-KEM-512, ML-KEM-768, ML-KEM-1024 (NIST FIPS 203) — pure Rust, `no_std`-compatible, default features
- Hybrid X25519+ML-KEM-768 construction (the recommended primary API)
- WASM bindings (`WasmHybridKemKeypair`, `WasmMlKem{512,768,1024}Keypair`, and the free functions) behind the opt-in `wasm` feature, targeting `wasm32-unknown-unknown`
- Wire types (`KemPublicKey`, `KemCiphertext`, `SharedSecret`, `HybridPublicKey`, `HybridKemCiphertext`) with base64url JSON and multibase (base58btc) encoding, zeroized secret material on drop

**Designed, not yet implemented:**

- HQC-128/192/256, BIKE, and Classic McEliece — each is gated behind a non-default feature (`hqc`, `bike`, `mceliece`) that is a **hard `compile_error!` stub, not a runtime option**. Enabling any of these three features fails the build on purpose: their underlying `pqcrypto-*` dependencies don't implement the API this crate calls against (82 and 25 compile errors respectively against the real `pqcrypto-hqc`/`pqcrypto-classicmceliece` APIs; `pqcrypto-bike` is a vendored stub that panics at runtime). This is intentional gating from P2-01 — a loud compile-time failure instead of a silent miscompile or runtime panic — not a bug. `cargo build --all-features` is expected to fail for exactly this reason, and CI asserts that it does.
- NTRU (`ntru` module) — deprecation marker only. NTRU was eliminated from NIST standardization; no operations are implemented and none are planned.

---

## Algorithm Support

| Algorithm                  | Standard            | Security Level | Public Key   | Ciphertext   | Shared Secret | WASM Native | Feature Flag  | Status                    |
|----------------------------|---------------------|----------------|--------------|--------------|---------------|-------------|---------------|---------------------------|
| **ML-KEM-512**             | NIST FIPS 203       | Level 1        | 800 bytes    | 768 bytes    | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **ML-KEM-768**             | NIST FIPS 203       | Level 3        | 1184 bytes   | 1088 bytes   | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **ML-KEM-1024**            | NIST FIPS 203       | Level 5        | 1568 bytes   | 1568 bytes   | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **Hybrid X25519+ML-KEM-768** | FIPS 203 + RFC 7748 | Level 3+     | 1216 bytes   | 1120 bytes   | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **HQC-128**                | NIST 2025           | Level 1        | 2249 bytes   | 4481 bytes   | 32 bytes      | ❌ C FFI    | `hqc`         | ⚠️ Gated — not implemented |
| **HQC-192**                | NIST 2025           | Level 3        | 4522 bytes   | 8978 bytes   | 32 bytes      | ❌ C FFI    | `hqc`         | ⚠️ Gated — not implemented |
| **HQC-256**                | NIST 2025           | Level 5        | 7245 bytes   | 14469 bytes  | 32 bytes      | ❌ C FFI    | `hqc`         | ⚠️ Gated — not implemented |
| **BIKE**                   | NIST Round 4        | Level 1/3/5    | variable     | variable     | 32 bytes      | ❌ C FFI    | `bike`        | ⚠️ Gated — not implemented |
| **Classic McEliece**       | NIST Round 4        | Level 1–5      | variable     | variable     | 32 bytes      | ❌ C FFI    | `mceliece`    | ⚠️ Gated — not implemented |

> **Recommended:** Use the **Hybrid X25519+ML-KEM-768** construction for all new applications. It provides security against both classical and quantum adversaries simultaneously.
>
> **Gated algorithms are placeholders, not runtime options.** HQC, BIKE, and Classic McEliece are not yet implemented against their published dependency APIs. Their feature flags exist so the intended surface is visible, but enabling any of them (`--features hqc`, `--features bike`, `--features mceliece`, or `--all-features`) is a hard `compile_error!` by design — not a runtime fallback or a partial implementation. They will be enabled once a real, passing implementation lands.

---

## Quick Start — Rust

```rust
use pqc_kem::fips203::HybridKemKeypair;
use rand::rngs::OsRng;

// ── Recipient: generate keypair ───────────────────────────────────────────────
let recipient = HybridKemKeypair::generate(&mut OsRng).unwrap();
let pub_key = recipient.public_key();

// ── Sender: encapsulate ───────────────────────────────────────────────────────
let x25519_pub = pub_key.x25519_bytes().unwrap();
let mlkem_pub  = pub_key.mlkem_bytes().unwrap();
let x25519_arr: [u8; 32] = x25519_pub.try_into().unwrap();

let (ciphertext, sender_ss) = HybridKemKeypair::encapsulate(
    &mut OsRng,
    &x25519_arr,
    &mlkem_pub,
).unwrap();

// ── Recipient: decapsulate ────────────────────────────────────────────────────
let recipient_ss = recipient.decapsulate(&ciphertext).unwrap();

assert_eq!(sender_ss.bytes, recipient_ss.bytes);
// shared secret is 32 bytes, derived via HKDF-SHA256
```

Using the convenience wrapper with a `HybridPublicKey` wire type:

```rust
use pqc_kem::fips203::HybridKemKeypair;
use rand::rngs::OsRng;

let recipient = HybridKemKeypair::generate(&mut OsRng).unwrap();
let pub_key   = recipient.public_key();

// encapsulate_to accepts the HybridPublicKey wire type directly
let (ciphertext, sender_ss) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key).unwrap();
let recipient_ss = recipient.decapsulate(&ciphertext).unwrap();

assert_eq!(sender_ss.bytes, recipient_ss.bytes);
```

Standalone ML-KEM-768 (no hybrid):

```rust
use pqc_kem::fips203::MlKem768Keypair;
use pqc_kem::types::{KemAlgorithm, KemPublicKey};
use rand::rngs::OsRng;

let recipient = MlKem768Keypair::generate(&mut OsRng).unwrap();
let pk        = recipient.public_key(); // KemPublicKey { algorithm: MlKem768, bytes: [..1184..] }

let (ct, sender_ss)   = MlKem768Keypair::encapsulate(&mut OsRng, &pk).unwrap();
let recipient_ss      = recipient.decapsulate(&ct).unwrap();

assert_eq!(sender_ss.bytes, recipient_ss.bytes);
```

---

## Quick Start — JavaScript / TypeScript (Browser)

Copy the `dist/` directory to your project, then:

```html
<script type="module">
import init, {
  WasmHybridKemKeypair,
  hybrid_encapsulate,
  pqc_kem_version,
  primary_algorithm,
} from './pqc_kem.js';

await init(); // initializes the WASM module

console.log('pqc-kem version:', pqc_kem_version());
console.log('primary algorithm:', primary_algorithm()); // "X25519+ML-KEM-768"

// ── Recipient: generate keypair ───────────────────────────────────────────────
const keypair = new WasmHybridKemKeypair();
const pubKeyJson = keypair.public_key_json(); // JSON string

// ── Sender: encapsulate ───────────────────────────────────────────────────────
// hybrid_encapsulate returns JSON: { ciphertext: {...}, shared_secret: "<base64url>" }
const resultJson = hybrid_encapsulate(pubKeyJson);
const result = JSON.parse(resultJson);
const ciphertextJson = JSON.stringify(result.ciphertext);
const senderSharedSecret = result.shared_secret; // base64url-encoded 32 bytes

// ── Recipient: decapsulate ────────────────────────────────────────────────────
const recipientSharedSecret = keypair.decapsulate(ciphertextJson); // Uint8Array (32 bytes)
</script>
```

TypeScript with type annotations:

```typescript
import init, {
  WasmHybridKemKeypair,
  WasmMlKem768Keypair,
  hybrid_encapsulate,
  ml_kem_768_encapsulate,
} from './pqc_kem.js';

await init();

// Hybrid KEM (recommended)
const keypair: WasmHybridKemKeypair = new WasmHybridKemKeypair();
const pubKeyJson: string            = keypair.public_key_json();
const encResult: string             = hybrid_encapsulate(pubKeyJson);
const { ciphertext, shared_secret } = JSON.parse(encResult);
const ss: Uint8Array                = keypair.decapsulate(JSON.stringify(ciphertext));

// Standalone ML-KEM-768
const mlkemKeypair: WasmMlKem768Keypair = new WasmMlKem768Keypair();
const mlkemPubBytes: Uint8Array         = mlkemKeypair.public_key_bytes();
const mlkemResult: string               = ml_kem_768_encapsulate(mlkemPubBytes);
// returns JSON: { "ciphertext": "<base64url>", "shared_secret": "<base64url>" }
```

---

## Quick Start — JavaScript / TypeScript (Node.js / Deno)

Build the WASM package targeting Node.js:

```powershell
cd pqc-kem
wasm-pack build --target nodejs --features wasm --release
```

Then use it in Node.js:

```javascript
const { default: init, WasmHybridKemKeypair, hybrid_encapsulate } = require('./pkg/pqc_kem.js');

// Node.js target does not require an async init() call
const keypair    = new WasmHybridKemKeypair();
const pubKeyJson = keypair.public_key_json();

const resultJson = hybrid_encapsulate(pubKeyJson);
const result     = JSON.parse(resultJson);

const ss = keypair.decapsulate(JSON.stringify(result.ciphertext));
console.log('shared secret (hex):', Buffer.from(ss).toString('hex'));
```

For Deno (using the `web` target output):

```typescript
import init, { WasmHybridKemKeypair, hybrid_encapsulate } from './dist/pqc_kem.js';

await init(new URL('./dist/pqc_kem_bg.wasm', import.meta.url));

const keypair    = new WasmHybridKemKeypair();
const pubKeyJson = keypair.public_key_json();
const result     = JSON.parse(hybrid_encapsulate(pubKeyJson));
const ss         = keypair.decapsulate(JSON.stringify(result.ciphertext));
```

> **Note:** The `--target nodejs` build uses synchronous WASM initialization. The `--target web` build (default in `build.ps1`) requires `await init()`.

---

## Installation

### As a Rust Crate

```toml
[dependencies]
pqc-kem = { path = "./pqc-kem" }
```

With specific features:

```toml
[dependencies]
# WASM target (wasm32-unknown-unknown)
pqc-kem = { path = "./pqc-kem", default-features = false, features = ["wasm"] }

# With HQC and BIKE (requires C toolchain)
pqc-kem = { path = "./pqc-kem", features = ["hqc", "bike"] }

# no_std with alloc (embedded / WASM without wasm-bindgen)
pqc-kem = { path = "./pqc-kem", default-features = false }
```

### As a WASM Package (npm / CDN)

1. Copy the `pqc-kem/dist/` directory to your project:

```
dist/
├── pqc_kem.js          # ES module entry point
├── pqc_kem_bg.wasm     # WASM binary
├── pqc_kem.d.ts        # TypeScript declarations
└── pqc_kem_bg.wasm.d.ts
```

2. Import from your application:

```javascript
import init, { WasmHybridKemKeypair, hybrid_encapsulate } from './dist/pqc_kem.js';
await init();
```

3. Serve with correct MIME type — ensure your server sends `Content-Type: application/wasm` for `.wasm` files.

---

## Feature Flags

| Feature      | Default | Description                                                                                   |
|--------------|---------|-----------------------------------------------------------------------------------------------|
| `std`        | ✅ Yes  | Enables `std`-dependent trait impls (`sha2/std`, `serde/std`, `zeroize/std`, `ml-kem/getrandom`). Disable for `no_std` targets. |
| `wasm`       | ❌ No   | Enables `wasm-bindgen` exports, `js-sys`, and `getrandom/js` for `window.crypto.getRandomValues()` entropy. Required for browser/WASM targets. |
| `hqc`        | ❌ No   | Enables HQC-128/192/256 via `pqcrypto-hqc` (C FFI). Not WASM-compatible. Requires a C toolchain. |
| `bike`       | ❌ No   | Enables BIKE via `pqcrypto-bike` (C FFI). Not WASM-compatible. Requires a C toolchain.        |
| `mceliece`   | ❌ No   | Enables Classic McEliece via `pqcrypto-classicmceliece` (C FFI). Very large keys (hundreds of KB). Not WASM-compatible. |

---

## API Reference

### ML-KEM (FIPS 203)

All three ML-KEM parameter sets share the same interface pattern. The types are in [`pqc_kem::fips203`](src/fips203/mod.rs).

#### `MlKem512Keypair` — Security Level 1

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self>` | Generate a new keypair |
| `public_key` | `fn public_key(&self) -> KemPublicKey` | Returns public key (800 bytes) |
| `encapsulate` | `fn encapsulate<R>(rng: &mut R, pk: &KemPublicKey) -> KemResult<(KemCiphertext, SharedSecret)>` | Encapsulate; ciphertext is 768 bytes |
| `decapsulate` | `fn decapsulate(&self, ct: &KemCiphertext) -> KemResult<SharedSecret>` | Decapsulate; shared secret is 32 bytes |

#### `MlKem768Keypair` — Security Level 3 *(recommended)*

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self>` | Generate a new keypair |
| `public_key` | `fn public_key(&self) -> KemPublicKey` | Returns public key (1184 bytes) |
| `encapsulate` | `fn encapsulate<R>(rng: &mut R, pk: &KemPublicKey) -> KemResult<(KemCiphertext, SharedSecret)>` | Encapsulate; ciphertext is 1088 bytes |
| `decapsulate` | `fn decapsulate(&self, ct: &KemCiphertext) -> KemResult<SharedSecret>` | Decapsulate; shared secret is 32 bytes |

#### `MlKem1024Keypair` — Security Level 5

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self>` | Generate a new keypair |
| `public_key` | `fn public_key(&self) -> KemPublicKey` | Returns public key (1568 bytes) |
| `encapsulate` | `fn encapsulate<R>(rng: &mut R, pk: &KemPublicKey) -> KemResult<(KemCiphertext, SharedSecret)>` | Encapsulate; ciphertext is 1568 bytes |
| `decapsulate` | `fn decapsulate(&self, ct: &KemCiphertext) -> KemResult<SharedSecret>` | Decapsulate; shared secret is 32 bytes |

---

### Hybrid KEM

[`HybridKemKeypair`](src/fips203/hybrid.rs) is the **primary recommended construction** for all applications. It combines X25519 (classical Diffie-Hellman) with ML-KEM-768 (post-quantum) so that breaking the shared secret requires breaking **both** components simultaneously.

#### Construction

```
x25519_ss  = X25519(ephemeral_private, recipient_x25519_public)
mlkem_ss   = ML-KEM-768.Decaps(ciphertext, recipient_mlkem_secret)
combined   = x25519_ss ‖ mlkem_ss          (64 bytes)
shared_key = HKDF-SHA256(combined, info="pqc-kem-hybrid-v1", len=32)
```

The HKDF info string `"pqc-kem-hybrid-v1"` is a domain separator that binds the derived key to this specific construction version.

#### `HybridKemKeypair` Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self>` | Generate a new hybrid keypair |
| `public_key` | `fn public_key(&self) -> HybridPublicKey` | Returns the hybrid public key wire type |
| `x25519_public_bytes` | `fn x25519_public_bytes(&self) -> [u8; 32]` | Returns X25519 public key (32 bytes) |
| `mlkem_public_bytes` | `fn mlkem_public_bytes(&self) -> Vec<u8>` | Returns ML-KEM-768 public key (1184 bytes) |
| `encapsulate` | `fn encapsulate<R>(rng: &mut R, x25519_pub: &[u8; 32], mlkem_pub: &[u8]) -> KemResult<(HybridKemCiphertext, SharedSecret)>` | Encapsulate to raw key bytes |
| `encapsulate_to` | `fn encapsulate_to<R>(rng: &mut R, pub_key: &HybridPublicKey) -> KemResult<(HybridKemCiphertext, SharedSecret)>` | Encapsulate to a `HybridPublicKey` wire type |
| `decapsulate` | `fn decapsulate(&self, ct: &HybridKemCiphertext) -> KemResult<SharedSecret>` | Decapsulate; shared secret is 32 bytes |
| `from_secret_key_bytes` | `fn from_secret_key_bytes(x25519_secret: &[u8], mlkem_seed: &[u8]) -> KemResult<Self>` | Restore keypair from 32-byte X25519 secret + 64-byte ML-KEM-768 seed |
| `x25519_secret_bytes` | `fn x25519_secret_bytes(&self) -> [u8; 32]` | ⚠️ Raw X25519 secret key bytes |
| `mlkem_secret_bytes` | `fn mlkem_secret_bytes(&self) -> Vec<u8>` | ⚠️ Raw ML-KEM-768 seed bytes (64 bytes) |

---

### WASM Exports

All exports are in [`pqc_kem::wasm`](src/wasm.rs) and require the `wasm` feature. Byte arrays cross the WASM boundary as `Uint8Array`. Errors are returned as JavaScript `Error` objects.

#### Classes

| Class | Constructor | Description |
|-------|-------------|-------------|
| `WasmHybridKemKeypair` | `new WasmHybridKemKeypair()` | Hybrid X25519+ML-KEM-768 keypair. **Recommended.** |
| `WasmMlKem512Keypair` | `new WasmMlKem512Keypair()` | ML-KEM-512 keypair (Security Level 1) |
| `WasmMlKem768Keypair` | `new WasmMlKem768Keypair()` | ML-KEM-768 keypair (Security Level 3) |
| `WasmMlKem1024Keypair` | `new WasmMlKem1024Keypair()` | ML-KEM-1024 keypair (Security Level 5) |

#### `WasmHybridKemKeypair` Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `public_key_json()` | `string` | JSON-serialized `HybridPublicKey` (share with senders) |
| `x25519_public_bytes()` | `Uint8Array` | X25519 public key (32 bytes) |
| `mlkem_public_bytes()` | `Uint8Array` | ML-KEM-768 public key (1184 bytes) |
| `decapsulate(ciphertext_json: string)` | `Uint8Array` | Decapsulate a JSON ciphertext; returns 32-byte shared secret |

#### `WasmMlKem{512,768,1024}Keypair` Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `public_key_bytes()` | `Uint8Array` | Raw public key bytes |
| `public_key_base64url()` | `string` | Public key as base64url string |
| `decapsulate(ciphertext_bytes: Uint8Array)` | `Uint8Array` | Decapsulate raw ciphertext bytes; returns 32-byte shared secret |

#### Free Functions

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `hybrid_encapsulate` | `(recipient_public_key_json: string) => string` | JSON `{ciphertext: {...}, shared_secret: "<base64url>"}` | Encapsulate to a hybrid public key |
| `ml_kem_512_encapsulate` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to ML-KEM-512 public key |
| `ml_kem_768_encapsulate` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to ML-KEM-768 public key |
| `ml_kem_1024_encapsulate` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to ML-KEM-1024 public key |
| `pqc_kem_version` | `() => string` | `"0.1.0"` | Returns the crate version |
| `primary_algorithm` | `() => string` | `"X25519+ML-KEM-768"` | Returns the primary algorithm identifier |

---

### WIT Component Model

The crate exposes a [WIT](wit/pqc-kem.wit) interface at `0x307:pqc-kem@0.1.0` for use with the WASM Component Model.

```wit
package 0x307:pqc-kem@0.1.0;

world pqc-kem {
    export ml-kem;      // ML-KEM-512/768/1024 (NIST FIPS 203)
    export hybrid-kem;  // X25519 + ML-KEM-768 (primary construction)
    export utils;       // version(), primary-algorithm(), key/ciphertext sizes
}
```

#### Using with wasmtime

```bash
# Build as a WASM component
cargo component build --release

# Run with wasmtime CLI
wasmtime run --wasm component-model pqc_kem.wasm
```

#### Using with jco (JavaScript Component Model)

```javascript
import { mlKem, hybridKem, utils } from './pqc_kem.js';

// Check version
console.log(utils.version());          // "0.1.0"
console.log(utils.primaryAlgorithm()); // "X25519+ML-KEM-768"

// ML-KEM-768 (standalone)
const keypair    = new mlKem.MlKemKeypair('ml-kem-768');
const pubKey     = keypair.publicKey();
const [ct, ss]   = mlKem.encapsulate('ml-kem-768', pubKey);
const recovered  = keypair.decapsulate(ct);

// Hybrid KEM (recommended)
const hybridKeypair  = new hybridKem.HybridKemKeypair();
const hybridPub      = hybridKeypair.publicKey();
const [hybridCt, hybridSs] = hybridKem.encapsulate(hybridPub);
const hybridRecovered      = hybridKeypair.decapsulate(hybridCt);
```

---

## Wire Types

### `HybridKemCiphertext`

Produced by [`HybridKemKeypair::encapsulate`](src/fips203/hybrid.rs) and [`hybrid_encapsulate`](src/wasm.rs). Transmitted from sender to recipient.

| Field | Type | Description |
|-------|------|-------------|
| `classical_ct` | `string` | X25519 ephemeral public key — 32 bytes, base64url-encoded |
| `pqc_ct` | `string` | ML-KEM-768 ciphertext — 1088 bytes, base64url-encoded |
| `algorithm` | `string` | Always `"X25519+ML-KEM-768"` |

```json
{
  "classical_ct": "aB3xK9mNpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUVWXY",
  "pqc_ct": "AAEC...base64url-1088-bytes...xyz",
  "algorithm": "X25519+ML-KEM-768"
}
```

### `HybridPublicKey`

Produced by [`HybridKemKeypair::public_key`](src/fips203/hybrid.rs). Distributed to senders; suitable for embedding in W3C DID Documents under `keyAgreement`.

| Field | Type | Description |
|-------|------|-------------|
| `x25519_key` | `string` | X25519 public key — 32 bytes, base64url-encoded |
| `mlkem_key` | `string` | ML-KEM-768 public key — 1184 bytes, base64url-encoded |
| `x25519_multibase` | `string` | X25519 key in multibase (base58btc, prefix `z`) for DID `keyAgreement` |
| `mlkem_multibase` | `string` | ML-KEM-768 key in multibase (base58btc, prefix `z`) for DID `keyAgreement` |

```json
{
  "x25519_key": "aB3xK9mNpQrStUvWxYzABCDEFGHIJKLMNOPQRSTUVWXY",
  "mlkem_key": "AAEC...base64url-1184-bytes...xyz",
  "x25519_multibase": "z6Mk...base58btc-encoded-x25519-key...",
  "mlkem_multibase": "z6Mk...base58btc-encoded-mlkem-key..."
}
```

---

## Security Considerations

### Why Hybrid Construction?

The Hybrid X25519+ML-KEM-768 construction provides **dual security**:

- **Against classical adversaries today:** X25519 provides well-understood, widely-deployed elliptic curve Diffie-Hellman security.
- **Against quantum adversaries tomorrow:** ML-KEM-768 (NIST FIPS 203) is secure against Grover's and Shor's algorithms.
- **Harvest-now-decrypt-later attacks:** Ciphertexts encrypted today cannot be decrypted by a future quantum computer because the attacker must also break X25519 (which a quantum computer cannot do faster than classically for the key sizes used here).

Breaking the combined shared secret requires breaking **both** X25519 **and** ML-KEM-768 simultaneously — a significantly higher bar than either alone.

### Secret Key Zeroization

All secret key material implements [`ZeroizeOnDrop`](https://docs.rs/zeroize) from the `zeroize` crate. When a `KemSecretKey` or `SharedSecret` goes out of scope, its backing memory is overwritten with zeros before deallocation, preventing secret material from lingering in heap memory.

```rust
{
    let keypair = HybridKemKeypair::generate(&mut OsRng).unwrap();
    let ss = keypair.decapsulate(&ct).unwrap();
    // ss.bytes is zeroized here when ss drops
}
```

#### JavaScript / WASM Callers

> ⚠️ **The JS garbage collector does NOT call `.free()` automatically.** wasm-bindgen classes hold secret key bytes in WASM linear memory. When the JS GC collects the JS wrapper object it only frees the JS-side handle — it does **not** trigger the Rust `Drop` impl or the `zeroize` destructor. Without an explicit `.free()` call, the secret key bytes remain in WASM linear memory for the entire lifetime of the WASM module instance.

**Fix — explicit `.free()` in a `try/finally` block:**

```javascript
const keypair = new WasmHybridKemKeypair();
try {
  const pubKey = keypair.public_key_json();
  const result = hybrid_encapsulate(pubKey);
  // ... use result ...
} finally {
  keypair.free(); // zeroizes secret key material in WASM memory
}
```

**Fix — `using` declaration (TC39 Explicit Resource Management):**

If your runtime supports it (Node.js 18+, or a bundler with the `using` transform), the `using` keyword calls `.free()` automatically at the end of the block:

```javascript
{
  using keypair = new WasmHybridKemKeypair();
  // keypair.free() is called automatically at end of block
  const pubKey = keypair.public_key_json();
  const result = hybrid_encapsulate(pubKey);
}
```

**Applies to all keypair classes.** Every wasm-bindgen keypair class exposes `.free()` and supports `Symbol.dispose`:

- `WasmHybridKemKeypair`
- `WasmMlKem512Keypair`
- `WasmMlKem768Keypair`
- `WasmMlKem1024Keypair`

**Shared secrets.** The `Uint8Array` values returned by `decapsulate()` and `hybrid_encapsulate()` live in JS heap memory — the Rust `zeroize` destructor does **not** reach them. Overwrite them with zeros when you are done:

```javascript
const sharedSecret = keypair.decapsulate(ciphertextJson); // Uint8Array (32 bytes)
// ... use sharedSecret ...
sharedSecret.fill(0); // manually zeroize JS-side shared secret
```

### Caller-Supplied Entropy

This crate **never hardcodes `OsRng`** in its core API. All `generate` and `encapsulate` methods accept a `&mut R` where `R: CryptoRng + RngCore`. This allows:

- Testing with deterministic RNGs
- Integration with hardware security modules
- Custom entropy sources in embedded environments

The WASM bindings (`wasm.rs`) use `rand_core::OsRng` internally, which routes through `getrandom/js` to `window.crypto.getRandomValues()` in browser environments.

### WASM Entropy

In `wasm32-unknown-unknown` targets with the `wasm` feature enabled, entropy is sourced from the browser's Web Crypto API:

```
window.crypto.getRandomValues() → getrandom/js → rand_core::OsRng → KEM operations
```

This is the same entropy source used by TLS implementations in modern browsers.

### NTRU Deprecation

The `ntru` module exists as a **deprecation marker only**. NTRU was eliminated from NIST standardization consideration. No NTRU operations are implemented. Do not use NTRU for new applications.

### Unsafe Code Policy

This crate's own code contains **zero `unsafe`**, enforced at compile time by `#![forbid(unsafe_code)]` in [`src/lib.rs`](src/lib.rs) — this is true of the published default build (`std`), `no_std`, and `wasm` feature combinations alike.

This forbids `unsafe` in this crate's source only; it does not (and cannot) reach into dependencies, some of which use `unsafe` internally (e.g. for SIMD or constant-time primitives). The gated `hqc`, `bike`, and `mceliece` features would additionally link C FFI dependencies (`pqcrypto-hqc`, `pqcrypto-classicmceliece`) if enabled — but those features don't compile today by design (see P2-01), so no build of this crate currently links C code.

---

## Building from Source

### Prerequisites

- Rust 1.85+ (MSRV, enforced in CI; `rustup update stable`)
- `wasm-pack` for WASM builds: `cargo install wasm-pack`
- `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`

### Run Tests

```powershell
cd pqc-kem
cargo test
```

81 tests pass across `hybrid_kem_tests`, `ml_kem_tests`, and `types_tests`.

### Build WASM `dist/`

```powershell
powershell -ExecutionPolicy Bypass -File pqc-kem/build.ps1
```

This runs `wasm-pack build --target web --features wasm --release` and copies the output into `pqc-kem/dist/`.

### Build for a Specific Target

```powershell
# Native release build
cd pqc-kem; cargo build --release

# WASM release build (no std, wasm feature)
cd pqc-kem; cargo build --target wasm32-unknown-unknown --no-default-features --features wasm --release

# With optional algorithm features (requires C toolchain)
# NOTE: the `bike` feature is not yet implemented and will emit a compile error.
# Use `--features hqc` alone until BIKE support is complete.
cd pqc-kem; cargo build --release --features hqc
```

> ⚠️ **`bike` feature not yet implemented.** Passing `--features bike` (or `--features hqc,bike`) will produce a compile error. The `bike` module is a placeholder; BIKE support is planned for a future release.

### Rebuild `dist/` Manually

```powershell
cd pqc-kem
wasm-pack build --target web --no-default-features --features wasm --release --out-dir dist
```

---

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on a fresh GitHub-hosted `ubuntu-latest` runner with no dependency or build caching — every run gets a genuinely clean checkout and toolchain install, not a machine with leftover local state. It needs nothing beyond what's listed above (no credentials, no pre-installed tools, no local files): just Rust via `rustup`, installed fresh by [`dtolnay/rust-toolchain`](https://github.com/dtolnay/rust-toolchain).

Four jobs:

- **Default features (build + test)** — `cargo build` / `cargo test` with default features. This is the crate's supported surface and must always pass. This job also records the clone-to-green time (fresh checkout → passing tests) in the workflow run summary.
- **MSRV (Rust 1.85.0, build + test)** — `cargo build` / `cargo test` with default features, pinned to exactly the `rust-version` declared in `Cargo.toml` (not `stable`). Fails if any future change relies on a Rust feature newer than the declared MSRV.
- **`--all-features` (must fail with exactly hqc/bike/mceliece)** — `cargo build --all-features` is *expected* to fail here: `hqc`, `bike`, and `mceliece` are deliberately gated behind `compile_error!` stubs (see P2-01) because their underlying `pqcrypto-*` dependencies don't implement what this crate calls against. This job asserts that contract in both directions — it fails if `--all-features` starts passing (a gate was silently removed/fixed) and it fails if the failure stops being exactly those three named messages (something else broke and got buried underneath them).
- **Packaged artifact (`cargo package` build + test)** — builds and tests the actual packaged `.crate` output (what a `cargo add` consumer gets), not the live working tree, catching cases where `.gitignore`/package-exclude rules would ship something broken or incomplete.

---

## Browser Test

A `test.html` page is included in `dist/` for quick smoke-testing in a browser.

```powershell
npx serve pqc-kem/dist
# Open http://localhost:3000/test.html
```

The test page exercises:
- `WasmHybridKemKeypair` keypair generation
- `hybrid_encapsulate` + `decapsulate` roundtrip
- `WasmMlKem768Keypair` standalone roundtrip
- `pqc_kem_version()` and `primary_algorithm()` utility calls

---

## Stability and support

This project ships `0.x`. See [`STABILITY.md`](./STABILITY.md) for what counts as a breaking
change, deprecation notice, release cadence, and support posture.

## Security

See [`SECURITY.md`](./SECURITY.md) to report a vulnerability.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md), including the current external-contribution
posture.

## License

MIT OR Apache-2.0

## Maintainer

Ed Johnson


