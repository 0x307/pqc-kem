# pqc-kem

[![CI](https://github.com/0x307/pqc-kem/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/0x307/pqc-kem/actions/workflows/ci.yml)
[![cargo-deny](https://github.com/0x307/pqc-kem/actions/workflows/cargo-deny.yml/badge.svg?branch=main)](https://github.com/0x307/pqc-kem/actions/workflows/cargo-deny.yml)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)
![WASM: Compatible](https://img.shields.io/badge/WASM-Compatible-green.svg)
![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-orange.svg)

> **On the two badges above.** Both **CI** and **cargo-deny** are build gates and must be
> green; a red run on either is a real break. This was not always true of `cargo-deny`: prior
> to 0.3.0 three `pqcrypto-*` crates, reachable only through the non-default `mceliece`
> feature, carried `unmaintained` advisories inherited from upstream PQClean's archival. 0.3.0
> removed the `bike`/`mceliece` features and their `pqcrypto-*` dependencies entirely (see
> [SECURITY.md](./SECURITY.md) for the history), so `cargo-deny` is expected to pass now.

**Post-quantum Key Encapsulation Mechanisms for Rust and WebAssembly.**

`pqc-kem` is a pure Rust, `no_std`-compatible **library** implementing post-quantum KEM algorithms: ML-KEM-512/768/1024 (NIST FIPS 203) and the recommended Hybrid X25519+ML-KEM-768 construction, plus optional, native-only HQC (NIST 2025) behind a non-default feature — meant to be imported into other builds (`cargo add pqc-kem`), including your own `wasm32-unknown-unknown` project, with zero external C dependencies for the primary ML-KEM and Hybrid KEM paths. It is not itself a standalone artifact (see [Crate layout](#crate-layout) below for the sibling crate that is). Secret key material is zeroized on drop via the `zeroize` crate, and entropy is never hardcoded — callers always supply their own RNG.

The prebuilt `.wasm` + `.js` + `.d.ts` + `.wit` artifacts for JavaScript/TypeScript consumers (no Rust toolchain required) are produced by the sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate — see [Crate layout](#crate-layout) and the [JS/TS quickstarts](#quick-start--javascript--typescript-browser) below. All wire types serialize to compact base64url JSON suitable for DID Documents and JWK payloads.

## What this crate promises

This crate implements several algorithms (see [Algorithm Support](#algorithm-support) below),
but they are not all equally recommended. Per [`STABILITY.md`](./STABILITY.md) (this project
ships `0.x`; breaking changes are governed by that document, not SemVer), the posture is:

- **The stable, recommended surface is the Hybrid X25519+ML-KEM-768 construction**
  (`fips203::HybridKemKeypair`) — this is [`PRIMARY_ALGORITHM`](src/lib.rs), the identifier
  string `"X25519+ML-KEM-768"` returned by `primary_algorithm()`/`pqc_kem::PRIMARY_ALGORITHM`.
  Use this for all new applications unless you have a specific reason not to.
- **ML-KEM-768 standalone** (`fips203::MlKem768Keypair`) is the recommended *non-hybrid* choice
  when you need pure post-quantum security with no classical component (e.g. interop with a
  peer that only speaks FIPS 203) — also default-feature, pure Rust, `no_std`.
- **ML-KEM-512 and ML-KEM-1024** are provided for completeness (NIST FIPS 203's other two
  parameter sets) — same implementation quality and test coverage as ML-KEM-768, just not the
  recommended default security level for most applications.
- **HQC-128/192/256 is optional, native-only, and non-default** (`hqc` feature, via `liboqs`).
  It is a real, working implementation (not a stub — see [Algorithm Support](#algorithm-support)
  and the [`src/hqc/mod.rs`](src/hqc/mod.rs) module docs), but it carries a C FFI dependency,
  is not WASM-compatible, and has had substantially less real-world exercise in this crate than
  the pure-Rust ML-KEM/hybrid path above. Everything in this crate — HQC included — ships under
  the same `0.x` stability policy in `STABILITY.md`; HQC's opt-in, non-default status is what
  keeps it off any build that doesn't explicitly ask for it (K-2).
- **BIKE, Classic McEliece, and NTRU are not part of this crate** — see the note under
  [Algorithm Support](#algorithm-support).

Known-answer test vectors, named byte-encoded hybrid profiles and the `aead-wrap` KEM→AEAD
helper, previously listed here as future work, ship in 0.3.0: see
[`tests/vectors/README.md`](tests/vectors/README.md),
[`docs/hybrid-profiles.md`](docs/hybrid-profiles.md) and
[Sealed boxes](#sealed-boxes-aead-wrap-feature) below.

## Crate layout

This repository is one Git repo, one published crate (`pqc-kem`), and two Cargo *packages*:

| Package | Publishes to crates.io? | `crate-type` | Purpose |
|---|---|---|---|
| [`pqc-kem`](./Cargo.toml) (this directory) | **Yes** | `rlib` only | The library. `cargo add pqc-kem` and use it directly in any Rust project — including your own `wasm32-unknown-unknown` build. |
| [`pqc-kem-wasm`](./pqc-kem-wasm) | No (`publish = false`) | `cdylib` only | Depends on `pqc-kem`; produces the standalone `.wasm` artifact + JS/TS bindings that ship to npm. Exists so JS/TS developers with no Rust toolchain still get a prebuilt package. |

Why two packages instead of one: Cargo's `[lib] crate-type` is unconditional — a single crate can't be "`rlib` for library consumers, `cdylib` for the standalone build" depending on who's asking. Cargo also always builds *every* declared crate-type for a package, even ones an ordinary dependent never asked for — so a crate declaring both `cdylib` and `rlib` forces every consumer to satisfy the `cdylib` link requirements too (this broke `pqc-kem` as a plain dependency in an earlier draft of this fix — see `CRA-1`, Linear, for the full writeup). Splitting the standalone-artifact mechanism into its own crate is what lets `pqc-kem` stay an ordinary, well-behaved Rust library.

## What runs today

- ML-KEM-512, ML-KEM-768, ML-KEM-1024 (NIST FIPS 203) — pure Rust, `no_std`-compatible, default features
- Hybrid X25519+ML-KEM-768 construction (the recommended primary API)
- `pqc-kem` itself builds cleanly for `wasm32-unknown-unknown` as an ordinary dependency of your own Rust/wasm-bindgen project — no special feature needed
- WASM/JS bindings (`WasmHybridKemKeypair`, `WasmMlKem{512,768,1024}Keypair`, and the free functions) and the prebuilt `.wasm` artifact, via the sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate (see [Crate layout](#crate-layout))
- Wire types (`KemPublicKey`, `KemCiphertext`, `SharedSecret`, `HybridPublicKey`, `HybridKemCiphertext`) with base64url JSON and multibase (base58btc) encoding, zeroized secret material on drop

**Also runs today (opt-in, native-only):**

- HQC-128/192/256 (NIST 2025 standard) behind the non-default `hqc` feature — a **real, working implementation** via `liboqs` (the `oqs` crate), not a stub. Requires a C toolchain, `cmake`, and `libclang` (for `bindgen`); not compatible with `wasm32-unknown-unknown`. Never part of the WASM/JS surface. See "Why `liboqs` and not `pqcrypto-hqc`" under Security Considerations for why this dependency was chosen.

---

## Algorithm Support

| Algorithm                  | Standard            | Security Level | Public Key   | Ciphertext   | Shared Secret | WASM Native | Feature Flag  | Status                    |
|----------------------------|---------------------|----------------|--------------|--------------|---------------|-------------|---------------|---------------------------|
| **ML-KEM-512**             | NIST FIPS 203       | Level 1        | 800 bytes    | 768 bytes    | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **ML-KEM-768**             | NIST FIPS 203       | Level 3        | 1184 bytes   | 1088 bytes   | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **ML-KEM-1024**            | NIST FIPS 203       | Level 5        | 1568 bytes   | 1568 bytes   | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **Hybrid X25519+ML-KEM-768** | FIPS 203 + RFC 7748 | Level 3+     | 1216 bytes   | 1120 bytes   | 32 bytes      | ✅ Yes      | *(default)*   | ✅ Implemented            |
| **HQC-128**                | NIST 2025           | Level 1        | 2249 bytes   | 4433 bytes   | 32 bytes      | ❌ C FFI    | `hqc`         | ✅ Implemented (via `liboqs`) |
| **HQC-192**                | NIST 2025           | Level 3        | 4522 bytes   | 8978 bytes   | 32 bytes      | ❌ C FFI    | `hqc`         | ✅ Implemented (via `liboqs`) |
| **HQC-256**                | NIST 2025           | Level 5        | 7245 bytes   | 14421 bytes  | 32 bytes      | ❌ C FFI    | `hqc`         | ✅ Implemented (via `liboqs`) |

> **Recommended:** Use the **Hybrid X25519+ML-KEM-768** construction for all new applications. It provides security against both classical and quantum adversaries simultaneously.
>
> **HQC is real and implemented, but native-only and opt-in.** Enabling `--features hqc` builds a working HQC-128/192/256 implementation via `liboqs` (the `oqs` crate) — requires a C toolchain, `cmake`, and `libclang` (for `bindgen`); not compatible with `wasm32-unknown-unknown`. See [Security Considerations § HQC dependency choice](#why-liboqs-and-not-pqcrypto-hqc) below for why `liboqs` was chosen over `pqcrypto-hqc`.
>
> **BIKE, Classic McEliece, and NTRU are not part of this crate.** Earlier `0.2.x` releases carried non-functional `bike`/`mceliece` feature stubs and an `ntru` deprecation-marker module; all three were removed entirely in 0.3.0 (see `CHANGELOG.md`). `cargo build --all-features` builds and tests cleanly now.

---

## Per-target support matrix

Evidence-based, not aspirational — each cell reflects an actual `cargo build`/`cargo test`
run, an existing CI job, or an explicit `cfg`/feature gate in this repo (see the reason column
where relevant). "native (std)" and "native no_std+alloc" are this crate's two
`--(no-)default-features` builds; the two `pqc-kem-wasm` rows are the sibling cdylib crate's
`wasm-bindgen`/`wasm-pack` output. Re-verify against
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) if this ever looks out of date — CI
is authoritative, this table is a snapshot of it plus local checks run for the 0.3.0 pass
(X-3).

| Target | ML-KEM-512/768/1024 | Hybrid X25519+ML-KEM-768 | HQC (native-only, `liboqs`) | serde/JSON wire types | Zeroization |
|---|---|---|---|---|---|
| **native (std)** — default features | ✅ Supported — `cargo test` (99 tests + 3 doctests) | ✅ Supported — same run | ✅ Supported — `--features hqc`; real `liboqs` build, exercised in CI's `hqc-feature-build-test` job on `ubuntu-latest` (not re-verified on this Windows machine this pass — `oqs-sys`'s `bindgen` step fails locally on Windows, a pre-existing, unrelated limitation) | ✅ Supported | ✅ Supported — `tests/zeroize_tests.rs`, 22 tests |
| **native no_std+alloc** (`--no-default-features`) | ✅ Supported — `cargo test --no-default-features` (same 99 tests + 3 doctests) | ✅ Supported — same run | ⚠️ **Unverified** — the `hqc` feature itself doesn't require this crate's own `std` feature, but the `--no-default-features --features hqc` combination is not exercised by any CI job (CI's `hqc` job uses default features) and could not be locally checked this pass for the same `oqs-sys`/`bindgen` reason as above | ✅ Supported — `serde_json/alloc`; same run | ✅ Supported — same run, 22 tests |
| **`wasm32-unknown-unknown`** (root crate `pqc-kem`, ordinary `rlib` dependency; no `wasm` feature exists — see Feature Flags) | ✅ Supported — `cargo build --target wasm32-unknown-unknown --no-default-features` succeeds locally; also CI's `wasm-cdylib-build` job (via the sibling crate, below) | ✅ Supported — same build | ❌ **Not available** — C FFI via `liboqs`; the `hqc` feature is native-target-only by design (`oqs-sys` links a C library; no `wasm32-unknown-unknown` liboqs build exists) | ✅ Supported — compiles; not independently executed at this layer (see the `pqc-kem-wasm` row for an executed round-trip of the same JSON types) | ✅ Supported — compiles; same zeroizing `Drop` mechanism as native |
| **`wasm32-unknown-unknown` via `pqc-kem-wasm`** (cdylib, `wasm-bindgen`/npm surface) | ✅ Supported — **executed**: `node tests/wasm_api_test.mjs`, 15/15 passing, round-trip verified for all three parameter sets | ✅ Supported — **executed**: round-trip + shared-secret-equality tests pass | ❌ **Not available** — never exposed on this surface by design (K-2: "keep HQC off the WASM/JS path"); no `WasmHqc*` types exist in [`pqc-kem-wasm/src/lib.rs`](pqc-kem-wasm/src/lib.rs) | ✅ Supported — **executed**; every wire type on this surface is JSON | ✅ Supported — **executed**: `.free()` and double-free-throws tests pass; JS-side caveats documented under [Security Considerations](#javascript--wasm-callers) |
| **`wasm32-wasip1`** (root crate, `--no-default-features`) | ⚠️ **Build-verified, execution unverified** — `cargo build --target wasm32-wasip1 --no-default-features` succeeds locally on this machine; no test in this repo runs on this target, and no CI job builds or tests it | ⚠️ Same as ML-KEM column | ❌ **Not available** — C FFI, native-target-only (same reason as `wasm32-unknown-unknown` above) | ⚠️ Build-verified only, same caveat | ⚠️ Build-verified only, same caveat |
| **`wasm32-wasip2`** (root crate, `--no-default-features`) | ⚠️ **Build-verified, execution unverified** — `cargo build --target wasm32-wasip2 --no-default-features` succeeds locally on this machine; same caveats as `wasm32-wasip1` above (no test/CI exercise) | ⚠️ Same as ML-KEM column | ❌ **Not available** — same reason | ⚠️ Build-verified only, same caveat | ⚠️ Build-verified only, same caveat |

**Legend:** ✅ Supported (verified by a passing build/test run or existing CI job) · ⚠️
Unverified / build-only (compiles, but execution or CI coverage is missing — treat as
provisional) · ❌ Not available (excluded by design or a hard platform constraint, not a gap).

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

Build the WASM package targeting Node.js (from the [`pqc-kem-wasm`](./pqc-kem-wasm) crate — see [Crate layout](#crate-layout)):

```powershell
cd pqc-kem-wasm
wasm-pack build --target nodejs --release -- --no-default-features
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
# WASM target (wasm32-unknown-unknown) -- builds as-is, no special feature
# needed; see "Crate layout" above. Write your own #[wasm_bindgen] surface
# on top, or see the pqc-kem-wasm crate in this repo as a reference.
pqc-kem = { path = "./pqc-kem", default-features = false }

# With HQC (requires a C toolchain, cmake, and libclang for bindgen)
pqc-kem = { path = "./pqc-kem", features = ["hqc"] }

# no_std with alloc (embedded)
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
| `hqc`        | ❌ No   | Enables HQC-128/192/256 via `liboqs` (the `oqs` crate, C FFI). Not WASM-compatible. Requires a C toolchain, `cmake`, and `libclang` (for `bindgen`) — no OpenSSL required with this feature alone. |
| `aead-wrap`  | ❌ No   | Adds [`aead_wrap`](src/aead_wrap.rs): seal a payload to a KEM public key (KEM → HKDF-SHA256 → XChaCha20-Poly1305 or ChaCha20-Poly1305). One new dependency, `chacha20poly1305`, without its `alloc` feature. `no_std`/`alloc`- and WASM-compatible. See [Sealed boxes](#sealed-boxes-aead-wrap-feature). |
| `kat`        | ❌ No   | Adds a handful of deterministic, **testing/interop-only** entry points (`MlKem{512,768,1024}Keypair::from_seed_halves`/`encapsulate_deterministic`/`from_expanded_decapsulation_key_bytes`/`to_expanded_decapsulation_key_bytes`, `fips203::hybrid::x25519_kat`) used by `tests/kat_ml_kem.rs` and `tests/kat_x25519.rs` to check this crate against published Known-Answer-Test vectors. `no_std`/`alloc`-compatible; adds no new dependencies. **Never use these for production key generation or key exchange.** See [Known-Answer Tests](#known-answer-tests) below. |

There is no `wasm` feature on `pqc-kem` itself — it builds for `wasm32-unknown-unknown` as an ordinary dependency, no feature flag needed (the required `getrandom` backend for that target is wired in automatically; see Cargo.toml). The `wasm-bindgen` JS/TS surface lives in the sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate — see [Crate layout](#crate-layout).

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

### Sealed boxes (`aead-wrap` feature)

A KEM gives you a 32-byte shared secret, not encrypted data. [`aead_wrap`](src/aead_wrap.rs)
does the remaining step, so callers don't each write their own key derivation and nonce
handling: seal a payload to a recipient's public key, and the recipient opens it with their
keypair.

```
(kem_ct, ss) = Encapsulate(recipient_public_key)
key          = HKDF-SHA256(ikm = ss, salt = none,
                           info = "pqc-kem-aead-wrap-v1" ‖ 0x00 ‖ kem_algorithm ‖ 0x00 ‖ context)
ciphertext   = AEAD(key, random nonce, plaintext, aad = kem_ct ‖ aad)
```

```rust
use pqc_kem::aead_wrap::{open_hybrid, seal_hybrid};
use pqc_kem::HybridKemKeypair;
use rand::rngs::OsRng;

let recipient = HybridKemKeypair::generate(&mut OsRng).unwrap();
let sealed = seal_hybrid(&mut OsRng, &recipient.public_key(), b"my-protocol/v1", b"header", b"payload").unwrap();
let plaintext = open_hybrid(&recipient, &sealed, b"my-protocol/v1", b"header").unwrap();
assert_eq!(&plaintext[..], b"payload");
```

- **Suites.** XChaCha20-Poly1305 is the default (`seal_hybrid`, `seal_ml_kem_768`).
  ChaCha20-Poly1305 is available through the `*_with_suite` functions for peers that need the
  IETF 12-byte-nonce construction. Each box carries its suite, and opening accepts either.
  Every box derives a fresh key from a fresh encapsulation, so a random nonce is safe for both
  suites. No function takes a caller-chosen nonce.
- **KEMs.** The X25519+ML-KEM-768 hybrid (profile v1) and ML-KEM-768.
- **`context`** is domain separation: the same shared secret under two contexts gives two
  unrelated keys. Use a fixed, protocol-specific string. Opening with a different context fails.
- **`aad`** is authenticated but not encrypted. The KEM ciphertext is always bound in as well,
  so a box's AEAD half cannot be moved onto another box's KEM half.
- **Errors.** Malformed boxes (wrong lengths, wrong algorithm) fail with
  `KemError::InvalidCiphertext`. Every failure after that, whether from a wrong key, tampering
  or a wrong context or AAD, returns one identical error, so a failed open reveals nothing
  about which check failed.
- **Secrets.** The derived key (`AeadKey`) and the opened plaintext (`Zeroizing<Vec<u8>>`)
  zeroize on drop.
- **Wire format.** `SealedBox` serializes to JSON with base64url byte fields
  (`SealedBox::to_json` / `from_json`), like the crate's other wire types.
- **Derivation vectors.** `tests/vectors/aead_wrap_v1.json` pins `derive_aead_key` to values
  computed by an independent RFC 5869 implementation. Changing the derivation means a new label
  (`pqc-kem-aead-wrap-v2`), never new values under the old one.

---

### HQC (NIST 2025 standard) — native only, `hqc` feature

[`Hqc128Keypair`/`Hqc192Keypair`/`Hqc256Keypair`](src/hqc/mod.rs) share the same method shape as the ML-KEM types above. Implemented via `liboqs` (the `oqs` crate) — see "Why `liboqs` and not `pqcrypto-hqc`" under Security Considerations for the rationale, and the module-level docs in [`src/hqc/mod.rs`](src/hqc/mod.rs) for the full technical writeup.

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> KemResult<Self>` | Generate a new keypair (liboqs uses its own internal entropy; `rng` is accepted for API consistency only) |
| `public_key` | `fn public_key(&self) -> KemPublicKey` | Returns the public key |
| `encapsulate` | `fn encapsulate<R>(rng: &mut R, pk: &KemPublicKey) -> KemResult<(KemCiphertext, SharedSecret)>` | Encapsulate |
| `decapsulate` | `fn decapsulate(&self, ct: &KemCiphertext) -> KemResult<SharedSecret>` | Decapsulate; **returns `Err`, never panics**, on a ciphertext/secret-key mismatch |

```rust
use pqc_kem::hqc::Hqc128Keypair;
use rand::rngs::OsRng;

let recipient = Hqc128Keypair::generate(&mut OsRng).unwrap();
let pk = recipient.public_key();

let (ct, sender_ss) = Hqc128Keypair::encapsulate(&mut OsRng, &pk).unwrap();
let recipient_ss = recipient.decapsulate(&ct).unwrap();

assert_eq!(sender_ss.bytes, recipient_ss.bytes);
```

---

### WASM Exports

All exports are in the sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate (see [Crate layout](#crate-layout)), not `pqc-kem` itself. Byte arrays cross the WASM boundary as `Uint8Array`. Errors are returned as JavaScript `Error` objects.

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
| `public_key_bytes()` | `Uint8Array` | Public key in its canonical profile-v1 encoding, `x25519(32) ‖ mlkem(1184)` (1216 bytes) |
| `decapsulate_bytes(ciphertext_bytes: Uint8Array)` | `Uint8Array` | Decapsulate a canonical profile-v1 ciphertext (1120 bytes); returns 32-byte shared secret |
| `aead_open(sealed_json: string, context: Uint8Array, aad: Uint8Array)` | `Uint8Array` | Open a box from `aead_seal_hybrid`; returns the plaintext |

#### `WasmMlKem{512,768,1024}Keypair` Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `public_key_bytes()` | `Uint8Array` | Raw public key bytes |
| `public_key_base64url()` | `string` | Public key as base64url string |
| `decapsulate(ciphertext_bytes: Uint8Array)` | `Uint8Array` | Decapsulate raw ciphertext bytes; returns 32-byte shared secret |
| `aead_open(sealed_json: string, context: Uint8Array, aad: Uint8Array)` | `Uint8Array` | **ML-KEM-768 only.** Open a box from `aead_seal_ml_kem_768`; returns the plaintext |

#### Free Functions

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `hybrid_encapsulate` | `(recipient_public_key_json: string) => string` | JSON `{ciphertext: {...}, shared_secret: "<base64url>"}` | Encapsulate to a hybrid public key |
| `ml_kem_512_encapsulate` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to ML-KEM-512 public key |
| `ml_kem_768_encapsulate` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to ML-KEM-768 public key |
| `ml_kem_1024_encapsulate` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to ML-KEM-1024 public key |
| `hybrid_encapsulate_bytes` | `(recipient_public_key_bytes: Uint8Array) => string` | JSON `{"ciphertext_bytes": "<base64url>", "shared_secret": "<base64url>"}` | Encapsulate to a hybrid public key in its 1216-byte canonical encoding |
| `hybrid_profile_id` | `() => string` | `"HybridKem-X25519-MLKEM768-v1"` | The hybrid construction's named profile |
| `aead_seal_hybrid` | `(recipient_public_key_json: string, context: Uint8Array, aad: Uint8Array, plaintext: Uint8Array) => string` | JSON sealed box | Seal to a hybrid public key with XChaCha20-Poly1305 |
| `aead_seal_ml_kem_768` | `(recipient_public_key_bytes: Uint8Array, context: Uint8Array, aad: Uint8Array, plaintext: Uint8Array) => string` | JSON sealed box | Seal to an ML-KEM-768 public key with XChaCha20-Poly1305 |
| `pqc_kem_version` | `() => string` | `"0.3.0"` | Returns the crate version |
| `primary_algorithm` | `() => string` | `"X25519+ML-KEM-768"` | Returns the primary algorithm identifier |

Sealing from JavaScript is XChaCha20-Poly1305 only, so nonces are always generated inside the
library. `aead_open` accepts either suite, so boxes sealed in Rust with ChaCha20-Poly1305 still
open in JavaScript. X-Wing (profile v2) is Rust-only in 0.3.0.

---

### WIT reference document (Component Model status: not shipped)

**No WASM Component (`wasm32-wasip2` or otherwise) is built anywhere in this repo.**
[`wit/pqc-kem.wit`](wit/pqc-kem.wit) is a **descriptive interface contract**, written in
WIT-style pseudocode, for the flat `wasm-bindgen` JS API that the sibling
[`pqc-kem-wasm`](./pqc-kem-wasm) crate actually produces (see
[WASM Exports](#wasm-exports) above and [`pqc-kem-wasm/src/lib.rs`](pqc-kem-wasm/src/lib.rs)).
It documents every class, method, and free function in that crate, one-to-one, so it's useful
as a quick reference — but it is **not parseable** by `jco`, `cargo component`, or any other
WASM Component Model toolchain, and there is no `cargo component build` step or `world`
declaration anywhere in this repo. `pqc-kem-wasm`'s `crate-type` is `["cdylib"]` built with
plain `wasm-bindgen`/`wasm-pack` (see [`build.ps1`](build.ps1)), which is a different, earlier
compilation target than the WASM Component Model.

The file itself opens with the same disclaimer, in more detail, and is kept in sync with
[`pqc-kem-wasm/src/lib.rs`](pqc-kem-wasm/src/lib.rs) as the source of truth for what it
documents.

---

## Wire Types

### `HybridKemCiphertext`

Produced by [`HybridKemKeypair::encapsulate`](src/fips203/hybrid.rs) and [`hybrid_encapsulate`](pqc-kem-wasm/src/lib.rs). Transmitted from sender to recipient.

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

### Audit and FIPS status

- **This crate has not been independently audited.** No third-party security review has been
  performed on `pqc-kem` itself.
- **No CMVP / FIPS 140-3 module validation exists or is claimed** for this crate or any of its
  dependencies. "FIPS 203" in this README refers to the *algorithm standard* ML-KEM implements,
  not a certified module.
- **ML-KEM comes from the [`ml-kem`](https://crates.io/crates/ml-kem) RustCrypto crate,
  version `0.3.2`** (exact version pinned in [`Cargo.lock`](Cargo.lock); `Cargo.toml` allows
  `"0.3"`). It implements the FIPS 203 algorithm but, like this crate, is **not itself
  CMVP-validated**.
- **X25519 comes from [`x25519-dalek`](https://crates.io/crates/x25519-dalek), version
  `2.0.1`.**
- **Constant-time behavior is delegated entirely to those two upstream crates.** This crate's
  own code performs no secret-dependent branching or comparison (`SharedSecret` deliberately
  has no `PartialEq`) and contains zero `unsafe` (`#![forbid(unsafe_code)]` — see
  [Unsafe Code Policy](#unsafe-code-policy) below); it does not itself implement any
  constant-time primitive, so its safety here is inherited, not independently verified by this
  crate.
- **Exact dependency versions on the default (`std`) crypto path**, from `Cargo.lock` at the
  time of this writing:

  | Crate | Version | Role |
  |---|---|---|
  | `ml-kem` | 0.3.2 | ML-KEM-512/768/1024 (FIPS 203) |
  | `x25519-dalek` | 2.0.1 | X25519 (hybrid construction) |
  | `hkdf` | 0.12.4 | HKDF-SHA256 (hybrid combiner) |
  | `sha2` | 0.10.9 | SHA-256 (used by `hkdf`) |
  | `zeroize` | 1.9.0 | Secret-material zeroization |
  | `serde` / `serde_json` | 1.0.229 / 1.0.151 | Wire-type (de)serialization |
  | `base64ct` | 1.8.3 | base64url encoding of wire types |
  | `bs58` | 0.5.1 | multibase (base58btc) encoding |
  | `thiserror` | 2.0.19 | Error types |
  | `rand_core` | 0.6.4 | Caller-supplied RNG trait bounds |
  | `chacha20poly1305` | 0.10.1 | Linked but currently unused in `src/` (see `Cargo.toml`'s comment; reserved for the planned `aead-wrap` feature) |
  | `oqs` (`hqc` feature only) | 0.11.0 | HQC-128/192/256 via `liboqs` |

  Re-run `cargo tree` / inspect `Cargo.lock` directly if this list is ever stale — it is not
  regenerated automatically.
- **Report a suspected vulnerability** via [`SECURITY.md`](./SECURITY.md), not a public GitHub
  issue.

### Known-Answer Tests

All of this crate's day-to-day tests are randomized round-trips (generate → encapsulate →
decapsulate, assert equality) — useful for catching regressions, but they don't prove this
crate's output matches an *independent* reference implementation. The non-default `kat` feature
closes that gap:

```sh
cargo test --features kat
```

This runs [`tests/kat_ml_kem.rs`](tests/kat_ml_kem.rs) and [`tests/kat_x25519.rs`](tests/kat_x25519.rs)
against vendored vector files under [`tests/vectors/`](tests/vectors/README.md):

- **ML-KEM-512/768/1024** — subsets of the official NIST ACVP `ML-KEM-keyGen-FIPS203` and
  `ML-KEM-encapDecap-FIPS203` test vectors (keyGen, encapsulation, and decapsulation — including
  implicit-rejection cases where the ciphertext is malformed).
- **X25519** — the RFC 7748 §5.2 scalar-multiplication and iterated vectors, plus the §6.1
  Alice/Bob Diffie-Hellman worked example.

Full provenance (upstream source, how each file was vendored, and how to regenerate) is
documented in [`tests/vectors/README.md`](tests/vectors/README.md). The `kat` feature also adds
a small number of deterministic, **testing/interop-only** entry points
(`MlKem{512,768,1024}Keypair::from_seed_halves`/`encapsulate_deterministic`/
`from_expanded_decapsulation_key_bytes`/`to_expanded_decapsulation_key_bytes`,
`fips203::hybrid::x25519_kat`) that exist solely to make this checkable — every one of them is
rustdoc'd as not suitable for production key generation or key exchange, and none of them are
enabled by default. `tests/vectors/` ships as part of the published crate package so downstream
integrators can reuse the same vectors (see `cargo package --list`).

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

#### Secret material and zeroization (0.3.0)

As of 0.3.0 (A-Z1 hardening), every keypair type in this crate implements
[`zeroize::ZeroizeOnDrop`](https://docs.rs/zeroize), not just the `KemSecretKey`/
`SharedSecret` wire types shown above:

| Type | Secret field(s) | How it zeroizes |
|---|---|---|
| `HybridKemKeypair` | `x25519_secret` (`StaticSecret`), `mlkem_dk` (`DecapsulationKey`) | Each field's own `Drop` impl (`x25519-dalek/zeroize` and `ml-kem/zeroize` features, both enabled by this crate) zeroizes it; the wrapper needs no explicit `Drop`. |
| `MlKem512Keypair` / `MlKem768Keypair` / `MlKem1024Keypair` | `decapsulation_key` (`DecapsulationKey`) | Same mechanism — `ml-kem/zeroize` gives `DecapsulationKey` its own zeroizing `Drop`. |
| `Hqc128Keypair` / `Hqc192Keypair` / `Hqc256Keypair` (`hqc` feature) | `secret_key_bytes` (`Vec<u8>`) | `#[derive(Zeroize, ZeroizeOnDrop)]` on the struct (both `Vec<u8>` fields, including the public one, are zeroized — zeroizing the public key too is harmless). |
| `KemSecretKey`, `SharedSecret` | `bytes` (`Vec<u8>`) | `#[derive(Zeroize, ZeroizeOnDrop)]` (unchanged from 0.2.0). |

**Public key material is never zeroized** — `KemPublicKey`, `HybridPublicKey`,
`EncapsulationKey`/`PublicKey` fields inside keypair structs, and JSON string fields
carry no secrets and are not zeroized on drop.

**New, zeroizing secret accessors** (replacing plain-byte accessors that were never
zeroized on drop):

```rust
impl HybridKemKeypair {
    pub fn x25519_secret(&self) -> KemSecretKey;          // 32 bytes, zeroized on drop
    pub fn mlkem_seed(&self) -> KemResult<KemSecretKey>;  // 64 bytes, zeroized on drop
}
impl MlKem512Keypair /* and 768/1024 */ {
    pub fn try_secret_key(&self) -> KemResult<KemSecretKey>; // fallible form of secret_key()
}
```

`HybridKemKeypair::x25519_secret_bytes()` and `mlkem_secret_bytes()` are
`#[deprecated(since = "0.3.0")]` — they still work (see `STABILITY.md` §8 for the
migration note and earliest-removal version) but return plain, non-zeroizing
`[u8; 32]`/`Vec<u8>` values. `mlkem_secret_bytes()` also silently returns an empty
`Vec` instead of an error if the seed is unavailable; `mlkem_seed()` returns
`Err(KemError::Internal(..))` in that case instead.

**What stays caller-managed, even at 0.3.0:** cloning a `KemSecretKey`/`SharedSecret`
produces a new, independently-zeroizing value — the *original* is unaffected and still
zeroizes on its own drop, but any `Vec<u8>`/`[u8; N]` you copy `.bytes` out of into your
own variables is not tracked or zeroized by this crate. The JS/WASM caveats in the next
subsection apply regardless of this crate's own zeroization guarantees, since they are
about a different memory space entirely (WASM linear memory / JS heap).

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

This crate (`pqc-kem`) **never hardcodes `OsRng`** in its API. All `generate` and `encapsulate` methods accept a `&mut R` where `R: CryptoRng + RngCore` — the caller always supplies the RNG.

- Testing with deterministic RNGs
- Integration with hardware security modules
- Custom entropy sources in embedded environments

The sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate's JS/TS bindings supply that RNG internally (a small `RngCore`/`CryptoRng` wrapper around `getrandom`'s `wasm_js` backend), so JS callers don't have to.

### WASM Entropy

For `wasm32-unknown-unknown` targets, `pqc-kem` wires in `getrandom` 0.4's `wasm_js` backend automatically (a target-conditional dependency — see Cargo.toml), so `ml-kem`'s own internal entropy needs work out of the box for any consumer building this crate for that target. The [`pqc-kem-wasm`](./pqc-kem-wasm) bindings source their own caller-facing entropy the same way:

```
window.crypto.getRandomValues() → getrandom (wasm_js backend) → RNG passed into KEM operations
```

This is the same entropy source used by TLS implementations in modern browsers.

### Unsafe Code Policy

This crate's own code contains **zero `unsafe`**, enforced at compile time by `#![forbid(unsafe_code)]` in [`src/lib.rs`](src/lib.rs) — this is true of both the `std` and `no_std` builds. The sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate carries the same `#![forbid(unsafe_code)]` in its own `src/lib.rs`.

This forbids `unsafe` in this crate's source only; it does not (and cannot) reach into dependencies, some of which use `unsafe` internally (e.g. for SIMD or constant-time primitives). The `hqc` feature links a C FFI dependency (`liboqs`, via the `oqs` crate) — real and working. (Prior to 0.3.0, the non-default `bike`/`mceliece` features would additionally have linked `pqcrypto-*` C FFI dependencies if they had ever compiled; both features and their dependencies were removed entirely in 0.3.0 — see `CHANGELOG.md`.)

### Why `liboqs` and not `pqcrypto-hqc`?

`pqc-kem` 0.1.0's `hqc` feature was a `compile_error!` stub whose comment claimed `pqcrypto-hqc 0.1`'s published API didn't match this crate's calls (82 compile errors). That claim was re-verified live rather than trusted during the 0.2.0 implementation pass, with two findings:

1. **The old comment is stale.** The currently published `pqcrypto-hqc` (0.2.x) API *does* match almost exactly. It is not the blocker the old comment describes.
2. **A different, more serious defect exists instead.** `pqcrypto-hqc` 0.2.2's `decapsulate()` wraps the underlying PQClean C reference implementation's informational "decapsulation check failed" return code — the FO-transform's *normal, expected* implicit-rejection outcome for **any** ciphertext/secret-key mismatch, not a rare adversarial edge case — in a hard `assert_eq!(.., 0)`. That **panics** (and, under a `panic = "abort"` profile, aborts the whole process) instead of returning an error, for something as ordinary as decapsulating a ciphertext with a secret key it wasn't encapsulated to. Verified live with two independent reproductions: a bit-flipped ciphertext, and an honestly mismatched (but otherwise valid) secret key — both panic via `pqcrypto-hqc`.

`liboqs` (via the `oqs` crate) wraps the identical underlying C return code as a proper `Result` instead — verified live that neither reproduction above panics; both cleanly return `Err`. Byte sizes are identical between the two bindings (both ultimately wrap the same NIST HQC parameter sets), so this is a drop-in-equivalent, strictly safer choice, not a design compromise. See [`src/hqc/mod.rs`](src/hqc/mod.rs) module docs and `CHANGELOG.md` for the full writeup.

**Build cost tradeoff:** `liboqs` needs a C toolchain, `cmake`, and `libclang` (for `bindgen`) to compile its vendored HQC sources, which is heavier than `pqcrypto-hqc`'s plain `cc`-crate build. Verified that the `hqc` feature alone (not `oqs`'s `kems`/`sigs`/`openssl` default feature groups) does **not** additionally require OpenSSL. GitHub Actions `ubuntu-latest` runners bundle `cmake` and `clang`/`libclang` by default, so this is not expected to need new CI setup steps, but that should be confirmed on the first real CI run against this feature.

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

99 tests + 3 doctests pass across the unit tests in `src/`, plus `hybrid_kem_tests`,
`ml_kem_tests`, `types_tests`, and `zeroize_tests` (default features; re-verified for
0.3.0 — see [CI](#continuous-integration) for the authoritative, up-to-date count). Add
`--features hqc` (requires a C toolchain, `cmake`, and `libclang`) to
additionally run `hqc_tests` (16 more tests), and `--features aead-wrap` to run
`aead_wrap_tests` (17 more tests).

### Build WASM `dist/`

```powershell
powershell -ExecutionPolicy Bypass -File pqc-kem/build.ps1
```

This builds the sibling [`pqc-kem-wasm`](./pqc-kem-wasm) crate — `wasm-pack build --target web --release -- --no-default-features` run from `pqc-kem-wasm/` — and copies the output into `pqc-kem/dist/`. See [Crate layout](#crate-layout).

### Build for a Specific Target

```powershell
# Native release build (the library)
cd pqc-kem; cargo build --release

# WASM release build of the library itself (no feature needed -- see Crate layout)
cd pqc-kem; cargo build --target wasm32-unknown-unknown --release

# WASM cdylib artifact (the standalone .wasm build, from pqc-kem-wasm)
cd pqc-kem-wasm; cargo build --target wasm32-unknown-unknown --no-default-features --release

# HQC (requires a C toolchain, cmake, and libclang for bindgen) — real, working
cd pqc-kem; cargo build --release --features hqc

# --all-features (same as --features hqc as of 0.3.0) — builds and tests cleanly
cd pqc-kem; cargo build --release --all-features
```

### Rebuild `dist/` Manually

```powershell
cd pqc-kem-wasm
wasm-pack build --target web --release --out-dir ../dist -- --no-default-features
```

---

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on a fresh GitHub-hosted `ubuntu-latest` runner with no dependency or build caching — every run gets a genuinely clean checkout and toolchain install, not a machine with leftover local state. It needs nothing beyond what's listed above (no credentials, no pre-installed tools, no local files): just Rust via `rustup`, installed fresh by [`dtolnay/rust-toolchain`](https://github.com/dtolnay/rust-toolchain).

Thirteen jobs (four added in 0.3.0's WP3 pass — `no-std-build`, `clippy-and-doc`,
`wasm-targets`, `wasm-pack-node-test` — closing the X-3 gap that previously left the
`no_std` claim, lint/doc hygiene, and the WASM JS API test unenforced by CI):

- **Default features (build + test)** — `cargo build` / `cargo test` with default features. This is the crate's supported surface and must always pass. This job also records the clone-to-green time (fresh checkout → passing tests) in the workflow run summary.
- **MSRV (Rust 1.85.0, build + test)** — `cargo build` / `cargo test` with default features, pinned to exactly the `rust-version` declared in `Cargo.toml` (not `stable`). Fails if any future change relies on a Rust feature newer than the declared MSRV.
- **`pqc-kem-wasm` (wasm32 cdylib artifact)** — builds the actual advertised standalone WASM artifact (the sibling `pqc-kem-wasm` crate; see [Crate layout](#crate-layout)) for `wasm32-unknown-unknown`. This is the exact invocation `build.ps1`/`build-wasm.ps1` run, minus wasm-pack's JS/TS glue generation.
- **Downstream consumer (no_std + external std leak, wasm32)** — builds `tests/downstream-consumer-fixture/`, a minimal separate crate that depends on `pqc-kem` as an ordinary no_std library while independently linking `std` via an unrelated dependency, targeting `wasm32-unknown-unknown`. This is the actual regression test for `CRA-1` — the defect it catches (a library crate wrongly claiming process-wide lang items) is only observable from a consumer's build graph, never from building `pqc-kem` on its own.
- **`hqc` feature (build + test)** — `cargo build`/`cargo test --features hqc`, on a runner with a C toolchain, `cmake`, and `libclang` available (verified not to additionally need OpenSSL for `hqc` alone). This is real, working functionality now, not a stub — must always pass. Also runs `cargo doc --no-deps --features hqc` with `-D warnings` (the only runner in this workflow that can build the `hqc`-gated doc items at all).
- **`--all-features` (build + test)** — `cargo build --all-features && cargo test --all-features` must pass. As of 0.3.0 `--all-features` adds `hqc`, `kat` and `aead-wrap` to the default; the non-functional `bike`/`mceliece` stubs that previously made this job an expected-failure check were removed entirely (see `CHANGELOG.md`'s 0.3.0 entry).
- **Packaged artifact (`cargo package` build + test)** — builds and tests the actual packaged `.crate` output (what a `cargo add` consumer gets), not the live working tree, catching cases where `.gitignore`/package-exclude rules would ship something broken or incomplete. (`pqc-kem-wasm/` and `tests/downstream-consumer-fixture/` are separate Cargo packages with their own `Cargo.toml`, so `cargo package` never pulls them into `pqc-kem`'s own published `.crate` — verified via `cargo package --list`.)
- **`no_std` build + test (`--no-default-features`)** *(new, WP3/X-3)* — `cargo build`/`cargo test --no-default-features`. Previously this claim was only checked locally via `verify-gates.ps1`; it's now enforced on every push/PR.
- **`clippy + rustdoc` (-D warnings, default features)** *(new, WP3/X-3, A-D1)* — `cargo clippy --all-targets -- -D warnings`, then `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"`. Catches both lint regressions and broken intra-doc links (the 9 warnings fixed in this work package — see `CHANGELOG.md`'s 0.3.0 entry) before they ship.
- **WASM target matrix (`wasm32-unknown-unknown` + `wasm32-wasip1`)** *(new, WP3/X-3)* — builds the root `pqc-kem` crate and the sibling `pqc-kem-wasm` crate for `wasm32-unknown-unknown` (`--no-default-features`), then additionally builds the root crate for `wasm32-wasip1` (`--no-default-features`). `wasm32-wasip2` is verified locally (see [Per-target support matrix](#per-target-support-matrix)) but not yet added to this job.
- **`wasm-pack` + `node` (WASM API regression test)** *(new, WP3/X-3, A-D1)* — installs `wasm-pack` and Node LTS, runs the same `wasm-pack build` invocation `build.ps1` runs (translated to bash) from `pqc-kem-wasm/`, then runs `node tests/wasm_api_test.mjs` against the freshly built `dist/`. This is the first CI coverage this test has ever had; previously it could only be run manually, which is how its version-string assertion went stale (A-D1).
- **`kat` feature (build + test)** *(WP4)* — `cargo build`/`cargo test --features kat`, with and without default features, running the Known-Answer Tests against the vendored vectors.
- **`aead-wrap` feature (build + test + clippy + rustdoc)** *(WP6)* — tests the sealed-box helper with and without default features, builds its `no_std` configuration for `wasm32-unknown-unknown`, and runs clippy and rustdoc with `-D warnings` on it. It is the only job that compiles `aead-wrap` directly, since the feature is off by default.

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


