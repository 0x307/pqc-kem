## pqc-kem v0.3.0 (Unreleased)

This release combines five work packages: **WP1** (feature-surface hygiene — K-1, K-3,
unused dependencies), **WP2** (secret-material zeroization hardening — A-Z1), **WP3**
(docs truthfulness, WASM target matrix, WIT header, CI coverage — X-3, X-5, K-2, A-D1),
**WP4** (Known-Answer Tests — X-4) and **WP5** (named hybrid profiles and X-Wing — K-5),
plus pre-release hardening. The X25519+ML-KEM-768 hybrid remains `PRIMARY_ALGORITHM`. Full
details for every change are in [`CHANGELOG.md`](./CHANGELOG.md)'s `[0.3.0] - Unreleased`
entry; this page is a reader-facing summary of it, not a separate source of truth.

### Highlights

- **Removed:** the non-functional `bike`/`mceliece` feature flags and their `src/bike`/
  `src/mceliece` stub modules (each was a permanent `compile_error!`, never a working
  implementation), the `pqcrypto-classicmceliece`/`pqcrypto-traits` dependencies that came
  with them (the sole reason `cargo deny check advisories` was red), and the `ntru`
  deprecation-marker module. `cargo build --all-features` now builds and tests cleanly for
  the first time — the only feature it adds beyond default is the real `hqc` implementation.
- **Deprecated:** `KemAlgorithm::Bike`/`ClassicMceliece` (kept for wire/JSON compatibility;
  removal earliest 0.4.0), and `HybridKemKeypair::x25519_secret_bytes()`/
  `mlkem_secret_bytes()` (replaced by zeroizing, and for the latter properly fallible,
  accessors — see below).
- **Added — zeroization hardening (A-Z1):** `x25519-dalek`'s and `ml-kem`'s `zeroize`
  features are now enabled, giving `HybridKemKeypair`, `MlKem{512,768,1024}Keypair`, and
  (behind `hqc`) `Hqc{128,192,256}Keypair` real `ZeroizeOnDrop` coverage for the first time.
  New accessors `HybridKemKeypair::{x25519_secret, mlkem_seed}` and
  `MlKem{512,768,1024}Keypair::try_secret_key()` return zeroizing types and proper `Result`s
  instead of the old silently-empty-on-failure raw-byte accessors.
- **Added — docs/CI truthfulness (WP3):** a "What this crate promises" section and a
  per-target support matrix in `README.md`; an explicit "Audit and FIPS status" statement
  (not independently audited, no CMVP/FIPS 140-3 validation); an accurate rewrite of the
  README's "WIT Component Model" section (no WASM Component is built anywhere in this repo —
  `wit/pqc-kem.wit` is a descriptive reference for the `wasm-bindgen` JS API, not a buildable
  WIT interface); four new CI jobs (`no-std-build`, `clippy-and-doc`, `wasm-targets`,
  `wasm-pack-node-test`); and fixes for every stale `"0.1.0"` version string and the
  9 pre-existing `rustdoc::broken_intra_doc_links` warnings (now 0, both with default
  features and `--no-default-features`).
- **Added — Known-Answer Tests (WP4, X-4/P1):** a new non-default `kat` feature (additive,
  `no_std`-compatible, no new dependencies) with `cargo test --features kat` now checking this
  crate's ML-KEM-512/768/1024 output against vendored NIST ACVP vectors (keyGen, encapsulation,
  and decapsulation — including implicit-rejection cases) and its X25519 output against RFC
  7748 §5.2/§6.1 vectors. Vector files live under `tests/vectors/` (shipped in the published
  package) with full provenance in `tests/vectors/README.md`. New CI job
  `kat-feature-build-test`.
- **Added — named hybrid profiles and X-Wing (WP5, K-5):** the existing hybrid is now the
  named profile `HybridKem-X25519-MLKEM768-v1`, byte-for-byte unchanged and still
  `PRIMARY_ALGORITHM`. X-Wing (`draft-connolly-cfrg-xwing-kem-10`) arrives as profile v2
  through a new `XWingKeypair`, checked against the three vectors published by the draft's
  authors and recommended for new deployments. Canonical byte encodings for the hybrid's
  public key and ciphertext. Specification in `docs/hybrid-profiles.md`. X-Wing is not yet
  exposed to JavaScript through `pqc-kem-wasm`.
- **Added — benchmarks:** `benches/kem.rs` covers every construction the crate ships, and
  `scripts/bench-report.mjs` turns a criterion run into `BENCHMARKS.md`, with both hybrid
  profiles compared against ML-KEM-768 and against each other.
- **Changed — pre-release hardening:** what ships to crates.io is now an allowlist
  (`include`), so stray files can't reach the package. Feature-only test targets use
  `required-features`, so a default `cargo test` no longer prints empty binaries as passes.

### Algorithms (unchanged from 0.2.0, HQC status corrected in prose only)

| Algorithm | Standard | Level | WASM Native | Feature |
|---|---|---|---|---|
| ML-KEM-512 | FIPS 203 | 1 | ✅ | *(default)* |
| ML-KEM-768 | FIPS 203 | 3 | ✅ (recommended standalone) | *(default)* |
| ML-KEM-1024 | FIPS 203 | 5 | ✅ | *(default)* |
| X25519+ML-KEM-768 | Hybrid | 3+ | ✅ | *(default, `PRIMARY_ALGORITHM`)* |
| HQC-128/192/256 | NIST 2025 | 1/3/5 | ❌ (native-only, C FFI via `liboqs`) | `hqc` |

BIKE, Classic McEliece, and NTRU are gone entirely as of 0.3.0 — see "Migration from 0.2.x"
below.

### Test counts (re-verified for this release)

```
cargo test                     # 119 tests + 3 doctests (default features)
cargo test --no-default-features  # same 119 tests + 3 doctests
cargo test --features hqc      # adds tests/hqc_tests.rs (16 tests) + 3 HQC zeroize checks
                                # (verified in CI on ubuntu-latest; the oqs-sys/bindgen build
                                # step for this feature does not currently succeed on Windows
                                # — a pre-existing, unrelated local limitation)
cargo test --features kat      # 137 tests + 3 doctests, 1 ignored. Adds tests/kat_ml_kem.rs
                                # (12 tests, 90 vector cases across keyGen/encap/decap x 3
                                # parameter sets), tests/kat_x25519.rs (3 run + 1 --ignored,
                                # 6 RFC 7748 vectors), tests/kat_xwing.rs (1 test, 3 draft
                                # vectors) and tests/kat_hybrid_v1.rs (2 tests); same counts
                                # with --no-default-features (kat is no_std/alloc-compatible)
```

### Migration from 0.2.x

Per [`STABILITY.md`](./STABILITY.md) §2/§4, this is a breaking release:

- **If you never enabled `features = ["bike"]`/`["mceliece"]`, never matched exhaustively on
  every `KemAlgorithm` variant, and never called `x25519_secret_bytes()`/
  `mlkem_secret_bytes()` (the common case): no change needed.** `cargo add pqc-kem@0.3` is
  enough.
- **If you enabled `features = ["bike"]` or `["mceliece"]`:** your build was already failing
  at 0.2.0 (both were hard `compile_error!` stubs). Delete the feature from your
  `Cargo.toml` — neither algorithm was ever implemented here.
- **If you depended on `pqc_kem::bike`, `pqc_kem::mceliece`, or `pqc_kem::ntru` directly:**
  those modules no longer exist. There is no replacement for `bike`/`mceliece`; for `ntru`,
  use `fips203::MlKem768Keypair`.
- **If you exhaustively `match` on `KemAlgorithm` without a wildcard arm:** matching
  `Bike`/`ClassicMceliece` now emits a deprecation warning (not an error). Add
  `#[allow(deprecated)]`, or switch to a wildcard `_ =>` arm ahead of their planned removal
  in 0.4.0. Wire/JSON compatibility (`"bike"`/`"classic_mceliece"` strings) is unchanged.
- **If you called `HybridKemKeypair::x25519_secret_bytes()`/`mlkem_secret_bytes()`:** both
  still work exactly as before (deprecation warning only). Switch to `x25519_secret()`/
  `mlkem_seed()` for zeroize-on-drop handling and (for the latter) a proper `Result` instead
  of a silent empty `Vec` on failure.
- **`--all-features` must now pass**, not fail. If any of your own tooling asserted the old
  "must fail with bike/mceliece compile errors" behavior, update it — see
  `verify-gates.ps1`'s 0.3.0 rewrite for the new positive assertion shape.
- **Everything else is unchanged:** `HybridKemKeypair::{generate, encapsulate, encapsulate_to,
  decapsulate, from_secret_key_bytes}`, `types::HybridKemCiphertext`/`HybridPublicKey`,
  `pqc_kem::PRIMARY_ALGORITHM`, and every wire/JSON field name/shape are identical to 0.2.0.

---

## pqc-kem v0.2.0 (2026-09-02)

Combined two independent pieces of work: a real HQC implementation (replacing the
`compile_error!` stub, via `liboqs`/the `oqs` crate rather than `pqcrypto-hqc`, for a
panic-safety reason documented in `CHANGELOG.md`), and a fix for `pqc-kem`'s broken
`wasm32-unknown-unknown` build (`CRA-1`) that split the WASM/JS bindings out into the new,
`publish = false` sibling crate `pqc-kem-wasm`. See `CHANGELOG.md`'s `[0.2.0]` entry for the
full writeup, including "Migration from 0.1.x".

---

## pqc-kem v0.1.0 (2026-08-27)

First release of the standalone post-quantum KEM library.

### Algorithms

| Algorithm | Standard | Level | WASM Native |
|---|---|---|---|
| ML-KEM-512 | FIPS 203 | 1 | ✅ |
| ML-KEM-768 | FIPS 203 | 3 | ✅ (recommended) |
| ML-KEM-1024 | FIPS 203 | 5 | ✅ |
| X25519+ML-KEM-768 | Hybrid | 3 | ✅ (primary) |
| HQC-128/192/256 | NIST 2025 | 1/3/5 | ⚠️ feature-gated (was a `compile_error!` stub) |
| BIKE | Round 4 alt | 1 | ⚠️ feature-gated (was a `compile_error!` stub) |
| Classic McEliece | Round 4 alt | 1 | ⚠️ feature-gated (was a `compile_error!` stub) |

### WASM Artifacts

`pqc-kem-v0.1.0-wasm.zip`:
- `pqc_kem_bg.wasm` — 244 KB compiled WebAssembly binary
- `pqc_kem.js` — ESM JavaScript glue module
- `pqc_kem.d.ts` — TypeScript type definitions
- `pqc_kem_bg.wasm.d.ts` — TypeScript definitions for the WASM binary
- `pqc-kem.wit` — WIT reference document (`0x307:pqc-kem@0.1.0`)
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
