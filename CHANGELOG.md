# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.2.0] - 2026-09-02

This release combines two independent pieces of work landed together: the real HQC
implementation (below) and a fix for `pqc-kem`'s broken `wasm32-unknown-unknown` build
(`CRA-1`, Linear). See "Migration from 0.1.x" at the end of this entry for what changes for
existing consumers.

### Added

- **New sibling crate: [`pqc-kem-wasm`](./pqc-kem-wasm)** (`CRA-1`). Carries the
  `wasm-bindgen` JS/TS bindings and the `crate-type = ["cdylib"]` standalone `.wasm` artifact
  that used to live in `pqc-kem` itself (`src/wasm.rs`, the `wasm` feature). Not published to
  crates.io (`publish = false`) — it exists purely to produce the prebuilt npm package via
  `wasm-pack` (`build.ps1` / `build-wasm.ps1`), same as before. See README.md's "Crate
  layout" for why this needed to be a separate crate rather than a feature flag: Cargo builds
  *every* declared `crate-type` for a package regardless of what a given consumer actually
  needs, so a crate declaring both `cdylib` and `rlib` forces every ordinary library consumer
  to also satisfy the `cdylib` link requirements — proven by a new downstream-consumer CI
  regression test (`tests/downstream-consumer-fixture/`) that fails on an earlier draft of
  this fix (lang items gated behind a `standalone` feature, `crate-type` left unconditional)
  for exactly this reason.
- Real HQC-128/192/256 (NIST 2025 standard) implementation behind the `hqc` feature flag,
  replacing the previous `compile_error!` stub. Native-target only (C FFI via `liboqs`, the
  `oqs` crate — not `wasm32-unknown-unknown` compatible; use ML-KEM for WASM targets).
  `KemAlgorithm::Hqc128/192/256` wire types are unchanged from 0.1.0 (no breaking change to
  the already-shipped type definitions or public key sizes).
- `tests/hqc_tests.rs` — keygen/encapsulate/decapsulate round-trip, shared-secret-equality,
  and public-key/ciphertext-size assertions per security level, plus negative tests proving
  a wrong-secret-key or malformed-ciphertext decapsulation returns `Err` and never panics —
  gated behind `--features hqc` (16 tests).

### Changed

- **BREAKING: `pqc-kem`'s `[lib] crate-type` is now `["rlib"]` only** (was `["cdylib",
  "rlib"]`) (`CRA-1`). `pqc-kem` was previously unbuildable for `wasm32-unknown-unknown` in
  *any* configuration: `cargo build --target wasm32-unknown-unknown --no-default-features
  --features wasm` hit `error[E0152]: found duplicate lang item panic_impl` (this crate
  unconditionally defined `#[global_allocator]`/`#[panic_handler]` whenever its own `std`
  feature was off, which is invalid — a library crate can't tell from its own feature flags
  whether the final linked program has `std` from elsewhere), and the `std`-enabled path hit
  a separate `getrandom` 0.4 wasm32 backend gap. Fixed by making `pqc-kem` an ordinary
  `rlib`-only library that never defines those lang items, and wiring `getrandom` 0.4's
  `wasm_js` backend in as a target-conditional dependency for `wasm32-unknown-unknown` (no
  feature flag needed). `pqc-kem` itself now builds cleanly for `wasm32-unknown-unknown` as a
  plain dependency of any Rust project, including your own `wasm-bindgen` app.
- **BREAKING: the `wasm` feature flag and `pqc_kem::wasm` module are removed from
  `pqc-kem`.** That surface (the `wasm-bindgen` JS/TS bindings) moved to the new
  `pqc-kem-wasm` crate — see "Added" above and "Migration from 0.1.x" below.
- **Dependency: `pqcrypto-hqc` → `liboqs` (`oqs` crate).** The stub's original comment
  claimed `pqcrypto-hqc 0.1`'s published API didn't expose what this crate needed (82
  compile errors). Re-verified live rather than trusted: the current published
  `pqcrypto-hqc` (0.2.x) API *does* match almost exactly — that claim was stale. However, a
  more serious, independent defect was found instead: `pqcrypto-hqc` 0.2.2's
  `decapsulate()` wraps the underlying PQClean C reference implementation's informational
  "decapsulation check failed" return code — the FO-transform's *normal, expected*
  implicit-rejection outcome for **any** ciphertext/secret-key mismatch, not a rare
  adversarial edge case — in a hard `assert_eq!(.., 0)`, which **panics** (and, under a
  `panic = "abort"` profile, aborts the process) instead of returning an error. Verified
  live with two independent reproductions (a bit-flipped ciphertext, and an honestly
  mismatched secret key) — both panic via `pqcrypto-hqc`. `liboqs` wraps the identical
  underlying return code as a proper `Result` instead; verified live that neither
  reproduction panics via `liboqs` — both cleanly return `Err`. See
  [`src/hqc/mod.rs`](src/hqc/mod.rs) module docs and README.md "Why `liboqs` and not
  `pqcrypto-hqc`?" for the full writeup.
- **Corrected HQC-128/256 ciphertext sizes: 4481 → 4433 bytes, 14469 → 14421 bytes.**
  HQC-192's 8978-byte ciphertext was already correct. Verified live against both
  `pqcrypto-hqc` 0.2.2 and `liboqs` 0.13.0 — two independent implementations of the same
  NIST submission, which agree on the corrected sizes. This reflects the HQC round-4/2023
  parameter revision to the error-correcting code, which changed ciphertext size at the
  128- and 256-bit levels but not the 192-bit level. Public key sizes (2249/4522/7245
  bytes) were already correct and are unchanged. This correction lands *before* any real
  implementation ever shipped (0.1.0's `hqc` was a hard compile error), so there is no
  previously-working wire format being broken.
- `README.md` and module-level docs for `hqc` no longer describe the feature as "NOT YET
  IMPLEMENTED" / "Gated — not implemented."
- CI now builds and tests `--features hqc` explicitly in its own job (previously excluded
  from all CI jobs because `--all-features` deliberately omits it). The `--all-features`
  job's expected-failure assertion is narrowed from three named features (hqc/bike/mceliece)
  to two (bike/mceliece only) — `hqc` now compiles and is included in `--all-features`.
- `SECURITY.md`'s accepted-advisories table drops `RUSTSEC-2026-0168` (`pqcrypto-hqc`)
  entirely — it is no longer a dependency of this crate in any configuration, not merely an
  accepted advisory. Re-ran `cargo deny check` after the swap: no new advisory, license,
  ban, or source finding from `oqs`/`oqs-sys`/`liboqs`.

### Not changed

- `bike` and `mceliece` features remain `compile_error!` stubs, unchanged.
- The primary `HybridKemKeypair` (X25519+ML-KEM-768) construction and its
  `"pqc-kem-hybrid-v1"` HKDF info string are unchanged.
- `KemAlgorithm::Hqc128/192/256` enum variants and public key sizes are unchanged.
- No public API, algorithm, or cryptographic changes from the wasm/no_std fix (`CRA-1`) —
  build configuration only. `HybridKemKeypair`, `MlKem{512,768,1024}Keypair`, and every wire
  type are unchanged.

### Migration from 0.1.x

Per `STABILITY.md` §2/§4, this is a breaking release, not a patch:

- **Library consumers of `pqc-kem` (the common case): no change needed.** `cargo add pqc-kem`
  and `cargo add pqc-kem@0.2` (Cargo's `^0.1` doesn't match `0.2.0`, so this must be a
  deliberate bump) is enough. If you were previously enabling `features = ["wasm"]` on
  `pqc-kem` directly, that feature no longer exists — see below.
- **If you consumed `pqc-kem`'s WASM/JS bindings (`WasmHybridKemKeypair`, `hybrid_encapsulate`,
  etc., or built `pqc-kem` itself with `--features wasm`):** that surface moved to the new
  `pqc-kem-wasm` crate. The compiled JS/TS API is unchanged (same function/class names, same
  `pqc_kem.js`/`pqc_kem_bg.wasm` file names) — only the Rust-side crate producing it changed.
  If you build the WASM artifact yourself rather than consuming the npm package, point your
  build at `pqc-kem-wasm/` instead of `pqc-kem/` (see README.md's updated build commands).
- **If you built `pqc-kem` itself as a standalone `no_std` cdylib** (e.g. directly invoking
  `cargo build --no-default-features --features wasm` against 0.1.x): `pqc-kem` no longer
  produces a `cdylib` at all. Use `pqc-kem-wasm` for that instead.

## [0.1.0] - 2026-08-27

### Added

- Initial release: ML-KEM-512, ML-KEM-768, and ML-KEM-1024 (NIST FIPS 203), plus the
  recommended Hybrid X25519+ML-KEM-768 construction (HKDF-SHA256 combiner) — pure Rust,
  `no_std`-compatible, 81 tests passing.
- WASM bindings (`wasm` feature) for `wasm32-unknown-unknown`, with wire types
  (`KemPublicKey`, `KemCiphertext`, `SharedSecret`, `HybridPublicKey`, `HybridKemCiphertext`)
  supporting base64url JSON and multibase (base58btc) encoding for DID Documents / JWK
  payloads.
- `no_std` + `alloc` support, caller-supplied RNG, secret key material zeroized on drop.
- `hqc`, `bike`, and `mceliece` feature flags exist so the intended algorithm surface is
  visible, but each is a hard `compile_error!` stub, not a runtime option — see README.md for
  status.

See [README.md](README.md) for full API and feature documentation.
