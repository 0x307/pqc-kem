# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

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
