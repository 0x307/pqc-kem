//! # pqc-kem — Post-Quantum Key Encapsulation Mechanisms
//!
//! A pure Rust, `no_std`-capable library implementing post-quantum KEM
//! algorithms, meant to be imported into other builds — not built or run on
//! its own. (For the WASM/JS bindings and the standalone `.wasm` artifact,
//! see the sibling `pqc-kem-wasm` crate.)
//!
//! - **ML-KEM** (NIST FIPS 203) — Primary standard, pure Rust, WASM-native
//!   - [`fips203::MlKem512Keypair`] — Security Level 1
//!   - [`fips203::MlKem768Keypair`] — Security Level 3 (recommended)
//!   - [`fips203::MlKem1024Keypair`] — Security Level 5
//!   - [`fips203::HybridKemKeypair`] — X25519 + ML-KEM-768 hybrid (primary construction)
//!
//! - **HQC** (NIST 2025) — Code-based alternative, gated behind `hqc` feature.
//!   Real implementation via `liboqs` (native targets only, not WASM).
//!   - `hqc::Hqc128Keypair`, `hqc::Hqc192Keypair`, `hqc::Hqc256Keypair` (only
//!     compiled with `--features hqc`; plain code spans here, not links, so
//!     `cargo doc --no-deps` stays warning-free with default features, where
//!     these types do not exist)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pqc_kem::fips203::HybridKemKeypair;
//! use rand::rngs::OsRng;
//!
//! // Recipient generates keypair
//! let recipient = HybridKemKeypair::generate(&mut OsRng).unwrap();
//! let pub_key = recipient.public_key();
//!
//! // Sender encapsulates
//! let x25519_pub = pub_key.x25519_bytes().unwrap();
//! let mlkem_pub = pub_key.mlkem_bytes().unwrap();
//! let x25519_arr: [u8; 32] = x25519_pub.try_into().unwrap();
//! let (ciphertext, sender_ss) = HybridKemKeypair::encapsulate(
//!     &mut OsRng,
//!     &x25519_arr,
//!     &mlkem_pub,
//! ).unwrap();
//!
//! // Recipient decapsulates
//! let recipient_ss = recipient.decapsulate(&ciphertext).unwrap();
//! assert_eq!(sender_ss.bytes, recipient_ss.bytes);
//! ```
//!
//! ## WASM Target Support
//!
//! This crate builds cleanly as an ordinary library dependency for
//! `wasm32-unknown-unknown` (e.g. from inside a `wasm-bindgen`/`wasm-pack`
//! project of your own) — no special feature needed; the `getrandom`
//! backend required for that target is wired in automatically (see
//! Cargo.toml). It does **not** ship JS bindings or build as a `.wasm`
//! artifact itself — that packaging lives in the sibling `pqc-kem-wasm`
//! crate, which depends on this one.
//!
//! ## `no_std` Support
//!
//! This crate is `no_std`-compatible with `alloc`, and is **always** just a
//! library — it never defines `#[global_allocator]` or `#[panic_handler]`
//! itself (a library crate can't validly infer from its own feature flags
//! whether the program linking it has `std` elsewhere; only the final
//! binary knows that, and only it should supply those). Disable the `std`
//! feature to use the `no_std` path:
//! ```toml
//! pqc-kem = { version = "0.2", default-features = false }
//! ```
//! The program embedding this crate is responsible for supplying its own
//! allocator and panic handler if it, in turn, has no `std` either.
//!
//! ---
//!
//! ## The 0x307 crate family
//!
//! `pqc-kem` is one of six open-source crates from [0x307](https://0x307.com/crates), held to one
//! audit and stability standard.
//!
//! | Crate | Tier | What it does |
//! |---|---|---|
//! | [pqc-sig](https://crates.io/crates/pqc-sig) | Production | ML-DSA, SLH-DSA and FN-DSA signatures (FIPS 204/205/206) |
//! | [pqc-kem](https://crates.io/crates/pqc-kem) (this crate) | Production | ML-KEM (FIPS 203), the X25519 + ML-KEM-768 hybrid, X-Wing, and sealed boxes |
//! | [aethel-core](https://crates.io/crates/aethel-core) | Production | Post-quantum anonymous identity: a separate identifier per context, context-bound ML-DSA signing |
//! | [aethel-sdk](https://crates.io/crates/aethel-sdk) | Preview | The SDK over aethel-core, and the place to start |
//! | [aethel-vault](https://crates.io/crates/aethel-vault) | Preview | Agent-held wallet: policy-gated x402 / EIP-3009 signing with ML-DSA-65 spend records |
//! | [pqc-privacy](https://crates.io/crates/pqc-privacy) | Lab | Research bundle, kept off every identity and payment path |
//!
//! **Production** crates are thin, standards-bound libraries meant to be depended on today. **Preview** crates work and are published, with APIs still settling. **Lab** crates are research, never on an identity or payment path.
//!
//! **Runnable examples:** [0x307/examples](https://github.com/0x307/examples), one program per
//! crate, pinned to the published versions.
//!
//! **Audit status:** None of these crates has been independently audited, and none holds a CMVP / FIPS 140-3 validation. "FIPS 203/204/205/206" means the algorithms follow those standards, not that the code is certified. Known issues for this crate are in
//! [SECURITY.md](https://github.com/0x307/pqc-kem/blob/main/SECURITY.md). Versioning and yanks:
//! [STABILITY.md](https://github.com/0x307/pqc-kem/blob/main/STABILITY.md).
//!

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// ── Public Modules ────────────────────────────────────────────────────────────

/// Error types for all KEM operations.
pub mod error;

/// Wire types: public keys, ciphertexts, shared secrets, algorithm identifiers.
pub mod types;

/// ML-KEM (NIST FIPS 203) — pure Rust, WASM-native.
pub mod fips203;

/// HQC (NIST 2025 standard) — gated behind `hqc` feature. Real implementation
/// via `liboqs`, native targets only (not WASM).
pub mod hqc;

/// KEM shared secret → HKDF-SHA256 → AEAD-sealed payload, in one path.
/// Gated behind the non-default `aead-wrap` feature.
#[cfg(feature = "aead-wrap")]
pub mod aead_wrap;

// ── Top-Level Re-exports ──────────────────────────────────────────────────────

pub use error::{KemError, KemResult};
pub use types::{
    HybridKemCiphertext,
    HybridProfile,
    HybridPublicKey,
    KemAlgorithm,
    KemCiphertext,
    KemPublicKey,
    KemSecretKey,
    SharedSecret,
};

// Primary recommended types — re-exported at crate root for convenience
pub use fips203::{
    HybridKemKeypair,
    MlKem512Keypair,
    MlKem768Keypair,
    MlKem1024Keypair,
    XWingKeypair,
};

// ── Version ───────────────────────────────────────────────────────────────────

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Algorithm suite identifier for the primary hybrid construction.
pub const PRIMARY_ALGORITHM: &str = "X25519+ML-KEM-768";

/// HKDF info string used in the hybrid KEM construction (profile v1).
pub const HYBRID_KEM_INFO: &str = "pqc-kem-hybrid-v1";

// ── Named Hybrid KEM Profiles (K-5, WP5) ───────────────────────────────────────
//
// See `docs/hybrid-profiles.md` for the full normative spec of both
// profiles: canonical byte layouts, combiners, and test vectors.

/// Profile identifier for this crate's original hybrid combiner
/// (`fips203::HybridKemKeypair`) — wire-compatible with every prior 0.x
/// release. `HKDF-SHA256(x25519_ss ‖ mlkem_ss, info="pqc-kem-hybrid-v1")`;
/// does not bind ciphertext/public key into the KDF.
pub const HYBRID_PROFILE_V1: &str = "HybridKem-X25519-MLKEM768-v1";

/// Profile identifier for X-Wing (`fips203::XWingKeypair`,
/// `draft-connolly-cfrg-xwing-kem`) — `SHA3-256`-based combiner that binds
/// `ct_X`/`pk_X`. **Recommended for new deployments.**
pub const HYBRID_PROFILE_V2: &str = "HybridKem-X25519-MLKEM768-v2";

/// Alias for [`HYBRID_PROFILE_V1`], kept for wire/API compatibility with
/// existing deployments that already treat this constant as identifying
/// `PRIMARY_ALGORITHM`'s hybrid construction. Points at v1, not v2 — see
/// `docs/hybrid-profiles.md` for the rationale and migration guidance.
pub const HYBRID_PROFILE_ID: &str = HYBRID_PROFILE_V1;
