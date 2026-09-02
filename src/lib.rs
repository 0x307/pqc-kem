//! # pqc-kem — Post-Quantum Key Encapsulation Mechanisms
//!
//! A standalone, WASM-compatible library implementing post-quantum KEM algorithms:
//!
//! - **ML-KEM** (NIST FIPS 203) — Primary standard, pure Rust, WASM-native
//!   - [`fips203::MlKem512Keypair`] — Security Level 1
//!   - [`fips203::MlKem768Keypair`] — Security Level 3 (recommended)
//!   - [`fips203::MlKem1024Keypair`] — Security Level 5
//!   - [`fips203::HybridKemKeypair`] — X25519 + ML-KEM-768 hybrid (primary construction)
//!
//! - **HQC** (NIST 2025) — Code-based alternative, gated behind `hqc` feature.
//!   Real implementation via `liboqs` (native targets only, not WASM).
//!   - [`hqc::Hqc128Keypair`], [`hqc::Hqc192Keypair`], [`hqc::Hqc256Keypair`]
//!
//! - **BIKE** (NIST Round 4 alternate) — gated behind `bike` feature.
//!   NOT YET IMPLEMENTED: enabling `bike` fails the build by design.
//!   - [`bike::BikeKeypair`]
//!
//! - **Classic McEliece** (NIST Round 4 alternate) — gated behind `mceliece` feature.
//!   NOT YET IMPLEMENTED: enabling `mceliece` fails the build by design.
//!   - [`mceliece::McElieceKeypair`]
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
//! ## WASM Usage
//!
//! Build with the `wasm` feature for `wasm32-unknown-unknown` targets:
//! ```toml
//! pqc-kem = { version = "0.1", features = ["wasm"] }
//! ```
//!
//! ## `no_std` Support
//!
//! This crate is `no_std`-compatible with `alloc`. Disable the `std` feature:
//! ```toml
//! pqc-kem = { version = "0.1", default-features = false }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// ── no_std runtime hooks ─────────────────────────────────────────────────────
//
// This crate's `crate-type` includes `cdylib`, so `cargo build` compiles it as
// a standalone linked artifact, not just an `rlib` dependency of some other
// binary. Without `std`, that final artifact needs its own global allocator
// and panic handler — there's no downstream crate to supply them (unlike a
// typical no_std *library* that expects its eventual binary crate to provide
// these). This is why the no_std path is meant for building this crate itself
// as the final artifact (the WASM cdylib via `build.ps1`), not for embedding
// it as a no_std dependency inside another program that defines its own
// allocator/panic handler — doing so would collide with these at link time.

#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

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

/// BIKE (NIST Round 4 alternate) — gated behind `bike` feature, NOT YET IMPLEMENTED.
pub mod bike;

/// Classic McEliece (NIST Round 4 alternate) — gated behind `mceliece` feature, NOT YET IMPLEMENTED.
pub mod mceliece;

/// NTRU — eliminated from NIST standardization. Deprecation marker only.
pub mod ntru;

/// WASM bindings via `wasm-bindgen` — requires `wasm` feature.
#[cfg(feature = "wasm")]
pub mod wasm;

// ── Top-Level Re-exports ──────────────────────────────────────────────────────

pub use error::{KemError, KemResult};
pub use types::{
    HybridKemCiphertext,
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
};

// ── Version ───────────────────────────────────────────────────────────────────

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Algorithm suite identifier for the primary hybrid construction.
pub const PRIMARY_ALGORITHM: &str = "X25519+ML-KEM-768";

/// HKDF info string used in the hybrid KEM construction.
pub const HYBRID_KEM_INFO: &str = "pqc-kem-hybrid-v1";
