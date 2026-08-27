//! ML-KEM (NIST FIPS 203) — Key Encapsulation Mechanism
//!
//! This module provides all three ML-KEM parameter sets:
//! - [`MlKem512`]  — Security Level 1 (AES-128 equivalent), 800-byte public key
//! - [`MlKem768`]  — Security Level 3 (AES-192 equivalent), 1184-byte public key  ← recommended
//! - [`MlKem1024`] — Security Level 5 (AES-256 equivalent), 1568-byte public key
//!
//! All implementations use the `ml-kem` crate (RustCrypto), which is:
//! - Pure Rust (no C FFI)
//! - `no_std`-compatible with `alloc`
//! - Directly compilable to `wasm32-unknown-unknown`
//! - Implements NIST FIPS 203 exactly

pub mod ml_kem_512;
pub mod ml_kem_768;
pub mod ml_kem_1024;
pub mod hybrid;

pub use ml_kem_512::MlKem512Keypair;
pub use ml_kem_768::MlKem768Keypair;
pub use ml_kem_1024::MlKem1024Keypair;
pub use hybrid::HybridKemKeypair;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // ── MlKem512Keypair smoke tests ───────────────────────────────────────────

    #[test]
    fn ml_kem_512_smoke() {
        let keypair = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let (ct, ss_enc) = MlKem512Keypair::encapsulate(&mut OsRng, &pk)
            .expect("encapsulate failed");
        let ss_dec = keypair.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.bytes, ss_dec.bytes, "ML-KEM-512 shared secrets must match");
    }

    // ── MlKem768Keypair smoke tests ───────────────────────────────────────────

    #[test]
    fn ml_kem_768_smoke() {
        let keypair = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let (ct, ss_enc) = MlKem768Keypair::encapsulate(&mut OsRng, &pk)
            .expect("encapsulate failed");
        let ss_dec = keypair.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.bytes, ss_dec.bytes, "ML-KEM-768 shared secrets must match");
    }

    // ── MlKem1024Keypair smoke tests ──────────────────────────────────────────

    #[test]
    fn ml_kem_1024_smoke() {
        let keypair = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");
        let pk = keypair.public_key();
        let (ct, ss_enc) = MlKem1024Keypair::encapsulate(&mut OsRng, &pk)
            .expect("encapsulate failed");
        let ss_dec = keypair.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.bytes, ss_dec.bytes, "ML-KEM-1024 shared secrets must match");
    }

    // ── HybridKemKeypair smoke tests ──────────────────────────────────────────

    #[test]
    fn hybrid_kem_smoke() {
        let keypair = HybridKemKeypair::generate(&mut OsRng).expect("keygen failed");
        let pub_key = keypair.public_key();
        let (ct, ss_enc) = HybridKemKeypair::encapsulate_to(&mut OsRng, &pub_key)
            .expect("encapsulate_to failed");
        let ss_dec = keypair.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss_enc.bytes, ss_dec.bytes, "Hybrid KEM shared secrets must match");
    }

    // ── Public key sizes ──────────────────────────────────────────────────────

    #[test]
    fn public_key_sizes() {
        let kp512 = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp768 = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp1024 = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");

        assert_eq!(kp512.public_key().bytes.len(), 800);
        assert_eq!(kp768.public_key().bytes.len(), 1184);
        assert_eq!(kp1024.public_key().bytes.len(), 1568);
    }

    // ── Secret key seed sizes ─────────────────────────────────────────────────

    #[test]
    fn secret_key_seed_sizes() {
        let kp512 = MlKem512Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp768 = MlKem768Keypair::generate(&mut OsRng).expect("keygen failed");
        let kp1024 = MlKem1024Keypair::generate(&mut OsRng).expect("keygen failed");

        assert_eq!(kp512.secret_key().bytes.len(), 64);
        assert_eq!(kp768.secret_key().bytes.len(), 64);
        assert_eq!(kp1024.secret_key().bytes.len(), 64);
    }
}
